"""Secure QR payload parser — Step 1.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 1
Provides : SecureQrParser (implements avs.contracts.PayloadParser)
Consumes : avs.contracts, avs.parser.fields
Used by  : avs.crypto (Step 1), avs.ocr (Step 17)

⚠ HIGHEST-RISK MODULE IN THE PROJECT
   ``_split_signature`` implements the security invariant from CONTRACTS.md §5:

       signed_bytes = payload[:-256]
       signature    = payload[-256:]

   Getting this boundary wrong produces false verdicts while every test that
   does not specifically probe it still passes. It is covered by dedicated
   boundary tests in tests/unit/test_tamper_detection.py. Do not modify it
   without re-running the full genuine + tampered corpus.
"""

from __future__ import annotations

import gzip
import zlib

from avs.contracts import (
    AadhaarAddress,
    AadhaarIdentity,
    ErrorCode,
    QrPayload,
)
from avs.parser.errors import ParseError
from avs.parser.fields import (
    ADDRESS_FIELDS,
    DELIMITER,
    HASH_LENGTH,
    SIGNATURE_LENGTH,
    EmailMobilePresence,
    detect_version,
    field_map_for,
)

__all__ = ["SecureQrParser"]

#: JPEG2000 magic bytes — used to locate the photograph inside the tail block.
_JP2_SIGNATURES = (
    b"\x00\x00\x00\x0cjP  ",  # JP2 container
    b"\xff\x4f\xff\x51",  # raw JPEG2000 codestream
)

#: Sanity bounds — a real payload is a few hundred bytes to a few KB.
_MIN_PAYLOAD_BYTES = SIGNATURE_LENGTH + 32
_MAX_PAYLOAD_BYTES = 8 * 1024 * 1024


class SecureQrParser:
    """Parses a decoded Secure QR string into a :class:`QrPayload`.

    The parser performs **no verification**. It unpacks structure and hands the
    signed byte range plus the signature to ``avs.crypto``, which alone decides
    authenticity. Keeping unpacking and verification separate means a parsing
    bug can never be mistaken for a valid signature.
    """

    def parse(self, raw_payload: str) -> QrPayload:
        """Unpack a decoded QR string.

        Raises:
            ParseError: with an ErrorCode from the parse family.
        """
        # ⛔ LEADING ZERO BYTES ARE NOT RECOVERABLE FROM A DECIMAL INTEGER.
        #
        #   The Secure QR carries its payload as one enormous decimal number.
        #   `int("00" + rest)` is the same integer as `int(rest)`, so if the
        #   original byte array began with 0x00 that byte is simply gone once
        #   we convert back.
        #
        #   The consequence is the worst one this project has:
        #
        #       signed_bytes = payload[:-256]
        #
        #   A missing leading byte shifts that range, the signature over it no
        #   longer matches, and a GENUINE Aadhaar is reported as TAMPERED. We
        #   would be accusing a real employee of forgery because of an arithmetic
        #   detail.
        #
        #   We cannot know how many leading zeros were lost, so we try the
        #   candidates. This does NOT weaken the security check: each candidate
        #   is verified independently against UIDAI's public key downstream, and
        #   a forged payload fails under every candidate. All we are doing is
        #   refusing to lose a genuine card to an encoding artefact.
        first_error: ParseError | None = None
        for data in self._byte_candidates(raw_payload):
            try:
                return self._parse_bytes(data)
            except ParseError as exc:
                # ⚠ Report the FIRST candidate's error, not the last.
                #
                #   The minimal byte-length is the normal case and its failure
                #   is the meaningful diagnosis. The +1 and +2 zero-padded
                #   retries are long shots that fail with noise — surfacing
                #   their error instead turns "expected 16 fields, found 8"
                #   into a generic "malformed", which is exactly the kind of
                #   misdirection that cost days on this project already.
                if first_error is None:
                    first_error = exc
                continue

        raise first_error or ParseError(
            ErrorCode.PAYLOAD_MALFORMED, "payload could not be unpacked"
        )

    def _byte_candidates(self, raw_payload: str) -> list[bytes]:
        """The minimal byte array, then variants with restored leading zeros."""
        minimal = self._to_bytes(raw_payload)
        return [minimal, b"\x00" + minimal, b"\x00\x00" + minimal]

    def _parse_bytes(self, data: bytes) -> QrPayload:
        """Unpack one candidate byte array. Raises ParseError if it is not one."""
        data = self._decompress(data)
        self._check_size(data)

        fields, tail_offset = self._split_fields(data)
        if not fields:
            raise ParseError(ErrorCode.PAYLOAD_MALFORMED, "no delimited fields found")

        # ⛔ MAP SELECTION MUST BE SELF-CORRECTING, NOT A GUESS FROM FIELD 0.
        #
        #   The UIDAI specification (SECURE QR CODE SPECIFICATION, March 2019,
        #   §3.1) defines the payload as starting with the email/mobile PRESENCE
        #   INDICATOR — "0", "1", "2" or "3". There is no version marker. Cards
        #   carrying a literal "V2" prefix also exist in the wild.
        #
        #   So the two maps differ by exactly one leading field, and picking
        #   between them by sniffing field 0 is fragile: any noise in that field
        #   silently shifts EVERY subsequent field by one, and the failure
        #   surfaces far away as "reference_id does not start with 4 digits".
        #   That cost this project three diagnostic rounds on real cards.
        #
        #   Instead: try the detected map first, then the other, and accept the
        #   one whose reference_id actually validates. `reference_id` is a strong
        #   discriminator — 4 digits followed by a DDMMYYYYHHMMSSsss timestamp —
        #   so a wrong alignment cannot masquerade as a right one.
        #
        #   This cannot weaken security. The signature is computed over the raw
        #   byte range and is unaffected by which map labels which field.
        detected = detect_version(fields[0])
        other = "V1" if detected == "V2" else "V2"

        last_failure: ParseError | None = None
        for version in (detected, other):
            mapping = self._mapping_for(version)
            if len(fields) < len(mapping):
                last_failure = last_failure or ParseError(
                    ErrorCode.PAYLOAD_TRUNCATED,
                    f"expected {len(mapping)} fields for {version}, found {len(fields)}",
                )
                continue
            candidate = dict(zip(mapping, fields, strict=False))
            reference = candidate.get("reference_id", "")
            if len(reference) >= 4 and reference[:4].isdigit():
                break
            last_failure = last_failure or ParseError(
                ErrorCode.PAYLOAD_MALFORMED,
                f"reference_id does not start with 4 digits under the {version} layout",
            )
        else:
            raise last_failure or ParseError(
                ErrorCode.PAYLOAD_MALFORMED, "no field layout produced a valid reference_id"
            )

        mapping = self._mapping_for(version)

        # Structural integrity: the 256-byte signature block sits at the very end
        # and must not reach back into the text fields. If it does, the payload
        # was truncated and any split we produced would be meaningless.
        #
        # Without this check a truncated payload still "parses", and only the
        # signature verification catches it. Rejecting it here is deterministic
        # and gives the employee an accurate UNREADABLE rather than TAMPERED —
        # a damaged image is not a forgery.
        if len(data) - SIGNATURE_LENGTH < tail_offset:
            raise ParseError(
                ErrorCode.PAYLOAD_TRUNCATED,
                f"signature block overlaps the text fields: payload is "
                f"{len(data)} bytes but fields alone occupy {tail_offset}",
            )

        values = dict(zip(mapping, fields, strict=False))
        presence = values.get("_presence", EmailMobilePresence.NEITHER)

        signed_bytes, signature = self._split_signature(data)
        photo, mobile_hash, email_hash = self._split_tail(data[tail_offset:], presence)

        identity = self._build_identity(values)
        address = self._build_address(values)

        return QrPayload(
            version=version,
            identity=identity,
            address=address,
            mobile_hash=mobile_hash,
            email_hash=email_hash,
            photo=photo,
            signed_bytes=signed_bytes,
            signature=signature,
            is_legacy_unsigned=False,
        )

    # ------------------------------------------------------------------ #
    # Decoding stages
    # ------------------------------------------------------------------ #

    @staticmethod
    def _to_bytes(raw_payload: str) -> bytes:
        """Large decimal integer → big-endian byte array."""
        text = raw_payload.strip()
        if not text:
            raise ParseError(ErrorCode.PAYLOAD_MALFORMED, "empty payload")

        if not text.isdigit():
            # A pre-2018 legacy QR carries XML, not a big integer. It contains
            # demographic data but is NOT signed, so it can never be verified.
            if text.lstrip().startswith("<?xml") or "uid=" in text[:200]:
                raise ParseError(
                    ErrorCode.PAYLOAD_LEGACY_UNSIGNED,
                    "pre-2018 unsigned QR — ask for a fresh e-Aadhaar",
                )
            raise ParseError(
                ErrorCode.PAYLOAD_MALFORMED,
                "payload is not a decimal integer string",
            )

        value = int(text)
        length = (value.bit_length() + 7) // 8
        return value.to_bytes(length, byteorder="big")

    @staticmethod
    def _decompress(data: bytes) -> bytes:
        """gunzip, inflate, or pass through — UIDAI has used all three."""
        if data[:2] == b"\x1f\x8b":  # gzip
            try:
                return gzip.decompress(data)
            except (OSError, EOFError, zlib.error) as exc:
                raise ParseError(
                    ErrorCode.PAYLOAD_MALFORMED, f"gzip decompression failed: {exc}"
                ) from exc

        try:  # zlib
            return zlib.decompress(data)
        except zlib.error:
            pass

        try:  # raw deflate
            return zlib.decompressobj(-zlib.MAX_WBITS).decompress(data)
        except zlib.error:
            pass

        return data  # uncompressed

    @staticmethod
    def _check_size(data: bytes) -> None:
        if len(data) < _MIN_PAYLOAD_BYTES:
            raise ParseError(
                ErrorCode.PAYLOAD_TRUNCATED,
                f"payload is {len(data)} bytes, minimum is {_MIN_PAYLOAD_BYTES}",
            )
        if len(data) > _MAX_PAYLOAD_BYTES:
            raise ParseError(ErrorCode.PAYLOAD_MALFORMED, "payload implausibly large")

    @staticmethod
    def _split_fields(data: bytes) -> tuple[list[str], int]:
        """Split leading text fields on 0xFF.

        Returns the decoded fields and the byte offset at which the binary tail
        begins. The tail holds the photograph, any optional hashes, and the
        signature.
        """
        fields: list[str] = []
        start = 0
        # 20 is a generous ceiling: the largest known map has 17 text fields.
        for _ in range(20):
            idx = data.find(bytes([DELIMITER]), start)
            if idx == -1:
                break
            chunk = data[start:idx]

            # ⛔ THE BUG THIS REPLACES, FOUND ON REAL CARDS.
            #
            #   This used to be a bare `chunk.decode("utf-8")` inside a
            #   try/except that BROKE OUT of the loop on UnicodeDecodeError,
            #   commented "binary content reached". That reasoning is wrong: a
            #   text field can fail to decode as UTF-8 simply because it is not
            #   UTF-8.
            #
            #   UIDAI encodes the Secure QR text fields as ISO-8859-1. Any name
            #   containing a byte above 0x7F therefore raised on the FIRST
            #   field, broke the loop with `fields` still empty, and surfaced as
            #   the baffling error "no delimited fields found" — on a payload
            #   that had decompressed perfectly and contained 46 delimiters.
            #
            #   Measured on the real corpus: 3 of 5 decoded cards died here.
            #   Pure-ASCII names survived; everyone else did not. In India that
            #   is not an edge case.
            #
            #   ISO-8859-1 maps every byte 0x00-0xFF to a code point and can
            #   never raise, so it is a safe final fallback. Decoding does not
            #   touch verification — the signature is computed over raw bytes —
            #   so this only affects which characters we read back.
            try:
                fields.append(chunk.decode("utf-8"))
            except UnicodeDecodeError:
                fields.append(chunk.decode("iso-8859-1"))

            start = idx + 1

            # The binary tail is detected STRUCTURALLY, by the photo marker —
            # never by guessing from a decode failure.
            if _looks_like_photo(data[start:]):
                break

        return fields, start

    @staticmethod
    def _mapping_for(version: str) -> tuple[str, ...]:
        try:
            return field_map_for(version)
        except KeyError as exc:
            raise ParseError(
                ErrorCode.PAYLOAD_UNSUPPORTED_VERSION,
                f"unknown Secure QR version: {version}",
            ) from exc

    # ------------------------------------------------------------------ #
    # ★ THE SECURITY INVARIANT — CONTRACTS.md §5
    # ------------------------------------------------------------------ #

    @staticmethod
    def _split_signature(data: bytes) -> tuple[bytes, bytes]:
        """Separate the signed region from the signature.

        ⚠ signed = data[:-256] and signature = data[-256:], exactly.

        An off-by-one here silently breaks the entire security guarantee: the
        signature would be computed over the wrong bytes and every document,
        genuine or forged, would be judged incorrectly. Covered by
        ``test_signature_boundary_is_exact``.
        """
        if len(data) <= SIGNATURE_LENGTH:
            raise ParseError(
                ErrorCode.PAYLOAD_TRUNCATED,
                f"payload of {len(data)} bytes cannot contain a {SIGNATURE_LENGTH}-byte signature",
            )
        return data[:-SIGNATURE_LENGTH], data[-SIGNATURE_LENGTH:]

    @staticmethod
    def _split_tail(tail: bytes, presence: str) -> tuple[bytes | None, str | None, str | None]:
        """Separate photo, optional hashes, and signature from the binary tail."""
        if len(tail) <= SIGNATURE_LENGTH:
            return None, None, None

        body = tail[:-SIGNATURE_LENGTH]
        hash_count = EmailMobilePresence.hash_count(presence)
        hash_bytes = hash_count * HASH_LENGTH

        if hash_bytes and len(body) > hash_bytes:
            photo = body[:-hash_bytes]
            hashes = body[-hash_bytes:]
        else:
            photo, hashes = body, b""

        mobile_hash: str | None = None
        email_hash: str | None = None
        chunks = [hashes[i : i + HASH_LENGTH].hex() for i in range(0, len(hashes), HASH_LENGTH)]

        if presence == EmailMobilePresence.BOTH and len(chunks) == 2:
            mobile_hash, email_hash = chunks[0], chunks[1]
        elif presence == EmailMobilePresence.MOBILE_ONLY and chunks:
            mobile_hash = chunks[0]
        elif presence == EmailMobilePresence.EMAIL_ONLY and chunks:
            email_hash = chunks[0]

        return (photo or None), mobile_hash, email_hash

    # ------------------------------------------------------------------ #
    # Field assembly
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_identity(values: dict[str, str]) -> AadhaarIdentity:
        reference_id = values.get("reference_id", "")
        last4 = reference_id[:4]

        if not (len(last4) == 4 and last4.isdigit()):
            raise ParseError(
                ErrorCode.PAYLOAD_MALFORMED,
                "reference_id does not start with 4 digits",
            )

        name = values.get("name", "").strip()
        if not name:
            raise ParseError(ErrorCode.PAYLOAD_MALFORMED, "name field is empty")

        return AadhaarIdentity(
            name=name,
            dob=values.get("dob", "").strip(),
            gender=values.get("gender", "").strip(),
            aadhaar_last4=last4,
            reference_id=reference_id,
        )

    @staticmethod
    def _build_address(values: dict[str, str]) -> AadhaarAddress:
        return AadhaarAddress(
            **{
                key: (values.get(key) or None)
                for key in ADDRESS_FIELDS
                if key in AadhaarAddress.model_fields
            }
        )


def _looks_like_photo(data: bytes) -> bool:
    return any(data.startswith(sig) for sig in _JP2_SIGNATURES)
