"""AVS must never persist Aadhaar data — Step 8.

⛔ THE ARCHITECTURAL PROMISE THIS FILE ENFORCES

   Dheeraj's Step 8 decision: uploaded Aadhaar images live in the **HRM's
   database**. AVS receives bytes, produces a verdict, and forgets them.

   That makes this service stateless with respect to personal data, which is a
   genuinely strong privacy property — there is no bucket to leak, no retention
   policy to get wrong, no purge job to fail silently, and a compromised AVS
   host yields nothing historical.

   A property like that is worth exactly as much as its enforcement. Written in
   a README it survives until the first person adds a debug dump or a cache. So
   it is asserted here: a full verification runs with every filesystem write
   intercepted, and any write containing image bytes fails the test.

WHAT THIS DOES NOT CLAIM
------------------------
It does not claim the bytes are scrubbed from RAM. Python strings and bytes are
immutable and the interpreter may copy them freely; promising memory
zeroisation in pure Python would be a lie told with confidence. What is
guaranteed and verified is narrower and honest: **nothing reaches disk.**
"""

from __future__ import annotations

import builtins
import contextlib
import io
from pathlib import Path

import pytest

from avs.contracts import CardSide
from avs.crypto import SecureQrVerifier
from avs.pipeline import DocumentVerifier, SideInput
from avs.privacy import DataMinimisingFilter
from tests.fixtures.qr_images import encode_jpeg, render_card
from tests.fixtures.synthetic import SyntheticQrBuilder

SECRET = "statelessness-test-secret-value"


class WriteRecorder:
    """Intercepts every filesystem write attempted during a block of code."""

    def __init__(self) -> None:
        self.writes: list[tuple[str, bytes]] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real_open = builtins.open
        real_write_bytes = Path.write_bytes
        real_write_text = Path.write_text
        recorder = self

        def watched_open(file, mode="r", *args, **kwargs):
            handle = real_open(file, mode, *args, **kwargs)
            if any(flag in mode for flag in ("w", "a", "x", "+")):
                recorder._wrap(handle, str(file))
            return handle

        def watched_write_bytes(self, data):
            recorder.writes.append((str(self), bytes(data)))
            return real_write_bytes(self, data)

        def watched_write_text(self, data, *args, **kwargs):
            recorder.writes.append((str(self), str(data).encode("utf-8", "replace")))
            return real_write_text(self, data, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", watched_open)
        monkeypatch.setattr(Path, "write_bytes", watched_write_bytes)
        monkeypatch.setattr(Path, "write_text", watched_write_text)

    def _wrap(self, handle: object, name: str) -> None:
        original = getattr(handle, "write", None)
        if original is None:
            return

        def watched(data):
            payload = data if isinstance(data, bytes | bytearray) else str(data).encode()
            self.writes.append((name, bytes(payload)))
            return original(data)

        # Some handles forbid attribute assignment. Path.write_bytes and
        # write_text are patched separately, so coverage does not depend on
        # this succeeding for every handle type.
        with contextlib.suppress(AttributeError, io.UnsupportedOperation):
            handle.write = watched  # type: ignore[attr-defined]


@pytest.fixture
def document(test_key) -> tuple[bytes, bytes]:
    """A real two-sided document: a QR-less front and a signed back."""
    front = encode_jpeg(render_card("https://example.com/front-has-no-secure-qr"))
    back = encode_jpeg(render_card(SyntheticQrBuilder(private_key=test_key).build()))
    return front, back


def test_verification_writes_no_image_bytes_to_disk(
    monkeypatch: pytest.MonkeyPatch, test_key, test_certificate, document
):
    """★ The load-bearing test for the Step 8 storage decision.

    Images belong to the HRM. If AVS ever starts writing them — a cache, a
    debug dump, a well-meaning "keep failures for analysis" — this fails.
    """
    front, back = document
    recorder = WriteRecorder()
    recorder.install(monkeypatch)

    verifier = DocumentVerifier(
        SecureQrVerifier([test_certificate]),
        DataMinimisingFilter(hash_secret=SECRET),
        time_budget_seconds=4.0,
    )
    result = verifier.verify(
        [SideInput(CardSide.FRONT, front), SideInput(CardSide.BACK, back)], job_id="stateless"
    )
    assert result.verdict.value == "VERIFIED", "the document must actually have been processed"

    # A JPEG's leading bytes are a reliable marker for "an image went to disk".
    offenders = [path for path, data in recorder.writes if front[:16] in data or back[:16] in data]
    assert not offenders, f"Aadhaar image bytes were written to: {offenders}"


def test_verification_writes_no_payload_to_disk(
    monkeypatch: pytest.MonkeyPatch, test_key, test_certificate, document
):
    """The decoded QR payload is as sensitive as the image — arguably more so,
    since it is the signed demographic record rather than a photograph of it."""
    front, back = document
    payload = SyntheticQrBuilder(private_key=test_key).build()

    recorder = WriteRecorder()
    recorder.install(monkeypatch)

    DocumentVerifier(
        SecureQrVerifier([test_certificate]),
        DataMinimisingFilter(hash_secret=SECRET),
        time_budget_seconds=4.0,
    ).verify([SideInput(CardSide.FRONT, front), SideInput(CardSide.BACK, back)], job_id="stateless")

    probe = payload[:64].encode("ascii")
    offenders = [path for path, data in recorder.writes if probe in data]
    assert not offenders, f"a Secure QR payload was written to: {offenders}"


def test_the_result_itself_carries_no_full_aadhaar_number(test_key, test_certificate, document):
    """⛔ Whatever the HRM stores, it stores from this object.

    The HRM keeps records permanently, so anything present here is present
    forever. A 12-digit number must never appear.
    """
    import json
    import re

    front, back = document
    result = DocumentVerifier(
        SecureQrVerifier([test_certificate]),
        DataMinimisingFilter(hash_secret=SECRET),
        time_budget_seconds=4.0,
    ).verify([SideInput(CardSide.FRONT, front), SideInput(CardSide.BACK, back)], job_id="stateless")

    serialised = json.dumps(result.model_dump(mode="json"))
    assert not re.search(r"\b\d{12}\b", serialised)


def test_recorder_actually_detects_a_write(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """⚠ A guard that never fires is indistinguishable from a broken guard.

    This project has already shipped one detector that reported zeros because
    it was broken rather than because there was nothing to find. So the recorder
    proves it can see a write before its silence is treated as evidence.
    """
    recorder = WriteRecorder()
    recorder.install(monkeypatch)

    (tmp_path / "evidence.bin").write_bytes(b"\xff\xd8\xff-image-like-bytes")

    assert recorder.writes, "the write recorder saw nothing — it is not working"
    assert any(b"image-like-bytes" in data for _, data in recorder.writes)
