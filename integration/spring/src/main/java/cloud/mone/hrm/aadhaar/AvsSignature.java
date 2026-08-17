package cloud.mone.hrm.aadhaar;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC signing and verification for both directions of the AVS integration.
 *
 * <p>Step 10. Mirrors {@code avs.security.signing} in the Python service. See
 * CONTRACTS.md §8.
 *
 * <h2>The canonical string</h2>
 *
 * <pre>{@code   timestamp + "." + nonce + "." + body }</pre>
 *
 * <p><b>⛔ The dot separators are part of the contract, not formatting.</b> Without
 * them {@code ("12", "3")} and {@code ("1", "23")} produce the same bytes, so an
 * attacker could shift characters between the timestamp and the nonce while
 * keeping the signature valid. This class and the Python implementation are
 * verified byte-for-byte against shared vectors — if you change the separator
 * here, authentication fails in production and nowhere else.
 *
 * <h2>Why HMAC rather than an API key</h2>
 *
 * <p>A static key is a bearer token: anyone who captures it can replay any
 * request forever, and a key that leaks into a proxy log stays usable until
 * somebody notices. An HMAC covers the timestamp, a nonce and the body, so a
 * captured request expires, cannot be replayed, and cannot be modified.
 *
 * <h2>⛔ Constant-time comparison</h2>
 *
 * <p>{@link #verify} uses {@link MessageDigest#isEqual} rather than
 * {@code String.equals}. String comparison short-circuits at the first differing
 * character, so the time it takes reveals how many leading bytes were correct —
 * enough to forge a signature one byte at a time. This is the single most
 * commonly missed detail in HMAC implementations.
 */
public final class AvsSignature {

    /** Headers carrying the signature. Identical in both directions. */
    public static final String HEADER_TENANT = "X-AVS-Tenant";
    public static final String HEADER_SIGNATURE = "X-AVS-Signature";
    public static final String HEADER_TIMESTAMP = "X-AVS-Timestamp";
    public static final String HEADER_NONCE = "X-AVS-Nonce";

    /**
     * How far a clock may drift, in seconds.
     *
     * <p>Five minutes. Wide enough that ordinary NTP drift never rejects a
     * legitimate caller; narrow enough that a captured request is useless within
     * one coffee break. Must match {@code MAX_CLOCK_SKEW_SECONDS} in Python.
     */
    public static final long MAX_CLOCK_SKEW_SECONDS = 300;

    private static final String ALGORITHM = "HmacSHA256";

    private AvsSignature() {}

    /** Signed headers for an outbound request. */
    public record Headers(String tenant, String signature, String timestamp, String nonce) {}

    /**
     * Compute the hex HMAC-SHA256 over {@code timestamp.nonce.body}.
     *
     * <p>The body is signed as <b>raw bytes</b>, never as a decoded string. A
     * multipart upload is not valid UTF-8, and re-encoding it would change the
     * bytes and therefore the signature.
     */
    public static String compute(String secret, String timestamp, String nonce, byte[] body) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), ALGORITHM));

            mac.update(timestamp.getBytes(StandardCharsets.US_ASCII));
            mac.update((byte) '.');
            mac.update(nonce.getBytes(StandardCharsets.US_ASCII));
            mac.update((byte) '.');
            mac.update(body);

            return HexFormat.of().formatHex(mac.doFinal());
        } catch (java.security.GeneralSecurityException e) {
            // HmacSHA256 is mandatory in every JRE. Reaching here means the
            // security provider is broken, which is not recoverable.
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /** Produce headers for an outbound request to AVS. */
    public static Headers sign(String secret, String tenantId, byte[] body) {
        String timestamp = Long.toString(Instant.now().getEpochSecond());
        String nonce = UUID.randomUUID().toString().replace("-", "");
        return new Headers(tenantId, compute(secret, timestamp, nonce, body), timestamp, nonce);
    }

    /** Why a signature check failed. Never returned to the caller — see the controller. */
    public enum Failure {
        OK,
        MISSING_HEADERS,
        BAD_TIMESTAMP,
        CLOCK_SKEW,
        SIGNATURE_MISMATCH
    }

    /**
     * Verify an inbound signature — used by the callback endpoint.
     *
     * <p><b>⛔ This is what stands between the HRM and anyone who can reach the
     * callback URL.</b> Without it, a POST containing {@code "verdict":"VERIFIED"}
     * approves a forged Aadhaar. The body must be the <i>raw</i> bytes received,
     * before any parsing.
     */
    public static Failure verify(
            String secret, String signature, String timestamp, String nonce, byte[] body) {

        if (secret == null || secret.isBlank()
                || signature == null || signature.isBlank()
                || timestamp == null || timestamp.isBlank()
                || nonce == null || nonce.isBlank()) {
            return Failure.MISSING_HEADERS;
        }

        long sentAt;
        try {
            sentAt = Long.parseLong(timestamp);
        } catch (NumberFormatException e) {
            return Failure.BAD_TIMESTAMP;
        }

        long drift = Math.abs(Instant.now().getEpochSecond() - sentAt);
        if (drift > MAX_CLOCK_SKEW_SECONDS) {
            return Failure.CLOCK_SKEW;
        }

        String expected = compute(secret, timestamp, nonce, body);

        // ⛔ Constant-time. String.equals() leaks the length of the matching
        //    prefix through timing, which is enough to forge a signature.
        boolean match = MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII),
                signature.getBytes(StandardCharsets.US_ASCII));

        return match ? Failure.OK : Failure.SIGNATURE_MISMATCH;
    }
}
