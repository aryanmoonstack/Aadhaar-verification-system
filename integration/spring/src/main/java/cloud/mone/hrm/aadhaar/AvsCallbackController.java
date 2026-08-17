package cloud.mone.hrm.aadhaar;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Receives verification results from AVS — Step 10.
 *
 * <h2>⛔ THIS IS THE MOST SECURITY-CRITICAL FILE IN THE INTEGRATION</h2>
 *
 * <p>This endpoint is reachable from AVS, which means it is reachable from
 * wherever AVS lives. If it accepted an unsigned body, then anyone who could
 * reach this URL could send:
 *
 * <pre>{@code   {"job_id":"...","verdict":"VERIFIED","signature_valid":true} }</pre>
 *
 * <p>and the HRM would mark a forged Aadhaar as approved. Every piece of
 * cryptography in the Python service — the RSA signature check, the pinned trust
 * store, the tamper-evident audit trail — would be bypassed by a single
 * unauthenticated POST. <b>The chain of trust ends here, and it is only as
 * strong as this one check.</b>
 *
 * <p>So: the HMAC is verified over the <b>raw request body</b>, before the JSON
 * is parsed, and the body is discarded if it fails.
 *
 * <h2>Why the raw body, and why before parsing</h2>
 *
 * <p>Jackson normalises as it parses — key order, whitespace, numeric forms. Any
 * of that changes the bytes, so re-serialising the parsed object produces a
 * different signature than AVS computed. Verify what actually arrived.
 *
 * <p>Parsing first would also mean running a parser over attacker-controlled
 * input before establishing that the sender is who they claim to be.
 *
 * <h2>What this endpoint deliberately does not do</h2>
 *
 * <p>It does not decide anything. It records the verdict AVS reached. The
 * decision was made by an RSA signature check against UIDAI's public key, and
 * nothing in the HRM may override it — see CONTRACTS.md §1 Rule 1.
 */
@RestController
@RequestMapping("/api/kyc/aadhaar")
public class AvsCallbackController {

    private static final Logger log = LoggerFactory.getLogger(AvsCallbackController.class);

    private final AvsProperties properties;
    private final AadhaarVerificationService verifications;
    private final ObjectMapper objectMapper;

    /**
     * Nonces already seen, so a captured callback cannot be replayed.
     *
     * <p>In-memory and therefore per-instance: behind a load balancer a replay
     * could land on a different node and be accepted. For a callback that is
     * idempotent by {@code jobId} this is acceptable — the second delivery
     * updates the same row to the same value. If you run more than one HRM
     * instance and want strict replay protection, back this with Redis.
     */
    private final Map<String, Long> seenNonces = new ConcurrentHashMap<>();

    private static final Duration NONCE_RETENTION =
            Duration.ofSeconds(AvsSignature.MAX_CLOCK_SKEW_SECONDS * 2);

    public AvsCallbackController(
            AvsProperties properties,
            AadhaarVerificationService verifications,
            ObjectMapper objectMapper) {
        this.properties = properties;
        this.verifications = verifications;
        this.objectMapper = objectMapper;
    }

    @PostMapping(path = "/callback", consumes = "application/json")
    public ResponseEntity<Map<String, String>> receive(
            @RequestBody byte[] rawBody,
            @RequestHeader(value = AvsSignature.HEADER_SIGNATURE, required = false) String signature,
            @RequestHeader(value = AvsSignature.HEADER_TIMESTAMP, required = false) String timestamp,
            @RequestHeader(value = AvsSignature.HEADER_NONCE, required = false) String nonce,
            @RequestHeader(value = "X-Request-ID", required = false) String requestId,
            HttpServletRequest request) {

        // ⛔ STEP 1, BEFORE ANYTHING ELSE. Not after parsing, not after logging
        //    the body, not after looking up the job.
        AvsSignature.Failure result = AvsSignature.verify(
                properties.callbackSecret(), signature, timestamp, nonce, rawBody);

        if (result != AvsSignature.Failure.OK) {
            log.warn(
                    "avs.callback.rejected reason={} remote={} requestId={}",
                    result, request.getRemoteAddr(), requestId);
            return unauthorized();
        }

        if (!rememberNonce(nonce)) {
            log.warn("avs.callback.replay nonce={} requestId={}", nonce, requestId);
            return unauthorized();
        }

        AvsResult payload;
        try {
            payload = objectMapper.readValue(
                    new String(rawBody, StandardCharsets.UTF_8), AvsResult.class);
        } catch (Exception e) {
            // Authenticated but unreadable. Different from unauthenticated: this
            // is a bug or a version mismatch on our side, worth an alert.
            log.error("avs.callback.unparseable requestId={}", requestId, e);
            return ResponseEntity.badRequest().body(Map.of("status", "unparseable"));
        }

        verifications.applyResult(payload, requestId);

        log.info(
                "avs.callback.accepted jobId={} verdict={} requestId={}",
                payload.jobId(), payload.verdict(), requestId);

        return ResponseEntity.ok(Map.of("status", "recorded"));
    }

    /**
     * One opaque response for every authentication failure.
     *
     * <p>Distinguishing "bad signature" from "replayed nonce" from "clock skew"
     * hands an attacker a working oracle for probing the scheme. The real reason
     * is in our logs; the caller gets one word. Mirrors the Python service's 401.
     */
    private ResponseEntity<Map<String, String>> unauthorized() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("status", "authentication failed"));
    }

    /** @return false if this nonce has been seen — a replay. */
    private boolean rememberNonce(String nonce) {
        long now = System.currentTimeMillis();
        long cutoff = now - NONCE_RETENTION.toMillis();
        seenNonces.entrySet().removeIf(e -> e.getValue() < cutoff);
        return seenNonces.putIfAbsent(nonce, now) == null;
    }
}
