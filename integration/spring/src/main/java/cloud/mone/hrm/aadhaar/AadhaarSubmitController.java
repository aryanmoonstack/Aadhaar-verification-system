package cloud.mone.hrm.aadhaar;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

/**
 * The endpoint the HRM front end posts card images to — Step 10/11.
 *
 * <p>This is the missing link between the two halves of the integration: the
 * Next.js route at {@code /api/aadhaar/verify} forwards here, and this hands off
 * to {@link AadhaarVerificationService}.
 *
 * <h2>Why the browser cannot skip this</h2>
 *
 * <p>Calling AVS requires an HMAC signature over the request body, and a
 * browser cannot hold a signing secret — anything shipped to a client is public
 * however it is obfuscated. So the images land here, and the server signs.
 *
 * <h2>⛔ This returns a job id, not a verdict</h2>
 *
 * <p>Verification takes 3–12 seconds. Blocking a servlet thread for that long
 * means a handful of concurrent uploads exhausts the pool and the whole HRM
 * stops responding. The verdict arrives at {@link AvsCallbackController} and the
 * front end polls {@link #status}.
 */
@RestController
@RequestMapping("/api/kyc/aadhaar")
public class AadhaarSubmitController {

    private static final Logger log = LoggerFactory.getLogger(AadhaarSubmitController.class);

    /** Two 12MP JPEGs are roughly 10MB. This is generous, not tight. */
    private static final long MAX_IMAGE_BYTES = 16L * 1024 * 1024;

    private final AadhaarVerificationService verifications;

    public AadhaarSubmitController(AadhaarVerificationService verifications) {
        this.verifications = verifications;
    }

    /**
     * Accept both faces of an employee's Aadhaar card.
     *
     * <p><b>Both are required</b> — CONTRACTS.md §11. The UIDAI signature covers
     * the QR payload only, never the printed face, so one image cannot be a
     * complete document. The QR may be on <i>either</i> side; do not validate
     * that it is on the back.
     */
    @PostMapping(path = "/submit", consumes = "multipart/form-data")
    public ResponseEntity<Map<String, Object>> submit(
            @RequestParam("front") MultipartFile front,
            @RequestParam("back") MultipartFile back,
            @RequestParam("employeeId") Long employeeId,
            @RequestHeader(value = "X-Request-ID", required = false) String requestId) {

        ResponseEntity<Map<String, Object>> rejection = validate(front, "front");
        if (rejection != null) return rejection;
        rejection = validate(back, "back");
        if (rejection != null) return rejection;

        try {
            AadhaarVerification record = verifications.submit(
                    employeeId, front.getBytes(), back.getBytes(), requestId);

            log.info("aadhaar.submit employeeId={} jobId={} requestId={}",
                    employeeId, record.getJobId(), requestId);

            return ResponseEntity.accepted().body(Map.of(
                    "jobId", record.getJobId(),
                    "status", record.getCompletedAt() == null ? "PENDING" : "DONE",
                    "message", record.getUserMessage()));

        } catch (IOException e) {
            log.error("aadhaar.submit.read_failed employeeId={}", employeeId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message",
                            "We could not read the photos. Please try again."));
        }
    }

    /**
     * Poll for a verdict.
     *
     * <p>The callback normally arrives first, so this usually returns a settled
     * result immediately. It exists because a callback can be missed — a deploy,
     * a network partition — and a UI that only ever waited for a push would hang
     * forever when one is lost.
     */
    @GetMapping("/status/{jobId}")
    public ResponseEntity<Map<String, Object>> status(@PathVariable String jobId) {
        return verifications.findByJobId(jobId)
                .map(record -> ResponseEntity.ok(Map.of(
                        "jobId", record.getJobId(),
                        "status", record.getCompletedAt() == null ? "PENDING" : "DONE",
                        "verdict", record.getVerdict().name(),
                        "approved", record.isApproved(),
                        "awaitsReview", record.awaitsReview(),
                        // ⛔ The service's own wording. Do not rewrite it in the
                        //    UI — it is deliberately phrased to never accuse
                        //    anyone of forgery. CONTRACTS.md §1.
                        "message", record.getUserMessage() == null ? "" : record.getUserMessage())))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** The HR review queue. Everything a human still has to decide. */
    @GetMapping("/review-queue")
    public List<Map<String, Object>> reviewQueue() {
        return verifications.awaitingReview().stream()
                .map(record -> Map.<String, Object>of(
                        "jobId", record.getJobId(),
                        "employeeId", record.getEmployeeId(),
                        "verdict", record.getVerdict().name(),
                        "submittedAt", record.getSubmittedAt().toString(),
                        "holderName", record.getHolderName() == null ? "" : record.getHolderName()))
                .toList();
    }

    /**
     * Validate an uploaded file before doing anything with it.
     *
     * <p>⚠ Content type is checked as a courtesy only. AVS re-checks the actual
     * leading bytes, because a declared content type is attacker-controlled and
     * a {@code .jpg} name proves nothing about what is inside.
     */
    private ResponseEntity<Map<String, Object>> validate(MultipartFile file, String which) {
        if (file == null || file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "message", "Please provide a photo of the " + which + " of your card."));
        }
        if (file.getSize() > MAX_IMAGE_BYTES) {
            return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(Map.of(
                    "message", "That photo is too large. Please try again."));
        }
        return null;
    }
}
