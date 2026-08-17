package cloud.mone.hrm.aadhaar;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Ties submission, callback and storage together — Step 10.
 *
 * <p>This is the only class the rest of the HRM should talk to. Everything else
 * in this package is an implementation detail of how AVS is reached.
 *
 * <h2>The shape of the flow</h2>
 *
 * <pre>
 *   employee uploads both card faces
 *        │
 *        ├─ submit()   → row created, PENDING, returns immediately
 *        │              (AVS answers 202; nothing waits)
 *        │
 *        └─ ~3-12 seconds later
 *           AvsCallbackController → applyResult() → row updated
 * </pre>
 *
 * <p><b>Nothing blocks.</b> Verification takes seconds; holding an HTTP worker
 * for that long means a handful of concurrent uploads exhausts the pool and the
 * whole HRM stops responding.
 */
@Service
public class AadhaarVerificationService {

    private static final Logger log = LoggerFactory.getLogger(AadhaarVerificationService.class);

    private final AvsClient client;
    private final AadhaarVerificationRepository repository;
    private final AvsProperties properties;

    public AadhaarVerificationService(
            AvsClient client,
            AadhaarVerificationRepository repository,
            AvsProperties properties) {
        this.client = client;
        this.repository = repository;
        this.properties = properties;
    }

    /**
     * Submit both faces of an employee's Aadhaar card.
     *
     * <p><b>Both are required</b> — CONTRACTS.md §11. The UIDAI signature covers
     * the QR payload only, never the printed face, so a single image cannot be a
     * complete document. Do not assume the QR is on the back: placement varies
     * by card format and the service checks both.
     *
     * @return the pending record. The verdict arrives by callback.
     */
    @Transactional
    public AadhaarVerification submit(
            Long employeeId, byte[] frontImage, byte[] backImage, String requestId) {

        String jobId = UUID.randomUUID().toString();
        AadhaarVerification record =
                new AadhaarVerification(jobId, employeeId, properties.tenantId());
        record.setRequestId(requestId);
        record.setUserMessage("Checking your Aadhaar. This usually takes a few seconds.");
        repository.save(record);

        AvsClient.Submission outcome =
                client.submit(jobId, frontImage, backImage, requestId);

        if (outcome instanceof AvsClient.Submission.Unavailable unavailable) {
            // ⛔ ERROR, not a rejection. ERROR means "wait for us"; a rejection
            //    means "your document was no good". Telling someone their
            //    genuine card failed because OUR trust store was empty would be
            //    both wrong and insulting.
            record.setVerdict(AvsVerdict.ERROR);
            record.setUserMessage(
                    "We could not check your Aadhaar just now. Please try again shortly.");
            record.setCompletedAt(Instant.now());
            log.warn("aadhaar.submit.unavailable employeeId={} reason={}",
                    employeeId, unavailable.reason());

        } else if (outcome instanceof AvsClient.Submission.Rejected rejected) {
            // Our request was malformed or unauthenticated — a bug on our side,
            // not the employee's problem. Still ERROR to them.
            record.setVerdict(AvsVerdict.ERROR);
            record.setUserMessage(
                    "We could not check your Aadhaar just now. Please try again shortly.");
            record.setCompletedAt(Instant.now());
            log.error("aadhaar.submit.rejected employeeId={} status={} reason={}",
                    employeeId, rejected.status(), rejected.reason());
        }

        return record;
    }

    /**
     * Record a verdict delivered by callback.
     *
     * <p><b>⛔ The caller must have verified the HMAC before calling this.</b>
     * {@link AvsCallbackController} does. Nothing in this method authenticates
     * anything — it trusts its input completely, which is safe only because the
     * controller established provenance first.
     *
     * <p>Idempotent by {@code jobId}: AVS may deliver twice, and the second
     * delivery must update the same row to the same values rather than create a
     * duplicate.
     */
    @Transactional
    public void applyResult(AvsResult result, String requestId) {
        Optional<AadhaarVerification> existing = repository.findByJobId(result.jobId());

        if (existing.isEmpty()) {
            // Authenticated, so genuinely from AVS — but we have no record of
            // asking. Worth investigating rather than discarding silently.
            log.error("aadhaar.callback.unknown_job jobId={} requestId={}",
                    result.jobId(), requestId);
            return;
        }

        AadhaarVerification record = existing.get();
        if (record.getCompletedAt() != null) {
            log.info("aadhaar.callback.duplicate jobId={} — already recorded", result.jobId());
            return;
        }

        record.setVerdict(result.typedVerdict());
        record.setUserMessage(result.userMessage());
        record.setProcessingMs(result.processingMs());
        record.setReferenceHash(result.referenceHash());
        record.setCompletedAt(Instant.now());

        if (result.proof() != null) {
            // ⛔ signature_valid comes ONLY from the proof. Never inferred from
            //    the verdict string — the database CHECK constraint depends on
            //    this being the real cryptographic fact.
            record.setSignatureValid(result.proof().valid());
            record.setCertificateSerial(result.proof().certificateSerial());
            record.setCertificateExpired(result.proof().certificateExpired());
            record.setQrVersion(result.proof().qrVersion());
        }

        if (result.identity() != null) {
            record.setHolderName(result.identity().name());
            record.setHolderDob(result.identity().dob());
            record.setHolderGender(result.identity().gender());
            record.setAadhaarLast4(result.identity().aadhaarLast4());
        }

        repository.save(record);

        log.info("aadhaar.callback.recorded jobId={} verdict={} approved={} requestId={}",
                record.getJobId(), record.getVerdict(), record.isApproved(), requestId);
    }

    /** One record by job id. Used by the status endpoint the UI polls. */
    @Transactional(readOnly = true)
    public Optional<AadhaarVerification> findByJobId(String jobId) {
        return repository.findByJobId(jobId);
    }

    /** Everything awaiting a human decision, newest first. */
    @Transactional(readOnly = true)
    public List<AadhaarVerification> awaitingReview() {
        return repository.findAwaitingReview(properties.tenantId());
    }

    /**
     * Has this card already been used by someone else in this tenant?
     *
     * <p>Matches on the salted reference hash. The HRM never holds an Aadhaar
     * number and must not derive one to answer this.
     */
    @Transactional(readOnly = true)
    public List<AadhaarVerification> otherEmployeesUsingSameCard(AadhaarVerification record) {
        if (record.getReferenceHash() == null) {
            return List.of();
        }
        return repository.findSameCardOtherEmployees(
                record.getTenantId(), record.getReferenceHash(), record.getEmployeeId());
    }
}
