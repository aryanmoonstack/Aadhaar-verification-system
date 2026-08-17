package cloud.mone.hrm.aadhaar;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * A permanent record of one Aadhaar verification — Step 10.
 *
 * <p><b>⛔ THIS ROW IS KEPT FOREVER.</b> Per the Step 8 decision, verification
 * records are retained permanently in the HRM. Anything stored here is stored
 * for the lifetime of the company, so every field earns its place.
 *
 * <p><b>There is no field for a full Aadhaar number.</b> The Secure QR contains
 * only the last four digits — CONTRACTS.md §4 — so a full number could only be
 * produced by constructing one. The database additionally CHECK-constrains
 * {@code aadhaarLast4} to exactly four digits, so a wrong value fails the INSERT
 * rather than being stored quietly.
 *
 * <p>The demographics here come from the <i>signed</i> payload, which is why
 * they can be trusted: UIDAI's signature covered those exact bytes.
 */
@Entity
@Table(name = "aadhaar_verification")
public class AadhaarVerification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Idempotency key. A redelivered callback updates this row, never inserts. */
    @Column(name = "job_id", nullable = false, unique = true, length = 64)
    private String jobId;

    @Column(name = "employee_id", nullable = false)
    private Long employeeId;

    @Column(name = "tenant_id", nullable = false, length = 64)
    private String tenantId;

    @Enumerated(EnumType.STRING)
    @Column(name = "verdict", nullable = false, length = 32)
    private AvsVerdict verdict = AvsVerdict.ERROR;

    /**
     * ⛔ The fact everything rests on.
     *
     * <p>True only when an RSA-2048/SHA-256 signature verified against a UIDAI
     * public key. No other condition may set it, and the database enforces that
     * a VERIFIED row must have it set.
     */
    @Column(name = "signature_valid", nullable = false)
    private boolean signatureValid;

    @Column(name = "certificate_serial", length = 128)
    private String certificateSerial;

    /**
     * The approving certificate had lapsed by the time we checked.
     *
     * <p><b>Not a problem.</b> UIDAI rotates its signing certificate every few
     * years and an e-Aadhaar keeps the signature it was issued with forever, so
     * most genuine older cards verify under a lapsed anchor. Recorded for audit,
     * never used to reject.
     */
    @Column(name = "certificate_expired", nullable = false)
    private boolean certificateExpired;

    @Column(name = "qr_version", length = 8)
    private String qrVersion;

    /**
     * Salted HMAC of the card's reference id.
     *
     * <p>Links repeat submissions of the same card without being reversible to
     * an Aadhaar number. Duplicate detection joins on this — never on a number.
     */
    @Column(name = "reference_hash", length = 128)
    private String referenceHash;

    @Column(name = "holder_name", length = 255)
    private String holderName;

    @Column(name = "holder_dob", length = 16)
    private String holderDob;

    @Column(name = "holder_gender", length = 16)
    private String holderGender;

    /** Exactly four digits. CHECK-constrained in the database. */
    @Column(name = "aadhaar_last4", length = 4, columnDefinition = "char(4)")
    private String aadhaarLast4;

    /**
     * The message shown to the employee.
     *
     * <p>⚠ The word "fake" must never appear here — CONTRACTS.md §1. A genuine
     * card photographed badly is not a forgery, and the service is careful to
     * say "could not be verified" instead. Do not rewrite these strings in the UI.
     */
    @Column(name = "user_message", columnDefinition = "text")
    private String userMessage;

    @Column(name = "processing_ms")
    private Integer processingMs;

    /** Correlates this row with AVS logs for the same document. */
    @Column(name = "request_id", length = 64)
    private String requestId;

    @Column(name = "submitted_at", nullable = false)
    private Instant submittedAt = Instant.now();

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "reviewed_by", length = 128)
    private String reviewedBy;

    @Column(name = "reviewed_at")
    private Instant reviewedAt;

    @Column(name = "review_note", columnDefinition = "text")
    private String reviewNote;

    protected AadhaarVerification() {} // JPA

    public AadhaarVerification(String jobId, Long employeeId, String tenantId) {
        this.jobId = jobId;
        this.employeeId = employeeId;
        this.tenantId = tenantId;
    }

    /**
     * ⛔ The ONLY question the HRM should ask before approving a profile.
     *
     * <p>Requires both the verdict AND the underlying signature fact. Checking
     * the verdict alone would mean a mislabelling bug could approve a forgery;
     * requiring {@code signatureValid} means every approval traces back to an
     * RSA signature that verified against UIDAI's key.
     */
    public boolean isApproved() {
        return verdict == AvsVerdict.VERIFIED && signatureValid;
    }

    public boolean awaitsReview() {
        return verdict.requiresHumanReview() && reviewedAt == null;
    }

    public void recordReview(String reviewer, String note) {
        this.reviewedBy = reviewer;
        this.reviewNote = note;
        this.reviewedAt = Instant.now();
    }

    // ── accessors ───────────────────────────────────────────────────────────

    public Long getId() { return id; }
    public String getJobId() { return jobId; }
    public Long getEmployeeId() { return employeeId; }
    public String getTenantId() { return tenantId; }
    public AvsVerdict getVerdict() { return verdict; }
    public boolean isSignatureValid() { return signatureValid; }
    public String getCertificateSerial() { return certificateSerial; }
    public boolean isCertificateExpired() { return certificateExpired; }
    public String getQrVersion() { return qrVersion; }
    public String getReferenceHash() { return referenceHash; }
    public String getHolderName() { return holderName; }
    public String getHolderDob() { return holderDob; }
    public String getHolderGender() { return holderGender; }
    public String getAadhaarLast4() { return aadhaarLast4; }
    public String getUserMessage() { return userMessage; }
    public Integer getProcessingMs() { return processingMs; }
    public String getRequestId() { return requestId; }
    public Instant getSubmittedAt() { return submittedAt; }
    public Instant getCompletedAt() { return completedAt; }
    public String getReviewedBy() { return reviewedBy; }
    public Instant getReviewedAt() { return reviewedAt; }
    public String getReviewNote() { return reviewNote; }

    void setVerdict(AvsVerdict verdict) { this.verdict = verdict; }
    void setSignatureValid(boolean v) { this.signatureValid = v; }
    void setCertificateSerial(String v) { this.certificateSerial = v; }
    void setCertificateExpired(boolean v) { this.certificateExpired = v; }
    void setQrVersion(String v) { this.qrVersion = v; }
    void setReferenceHash(String v) { this.referenceHash = v; }
    void setHolderName(String v) { this.holderName = v; }
    void setHolderDob(String v) { this.holderDob = v; }
    void setHolderGender(String v) { this.holderGender = v; }
    void setAadhaarLast4(String v) { this.aadhaarLast4 = v; }
    void setUserMessage(String v) { this.userMessage = v; }
    void setProcessingMs(Integer v) { this.processingMs = v; }
    void setRequestId(String v) { this.requestId = v; }
    void setCompletedAt(Instant v) { this.completedAt = v; }
}
