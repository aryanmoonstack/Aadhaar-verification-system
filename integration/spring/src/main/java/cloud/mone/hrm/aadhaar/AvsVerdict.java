package cloud.mone.hrm.aadhaar;

/**
 * The nine verdicts — CONTRACTS.md §1. Step 10.
 *
 * <p><b>⛔ Exactly nine. No step may invent a tenth.</b> This enum mirrors
 * {@code avs.contracts.enums.Verdict}; adding a value here without adding it
 * there means the HRM claims an outcome the service cannot produce.
 *
 * <h2>Two absolute rules, encoded rather than documented</h2>
 *
 * <p><b>Rule 1</b> — {@link #VERIFIED} is the only auto-approval, and the
 * service only produces it when an RSA signature verified against UIDAI's
 * public key. {@link #isAutoApprove()} is the only place the HRM should ask.
 *
 * <p><b>Rule 2</b> — nothing is ever auto-rejected. Every other verdict routes
 * to a re-upload prompt or a human. {@link #isAutoReject()} exists only to
 * return {@code false}, so that a future reader looking for auto-rejection
 * finds the reason it does not exist.
 */
public enum AvsVerdict {

    /** Valid UIDAI signature. The ONLY verdict that may approve automatically. */
    VERIFIED(true, false),

    /** QR decoded, signature invalid. Human review — never an accusation. */
    TAMPERED(false, true),

    /** No QR could be read. A retry, not a failure of the person. */
    UNREADABLE(false, false),

    /** Pre-2018 unsigned QR. Not a forgery — it simply predates signing. */
    LEGACY_FORMAT(false, false),

    /** Not an Aadhaar card. */
    WRONG_DOCUMENT(false, false),

    /** Signature valid, name or DOB differs from the employee profile. */
    PROFILE_MISMATCH(false, true),

    /** Signature valid, printed text disagrees with the signed fields. */
    TEXT_MISMATCH(false, true),

    /** This Aadhaar is already bound to another employee. */
    DUPLICATE(false, true),

    /** Our processing failed. The employee should wait, not re-upload. */
    ERROR(false, true);

    private final boolean autoApprove;
    private final boolean humanReview;

    AvsVerdict(boolean autoApprove, boolean humanReview) {
        this.autoApprove = autoApprove;
        this.humanReview = humanReview;
    }

    /** ⛔ The only question the HRM should ask before approving a profile. */
    public boolean isAutoApprove() {
        return autoApprove;
    }

    public boolean requiresHumanReview() {
        return humanReview;
    }

    /**
     * Always false. CONTRACTS.md §1 Rule 2.
     *
     * <p>The system never tells an employee they committed fraud. A genuine card
     * photographed badly is indistinguishable from a forgery to any automated
     * check, so no automated check may reject one.
     */
    public boolean isAutoReject() {
        return false;
    }

    /**
     * Unknown values map to {@link #ERROR} rather than throwing.
     *
     * <p>If AVS ever sends a verdict this HRM build does not know, failing the
     * whole callback would lose the record entirely. ERROR routes it to a human,
     * which is the safe direction.
     */
    public static AvsVerdict parse(String value) {
        if (value == null) return ERROR;
        try {
            return valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return ERROR;
        }
    }
}
