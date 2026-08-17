package cloud.mone.hrm.aadhaar;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The verification result AVS sends back — CONTRACTS.md §8. Step 10.
 *
 * <p>{@code @JsonIgnoreProperties(ignoreUnknown = true)} is deliberate: the
 * contract is additive, so AVS may add fields in a later step. An HRM that
 * refused unknown fields would break on a routine service upgrade.
 *
 * <p><b>⛔ There is no field for a full Aadhaar number, and there must never
 * be.</b> The Secure QR contains only the last four digits — CONTRACTS.md §4 —
 * so a field for the full number could only ever be filled by constructing one,
 * which no code path may do.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AvsResult(
        @JsonProperty("job_id") String jobId,
        @JsonProperty("verdict") String verdict,
        @JsonProperty("user_message") String userMessage,
        @JsonProperty("processing_ms") Integer processingMs,
        @JsonProperty("reference_hash") String referenceHash,
        @JsonProperty("proof") Proof proof,
        @JsonProperty("identity") Identity identity) {

    /** Evidence for the verdict. {@code valid} is the fact everything rests on. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Proof(
            @JsonProperty("valid") boolean valid,
            @JsonProperty("certificate_serial") String certificateSerial,
            @JsonProperty("certificate_expired") boolean certificateExpired,
            @JsonProperty("qr_version") String qrVersion,
            @JsonProperty("signed_byte_length") Integer signedByteLength) {}

    /** Demographics from the signed QR. {@code aadhaarLast4} is FOUR digits. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Identity(
            @JsonProperty("name") String name,
            @JsonProperty("dob") String dob,
            @JsonProperty("gender") String gender,
            @JsonProperty("aadhaar_last4") String aadhaarLast4) {}

    public AvsVerdict typedVerdict() {
        return AvsVerdict.parse(verdict);
    }

    /**
     * ⛔ The only safe approval test.
     *
     * <p>Requires BOTH the verdict and the underlying signature fact. Trusting
     * the verdict string alone would mean a bug that mislabels a result could
     * approve a forgery; requiring {@code proof.valid} means an approval always
     * traces back to an RSA signature that verified against UIDAI's key.
     */
    public boolean isApproved() {
        return typedVerdict().isAutoApprove() && proof != null && proof.valid();
    }
}
