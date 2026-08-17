package cloud.mone.hrm.aadhaar;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/** Step 10. */
public interface AadhaarVerificationRepository extends JpaRepository<AadhaarVerification, Long> {

    Optional<AadhaarVerification> findByJobId(String jobId);

    List<AadhaarVerification> findByEmployeeIdOrderBySubmittedAtDesc(Long employeeId);

    /** The HR review queue. Backed by the partial index in V1. */
    @Query("""
        SELECT v FROM AadhaarVerification v
        WHERE v.tenantId = :tenantId
          AND v.reviewedAt IS NULL
          AND v.verdict <> cloud.mone.hrm.aadhaar.AvsVerdict.VERIFIED
        ORDER BY v.submittedAt DESC
        """)
    List<AadhaarVerification> findAwaitingReview(@Param("tenantId") String tenantId);

    /**
     * Has this CARD already been used by a different employee? (Step 18.)
     *
     * <p>Matches on the salted reference hash, never on an Aadhaar number —
     * which the HRM does not hold and must not derive.
     */
    @Query("""
        SELECT v FROM AadhaarVerification v
        WHERE v.tenantId = :tenantId
          AND v.referenceHash = :referenceHash
          AND v.employeeId <> :employeeId
          AND v.signatureValid = true
        """)
    List<AadhaarVerification> findSameCardOtherEmployees(
            @Param("tenantId") String tenantId,
            @Param("referenceHash") String referenceHash,
            @Param("employeeId") Long employeeId);
}
