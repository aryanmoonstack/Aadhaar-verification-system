-- Aadhaar verification records — PostgreSQL.
--
-- ⚠ Moved here from `integration/spring/` when the Spring client was dropped
--   (20 Aug 2026). The Java code became dead when the Next.js route started
--   calling AVS directly — but this file did not. It encodes two constraints
--   (D113) that nothing else in the system enforces, and they apply whichever
--   language writes the rows.
--
--   Applied with whatever your HRM already uses — Flyway, Liquibase, or by
--   hand. It is plain PostgreSQL and depends on nothing.
--
-- ⛔ THIS TABLE IS PERMANENT AND CONTAINS IDENTITY DATA.
--
--    Dheeraj's Step 8 decision: verification records are kept permanently in
--    the HRM. So every column here is a column that exists forever, and the
--    schema is the last line of defence against storing something that should
--    never have been stored.
--
-- ⚠ WHAT IS WRITTEN TODAY, AND WHY THE SCHEMA IS WIDER THAN THAT
--
--    Only APPROVED verifications are inserted right now — a real card, signed,
--    signature checked. Everything else shows the employee a re-upload message
--    and is not stored, which keeps failed attempts (and their identity data)
--    out of the database entirely.
--
--    The review columns below are unused for now on purpose. `PROFILE_MISMATCH`
--    needs expected identity passed at submit time, `TEXT_MISMATCH` needs OCR
--    (Step 17) and `DUPLICATE` needs Step 18 — none are reachable yet. When
--    they are, those rows need somewhere to land, and a schema change at that
--    point would be a migration against live identity data. Leaving the columns
--    here now costs nothing and avoids that.
--
-- ⛔ THERE IS NO COLUMN FOR A FULL AADHAAR NUMBER, AND THERE MUST NEVER BE.
--
--    The Secure QR contains only the last four digits (CONTRACTS.md §4). A
--    column for the full number could only ever be filled by constructing one,
--    which no code path is permitted to do. `aadhaar_last4` is CHECK-constrained
--    to exactly four digits so the database refuses a twelve-digit value even if
--    application code is wrong.

CREATE TABLE aadhaar_verification (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    job_id              VARCHAR(64)  NOT NULL UNIQUE,
    employee_id         BIGINT       NOT NULL,
    tenant_id           VARCHAR(64)  NOT NULL,

    -- One of the nine verdicts. CONTRACTS.md §1.
    verdict             VARCHAR(32)  NOT NULL,

    -- ⛔ The fact everything rests on. TRUE only when an RSA signature verified
    --    against a UIDAI public key. No other condition may set it.
    signature_valid     BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Which trust anchor approved it, for audit. `certificate_expired` records
    -- that UIDAI had rotated since issue — normal, and NOT a reason to reject.
    certificate_serial  VARCHAR(128),
    certificate_expired BOOLEAN      NOT NULL DEFAULT FALSE,
    qr_version          VARCHAR(8),

    -- Salted HMAC of the card's reference id. Links repeat submissions of the
    -- same card WITHOUT being reversible to an Aadhaar number. This is what
    -- duplicate detection joins on — never the number itself.
    reference_hash      VARCHAR(128),

    -- Demographics from the SIGNED payload. Trustworthy precisely because the
    -- signature covered them.
    holder_name         VARCHAR(255),
    holder_dob          VARCHAR(16),
    holder_gender       VARCHAR(16),
    aadhaar_last4       CHAR(4),

    user_message        TEXT,
    processing_ms       INTEGER,
    request_id          VARCHAR(64),

    submitted_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ,

    reviewed_by         VARCHAR(128),
    reviewed_at         TIMESTAMPTZ,
    review_note         TEXT,

    -- ⛔ The database itself refuses anything but exactly four digits. If
    --    application code ever tries to write a full Aadhaar number here, the
    --    INSERT fails rather than succeeding quietly.
    CONSTRAINT aadhaar_last4_is_four_digits
        CHECK (aadhaar_last4 IS NULL OR aadhaar_last4 ~ '^[0-9]{4}$'),

    -- ⛔ Rule 1: VERIFIED requires a valid signature. Enforced in the schema so
    --    that no future code path, migration or manual UPDATE can approve
    --    something the cryptography did not.
    CONSTRAINT verified_requires_valid_signature
        CHECK (verdict <> 'VERIFIED' OR signature_valid = TRUE)
);

COMMENT ON CONSTRAINT verified_requires_valid_signature ON aadhaar_verification IS
    'CONTRACTS.md Rule 1 — VERIFIED is the only auto-approval and requires signature_valid.';

-- The HR review queue: everything awaiting a human. Partial, because reviewed
-- rows are the overwhelming majority and never appear in this query.
CREATE INDEX idx_aadhaar_pending_review
    ON aadhaar_verification (tenant_id, submitted_at DESC)
    WHERE reviewed_at IS NULL AND verdict <> 'VERIFIED';

-- Duplicate detection (Step 18): has this CARD been used by another employee?
CREATE INDEX idx_aadhaar_reference_hash
    ON aadhaar_verification (tenant_id, reference_hash)
    WHERE reference_hash IS NOT NULL;

CREATE INDEX idx_aadhaar_employee ON aadhaar_verification (employee_id, submitted_at DESC);
