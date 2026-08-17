# Benchmarks

## Decode rate — the project's primary health metric

Established in **Step 5** against the local corpus, then re-measured after each AI
vision step to prove the lift.

| Step | What changed | Decode rate |
|------|--------------|-------------|
| 5    | Deterministic cascade only | _baseline — record here_ |
| 15   | + AI QR localiser | _target: material improvement_ |
| 16   | + browser pre-check | _target: first-attempt ≥90%_ |
| 19   | + AI restoration on retry | _target: ≥95% overall_ |

Record the Step 5 number carefully. It is the figure every later AI investment is
measured against.

Benchmarks read from `AVS_CORPUS_DIR` and never copy images into the repository.
