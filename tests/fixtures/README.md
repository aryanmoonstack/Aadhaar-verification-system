# Test Fixtures

## ⛔ Never commit Aadhaar data

No real Aadhaar image, QR payload string, or Aadhaar number belongs in this
repository — not in fixtures, not in test files, not in comments.

## Where the corpus lives

On your machine only, outside the repo:

```
/your/path/aadhaar-corpus/
├── genuine/     50-80 real cards — varied phones, lighting, scanners
└── tampered/    20+ deliberately edited, re-printed, re-photographed
```

Point tests at it:

```bash
export AVS_CORPUS_DIR=/your/path/aadhaar-corpus
pytest -m corpus
```

Tests marked `@pytest.mark.corpus` skip automatically when it is absent, so CI
stays green without ever seeing the data.

## What may be committed

Synthetic images, structurally-invalid payloads, and malformed inputs used to test
error paths — provided they contain no real personal data.
