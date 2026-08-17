# UIDAI Certificate Trust Store

This directory is the **root of trust for the entire system**. Everything AVS
approves, it approves because a certificate in here validated a signature.

Treat changes to this directory with the same care as a production database
migration.

---

## Obtaining UIDAI certificates

UIDAI publishes its public signing certificates in the **Developer Section →
Data and Downloads** area of `uidai.gov.in`:

<https://uidai.gov.in/en/916-developer-section/data-and-downloads-section/19388-uidai-certificate-details-2.html>

Download the **production** certificate for live use. A separate staging
certificate exists for UIDAI's test environment; keep the two apart, and never
put the staging certificate in a production trust store.

Files are usually DER-encoded with a `.cer` extension. AVS accepts `.cer`,
`.crt`, `.pem` and `.der`, in either PEM or DER encoding.

---

## Adding a certificate

```powershell
# 1. Download the certificate into this directory
#    certs/uidai_prod_2026.cer

# 2. Print its fingerprint
avs certs fingerprints

# 3. Verify that fingerprint against UIDAI's published value
#    Do NOT skip this. It is the only step that proves the file you downloaded
#    is the file UIDAI published.

# 4. Add the line to FINGERPRINTS.txt (see pinning, below)

# 5. Confirm the store is healthy
avs certs status
```

---

## The four rules

### 1. Keep multiple certificates. Always.

UIDAI rotates its signing certificate. Verification tries **every** certificate
in this directory, so a card signed under the previous certificate keeps working
after a rotation.

A store holding one certificate works perfectly right up until the day it
silently rejects every genuine card in the country. Never prune this directory
down to "just the current one" — keep superseded certificates until you are
certain no card in circulation was signed with them.

### 2. Never fetch certificates at runtime.

They are committed files, loaded once at startup. This is what allows AVS to run
with **outbound internet firewalled shut** — no egress, nothing to intercept, no
dependency on UIDAI's uptime at verification time.

### 3. Public keys only.

These are public certificates. **No private key ever belongs in this repository.**
The `detect-private-key` pre-commit hook enforces this, but the rule matters more
than the hook.

### 4. Enable pinning in production.

See below. Without it, write access to this directory is enough to mint
approvals.

---

## Fingerprint pinning — `FINGERPRINTS.txt`

### The attack it prevents

Anyone who can write a file into `certs/` can add a certificate whose private key
they hold. They then sign a forged Aadhaar payload themselves, AVS finds their
certificate in the trust store, the signature validates, and the forgery is
approved as genuine.

The cryptography is doing exactly what it should. The trust store is what failed.

### How pinning closes it

When `FINGERPRINTS.txt` exists, it acts as an **allow-list**. Only certificates
whose SHA-256 fingerprint appears in the file are loaded. Everything else is
refused and reported as a fatal load issue.

An attacker would now need to modify a version-controlled, code-reviewed file as
well as drop the certificate — a far higher bar, and one that leaves a trail.

### Format

```
# SHA-256 fingerprints of trusted UIDAI certificates.
# Verify each against UIDAI's published value before adding a line here.

a1b2c3d4e5f6...  uidai_prod_2026.cer
9f8e7d6c5b4a...  uidai_prod_2024.cer   # superseded, kept for older cards
```

- One fingerprint per line, optionally followed by a label
- Blank lines and `#` comments are ignored
- Both `aabbcc…` and `AA:BB:CC:…` forms are accepted (the latter is what
  `openssl x509 -fingerprint -sha256` prints)

### Generating it

```powershell
avs certs fingerprints > certs\FINGERPRINTS.txt
```

Then **check each fingerprint against UIDAI's published value before trusting the
file**. Generating the pin file from the certificates already present only pins
what you have — it does not verify that what you have is authentic.

### Enforcing it

```python
FileCertificateStore(cert_dir, require_pinning=True)
```

The store then refuses to start at all if `FINGERPRINTS.txt` is missing. Use this
in production, where starting without pinning is worse than not starting.

---

## Monitoring

```powershell
avs certs status                 # full table + health summary
avs certs status --strict        # exit 1 on any warning — for CI and health checks
```

| Signal | Meaning | Action |
|---|---|---|
| `OK` | All certificates valid, none expiring soon | None |
| `WARNING` | Something expires within 90 days, or a certificate was refused | Obtain a replacement, or investigate the refusal |
| `EXPIRED` | Certificates present but none usable | **Outage** — no document can be verified |
| `EMPTY` | No certificates at all | **Outage** — the service must not report ready |

**Alert at 90 days.** That is enough time to obtain a replacement, verify its
fingerprint, get the change reviewed, and deploy — without anyone rushing a
change to the root of trust.

Step 7 wires `TrustStoreHealth.is_ready` into the `/ready` probe, so a service
with an unusable trust store will not receive traffic.

---

## Why this directory is empty right now

No certificate is committed here yet. Until you add one, `avs certs status`
reports `EMPTY` and every verification fails.

**That is correct behaviour.** No trust anchor, no approval — the system fails
closed, never open.
