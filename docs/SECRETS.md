# Secrets — what to generate and where each one goes

**There is nothing to hand over.** No secret exists yet. They are generated at
deployment, by whoever deploys, and the same value is set on both sides.

⛔ **Never send a secret over chat, email, Slack or a ticket.** Whoever runs the
deployment should generate it directly into the secret store — a Kubernetes
Secret, AWS Secrets Manager, a `.env` on the server, whatever you already use.
If a secret has ever appeared in a message, treat it as compromised and
regenerate it. Rotating is cheap; a leaked signing key is not.

---

## Generate three values

Run this three times. Each output is 64 hex characters.

```bash
openssl rand -hex 32
```

On Windows without openssl:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Where each one goes

### 1. Tenant secret — the HRM proves it is the HRM

The HRM signs every request to AVS with it. AVS checks the signature.

| Side | Setting | Notes |
|---|---|---|
| **AVS** | env var `AVS_TENANT_M_ONE_PROD_SECRET` | the NAME comes from `secret_env` in `tenants.json` |
| **Next.js** | env var `AVS_SECRET` | ⛔ **never** `NEXT_PUBLIC_AVS_SECRET` — that prefix compiles it into the browser bundle |

`tenants.json` holds only the tenant id and the **name** of the environment
variable — never the secret itself. That is why the file is safe to commit and
to put in a ConfigMap:

```json
{
  "tenants": [
    {
      "tenant_id": "m-one-prod",
      "name": "M-One HRM production",
      "secret_env": "AVS_TENANT_M_ONE_PROD_SECRET",
      "strictness": "STANDARD"
    }
  ]
}
```

The HRM also needs `avs.tenant-id: m-one-prod` — this must match `tenant_id`
exactly, and it is an identifier, not a secret.

### 2. Callback secret — NOT NEEDED TODAY

⚠ **Skip this one.** The Next.js integration polls for the result rather than
receiving a callback, so no callback endpoint exists and `callback_url` is never
sent. Generating a secret for a feature nothing uses just creates one more thing
to rotate and leak.

Only if you later add a callback receiver:

| Side | Setting |
|---|---|
| **AVS** | env var `AVS_CALLBACK_SECRET` |
| **Receiver** | whatever you name it |

⛔ It would then be the most security-critical value in the integration. A
callback endpoint is reachable from wherever AVS runs; if it accepted an
unsigned body, anyone able to reach that URL could POST `{"verdict":"VERIFIED"}`
and approve a forged Aadhaar — bypassing the RSA check, the pinned trust store
and the audit trail in a single request. Verify the HMAC over the raw body,
before parsing.

### 3. Hash secret — AVS only, not shared

| Side | Setting |
|---|---|
| **AVS** | env var `AVS_HASH_SECRET` |
| **HRM** | *nothing — do not set it* |

Salts the HMAC of the Aadhaar reference id, so what gets stored is not
reversible to a number.

⚠ **It must be stable across restarts and across every AVS instance.** If it
changes, every reference hash changes, and duplicate detection silently stops
matching anything — with no error, because nothing is technically wrong.

---

## Summary

**Two secrets, not three.**

| Value | AVS | Next.js | Must match? |
|---|---|---|---|
| Tenant secret | `AVS_TENANT_M_ONE_PROD_SECRET` | `AVS_SECRET` | ✅ yes |
| Hash secret | `AVS_HASH_SECRET` | — | AVS only, must be stable |
| Tenant id | `tenants.json` | `AVS_TENANT_ID` | ✅ yes, not secret |
| Callback secret | — | — | ⚠ not used; polling instead |

Plus `HRM_DATABASE_URL` on the Next.js side, where approved verifications are
recorded. Not an AVS secret, but it belongs in the same store.

---

## Both sides refuse weak secrets, deliberately

Under 32 characters, or containing `changeme` / `secret` / `placeholder`, and
the service will not start. Java:

```
avs.secret is only 12 characters; minimum is 32.
Generate one with: openssl rand -hex 32
```

A service that silently starts with `changeme` as a signing key is worse than
one that refuses to start, because nothing looks wrong until it is exploited.

---

## How to tell it worked

**Right:** submissions return 202 with a `jobId`.

**Tenant secret wrong:** every request returns **401**. Looks like a network
problem; it is not. The AVS log says which:

```json
{"event": "request_rejected", "reason": "signature mismatch", "tenant": "m-one-prod"}
```

**Callback secret wrong:** submissions succeed but verdicts never arrive. The
HRM's polling still works, so it looks like slowness rather than a failure.
Check the HRM log for a rejected callback.

⚠ The signature covers the **raw request body**. `lib/avsSignature.ts` builds its
multipart body by hand for exactly this reason — any library that regenerates it
with a different boundary or header order produces bytes that no longer match,
and the symptom is an unexplained 401 with correct-looking secrets. Measured:
a `FormData` body returns 401 where the identical hand-built buffer returns 202.

---

## Before going live

```powershell
python -m avs.cli certs pin --dir certs
python scripts\preflight.py --url https://<the deployed AVS>
```

`preflight` reports `auth_required`, `tenants` and `pinning_enabled`, and
refuses to give a clean bill of health while any of them is wrong.
