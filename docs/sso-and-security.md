# Selective SSO, Organization Security & Observability

PsiTransfer supports **Selective Single Sign-On (SSO)** and **Organization-Level Access Control**, allowing users to perform standard public file uploads or enforce SSO authorization for sensitive organizational file transfers.

---

## 🔒 1. Selective SSO Architecture

### Zero-Disruption Default Mode
When SSO is enabled (`ssoEnabled: true`), PsiTransfer operates in a hybrid selective security mode:
- **Standard Transfer**: Uploads remain password-protected or publicly accessible without requiring SSO authentication.
- **Secure Organization Transfer**: Uploads associated with a target Organization require downloaders to authenticate via SSO. Downloads are granted only if the user's SSO claim domain matches the target Organization domain.

---

## 🎛️ 2. Admin SSO Management UI (`/admin`)

The Admin Panel (`/admin`) includes a tabbed interface for managing file buckets and Organization SSO configurations:

### Configuration Parameters per Organization:
- **Domain**: The target domain (e.g. `company.com` or `banco.com.br`) validated against RFC 1035 format.
- **Organization Name**: Friendly name displayed on login pages and download prompts.
- **Require SSO**: Checkbox toggle to enforce mandatory SSO for all downloads destined to this Organization.
- **OIDC Issuer URL**: OpenID Connect Issuer URL (e.g., `https://auth.company.com/realms/master`).
- **Client ID & Client Secret**: OAuth2 / OIDC credentials for IDP authentication.

### Admin APIs:
- `GET /admin/sso-orgs.json` — Lists all registered Organizations (requires `x-passwd` header).
- `POST /admin/sso-orgs.json` — Adds or updates Organization SSO configurations.
- `DELETE /admin/sso-orgs/:domain` — Deletes Organization SSO configuration.

---

## 📤 3. Upload Page Organization Selector

On the Upload page (`/`), users can select the **Transfer Security Mode**:
1. **Standard Transfer (Public / Password Only)** — Default PsiTransfer behavior.
2. **Secure Organization Transfer (SSO Required)** — Select target Organization from a dropdown list. TUS metadata automatically tags the bucket with `org` and `ssoEnforced: "true"`.

---

## 📊 4. Prometheus Metrics Endpoint (`GET /metrics`)

PsiTransfer exposes application metrics for Prometheus scraping in standard format at `GET /metrics`:

```text
# HELP psitransfer_uptime_seconds Total application uptime in seconds
# TYPE psitransfer_uptime_seconds counter
psitransfer_uptime_seconds 3600

# HELP psitransfer_active_buckets_total Total number of active transfer buckets
# TYPE psitransfer_active_buckets_total gauge
psitransfer_active_buckets_total 5

# HELP psitransfer_files_total Total number of stored files
# TYPE psitransfer_files_total gauge
psitransfer_files_total 12

# HELP psitransfer_storage_bytes_total Total size of stored files in bytes
# TYPE psitransfer_storage_bytes_total gauge
psitransfer_storage_bytes_total 104857600
```

---

## 🛡️ 5. Security & Secret Governance

- **Cookie Security**: `psitransfer_sso` cookies are set with `HttpOnly`, `SameSite=Lax`, and dynamic `Secure: true` when running behind HTTPS or SSL.
- **Secret Hardening**: Logs a security warning if the default `ssoSecret` key is detected in production.
- **Domain Validation**: Rejects malformed domain strings on Admin endpoints.
- **Timing-Safe Password Validation**: Utilizes `timingSafeEqual()` for password comparisons to prevent timing attacks.
