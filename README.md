# Smriti Nexus

**Remember the Why. Preserve the How. Empower the Next.**

Smriti Nexus is a React/Vite institutional-memory interface with a FastAPI backend. The workspace keeps its existing dark-green design and memory explorer, relationship graph, evidence previews, correction review, handovers, audit export, and demo retrieval experience.

## Current architecture and security status

- Frontend: React 19 and Vite. The production API origin is configured with `VITE_API_URL`.
- Backend: Python 3.11+ and FastAPI.
- Database: MongoDB via PyMongo; set `MONGODB_URI` to a TLS-enabled MongoDB Atlas connection. Data access is organization-scoped in backend queries.
- Authentication: normal/production mode uses email/password with Argon2id hashing, short-lived signed bearer tokens, server-side revocable sessions, login lockout, and Admin/Manager/Employee membership roles. A temporary loopback-only demo mode is available for local development without sign-in.
- AI: the existing assistant is a local keyword-retrieval demo. **No external LLM provider is configured or called.** A backend privacy policy service detects/redacts common credential and identifier patterns, minimizes context, and blocks `TOP_SECRET` context. `/api/privacy/preview` lets an authenticated caller inspect the decision; no prompt or evidence is sent to a provider.
- Encryption: the backend supports envelope encryption for `CONFIDENTIAL` and `TOP_SECRET` memory/correction content. For free local development, `KMS_PROVIDER=local` uses a random AES-256 data key per content value and wraps it with an AES-GCM key derived from `LOCAL_MASTER_KEY`. The master key is read only from the backend environment and is never stored in MongoDB or source. This is a **local development key, not a key vault**; it is not accepted in production. Production requires the optional Google Cloud KMS provider and uses Application Default Credentials. Neither local development encryption nor Google Cloud KMS encrypts titles/tags or other metadata.
- This project has not been deployed. A public HTTPS URL requires deployment and production environment variables described below.

## Local setup

To run the local demo without signing in or connecting to Atlas, start the backend in demo mode. Demo data is held in memory and cleared whenever the backend stops:

```powershell
cd backend
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
$env:ENVIRONMENT = "development"
$env:DEMO_MODE = "true"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

The frontend development server skips login by default and connects to this API. Demo mode ignores any configured MongoDB URI, uses only an ephemeral local mock database, and is restricted to requests from this computer. Never expose the demo backend to a network.

To encrypt local confidential memories, generate a separate master key and put it in `backend\.env` (do not paste it into source code or commit it):

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set `KMS_PROVIDER=local` and `LOCAL_MASTER_KEY=<generated-value>` in `backend\.env`, then restart the backend. Keep that same key safe: losing or changing it makes existing locally encrypted content unreadable. The Security & Audit dashboard labels this mode **Local development key**. This option is not suitable for public deployment or sensitive production data.

Set up and start the frontend in a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL printed in the terminal. Local Vite development skips the login screen by default; set `VITE_DEMO_MODE=false` to show it again. With backend `DEMO_MODE=true`, requests from the same computer enter a seeded `Local Demo Workspace` as an Admin. This mode is intended only for local demonstrations, not shared or public use.

For persistent data and normal authentication, create `backend\.env` from `backend\.env.example`, configure a MongoDB URI, database name, JWT secret, audit key, and exact local frontend origins, then set `DEMO_MODE=false`. Set frontend `VITE_DEMO_MODE=false` to restore login. Sign-up creates a separate organization and never joins an existing one. An organization Admin can issue a one-time invitation from the protected API; an invited person sets their own password when accepting it.

## Roles

| Role | Access |
| --- | --- |
| Admin | Read and modify workspace memories, review corrections, manage members, and access audit/security data |
| Manager | Read, create and update memories, review corrections, and view workspace audit data |
| Employee | Read memories, create unverified/disputed memories, ask the local demo assistant, and submit corrections |

All protected API routes verify the session and membership on the backend. Object lookups and searches include the authenticated organization ID. Frontend controls are not treated as an authorization boundary.
The backend refuses to start in production if `DEMO_MODE=true`; the frontend also enables the login bypass only in Vite development builds.

## Environment variables

### Backend

| Variable | Purpose |
| --- | --- |
| `ENVIRONMENT` | Use `production` on the hosted backend; production startup requires secrets and MongoDB configuration |
| `DEMO_MODE` | Set `true` only for local development without sign-in; grants local loopback callers Admin access and is rejected in production |
| `MONGODB_URI` | Private Atlas URI; use a least-privilege database user and TLS |
| `MONGODB_DATABASE` | Database name (default `smriti_nexus`) |
| `JWT_SECRET` | Random signing secret, at least 32 bytes; keep in the backend host's secret manager |
| `AUDIT_SIGNING_KEY` | Separate random key for audit hash-chain signing |
| `ALLOWED_ORIGINS` | Comma-separated exact HTTPS Vercel frontend origins, no wildcard |
| `KMS_PROVIDER` | Set to `local` for local development or `google-cloud-kms` in production |
| `LOCAL_MASTER_KEY` | Random local-only key of at least 32 bytes; keep in the backend `.env`, never commit or use in production |
| `GCP_KMS_KEY_NAME` | Full symmetric CryptoKey resource, e.g. `projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY` |
| `SEARCH_INDEX_KEY` | Independent random 32+ byte secret used to HMAC-index terms when using Google Cloud KMS; store in the host secret manager, not in MongoDB. Local mode derives its index key from `LOCAL_MASTER_KEY`. |

Generate independent backend secrets locally:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Generate a separate random `LOCAL_MASTER_KEY` only for local development. Never reuse the JWT or audit key, and never use this development-only key in production:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### Google Cloud KMS production setup

1. In Google Cloud, enable the Cloud Key Management Service API and create a **symmetric encrypt/decrypt** CryptoKey. Keep the CryptoKey in a supported location and configure its rotation policy in Google Cloud.
2. Give the backend runtime identity only the `roles/cloudkms.cryptoKeyEncrypterDecrypter` permission on that specific CryptoKey. On Google Cloud, attach a dedicated service account to the backend and use ADC; do not download or commit service-account JSON keys. For hosting outside Google Cloud, use Workload Identity Federation rather than a long-lived service-account key.
3. Configure backend secrets: `ENVIRONMENT=production`, `KMS_PROVIDER=google-cloud-kms`, `GCP_KMS_KEY_NAME` with the full CryptoKey resource, and a distinct random `SEARCH_INDEX_KEY` of at least 32 bytes, along with the existing MongoDB/auth/CORS settings. Do not set `LOCAL_MASTER_KEY`.
4. Run a deployment smoke test that writes and reads a `CONFIDENTIAL` record, confirms MongoDB stores an envelope rather than plaintext content, and checks Cloud KMS audit logs. The Security dashboard reports configuration, not successful KMS connectivity.

Google Cloud KMS is not enabled or provisioned by this code change; no project, CryptoKey, IAM binding, credentials, or billing resources were supplied. Production startup rejects configurations that do not select Google Cloud KMS, but actual KMS permissions and network access must be verified in the deployment. KMS requests incur provider usage/costs according to the selected Google Cloud pricing and quota. Do not switch CryptoKeys or revoke access to an old key until all data wrapped by it has been rewrapped and verified.

### Frontend

| Variable | Purpose |
| --- | --- |
| `VITE_API_URL` | Public HTTPS base URL of the deployed FastAPI service; this value is public and must not contain secrets |
| `VITE_DEMO_MODE` | Set `false` to show login while using the Vite development server; production builds always require login |

## Deployment outline (Vercel + Render + MongoDB Atlas)

1. Create an Atlas database user with access only to the Smriti Nexus database. Restrict Atlas Network Access to the Render service's outbound IPs when available; avoid a global `0.0.0.0/0` allow rule for sensitive data.
2. Deploy `backend` as a Python web service on Render. Build/install command: `pip install -r requirements.txt`; start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`. Configure `ENVIRONMENT=production`, `MONGODB_URI`, `MONGODB_DATABASE`, `JWT_SECRET`, `AUDIT_SIGNING_KEY`, and `ALLOWED_ORIGINS` in Render's environment/secret settings. Use the exact Vercel domain (and any explicitly approved preview domain) for `ALLOWED_ORIGINS`.
3. Deploy `frontend` on Vercel with root directory `frontend`, build command `npm run build`, output directory `dist`, and `VITE_API_URL` set to the Render HTTPS service URL. Rebuild after changing this variable.
4. Verify `/api/health`, signup/login, cross-organization access denial, correction review, and the privacy preview over HTTPS before inviting real users.
5. Set a backup/restore policy in Atlas and keep the database URI and signing keys in host secret managers. Rotate secrets if an `.env` file has been shared.

Free tiers and startup/cloud-credit programs change over time and may sleep, limit storage/egress, or require billing details. Verify current eligibility and costs with each provider before creating resources. No cloud credits, hosting services, external AI provider, or KMS are assumed or provisioned by this project.

## Migrating an existing SQLite database

The migration script reads the existing SQLite database in read-only mode and inserts records into the selected, already-created MongoDB organization. It does not delete or modify the SQLite source. Review the data and target organization before running:

```powershell
cd backend
.\.venv\Scripts\python.exe scripts\migrate_sqlite_to_mongo.py --organization-id <organization-id>
```

Set `MONGODB_URI` and `MONGODB_DATABASE` in the backend environment first. Migration is idempotent for a given organization and memory/correction ID. Existing audit rows are not imported by this script.

## Privacy gateway behavior

The privacy module recognizes common password/secret assignments, common API-key formats, email addresses, phone-like identifiers, and common government-ID shapes. Pattern detection is heuristic and is not a substitute for a DLP service or human review. `TOP_SECRET` records are blocked from the external-provider path. The current assistant has no external provider and reports that no data was transmitted. The gateway records decision, category names, provider/model labels, and counts; it does not store the question or raw evidence in its privacy audit metadata.

Treat memory contents as untrusted data. Future LLM integrations must call the backend privacy gateway, pass only its minimized/redacted output, use fixed system instructions that cannot be overridden by retrieved memory, and must never call providers directly from the browser.

Sensitive content writes fail closed unless the selected encryption provider is configured. In production, Google Cloud KMS wraps each random AES-256 content key, and `SEARCH_INDEX_KEY` creates keyed word tokens for content search. These tokens leak word equality/frequency and are not a substitute for production searchable encryption. Losing access to the KMS key or search-index key can make encrypted content unreadable or unsearchable; back up and rotate keys using a documented, tested recovery procedure.

## Tests and build

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest
cd ..\frontend
npm run build
```

Backend tests use `mongomock`; they do not verify connectivity to a real Atlas cluster. Verify Atlas credentials, network access, TLS, backups, production CORS, and hosted HTTPS separately.

## Existing MVP limitations

- The assistant uses bounded keyword retrieval and fixed demo responses, not an LLM or semantic/vector search.
- Evidence previews show saved memory excerpts, not original uploaded files.
- Google Cloud KMS integration is implemented, but no production KMS key or cloud identity is configured or connectivity-tested in this workspace. Only memory/correction content fields are encrypted; titles and other metadata remain searchable plaintext. Email delivery and production deployment are also not configured.
- Session access tokens are short-lived and held in browser `sessionStorage`; logout revokes the server-side session. A refresh-token flow and stricter XSS protections should be added before production use with sensitive data.
