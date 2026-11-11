# RepoGuard AI — SIH26155

A local, read-only prototype for network-device configuration compliance auditing. This project is specifically about network configuration security, not software dependency scanning. It does not connect to devices, execute uploaded commands, or send configuration data to an external service.

## Run locally

Requirements: Python 3.10+ and Node.js 20+.

```sh
cd backend
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload
```

In a second terminal:

```sh
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. FastAPI docs are at http://localhost:8000/docs. Local audit history and approved mappings are stored in `backend/repoguard.db` (SQLite).

## Container deployment

Docker Compose runs the frontend and API together, keeps SQLite data in a named volume, and binds the site to localhost only:

```sh
docker compose up --build -d
```

Open http://localhost:8080. Stop with `docker compose down`; audit data remains in the `repoguard-data` volume. To remove the stored audit data too, run `docker compose down --volumes`.

This prototype has no user authentication, so Compose deliberately binds only to `127.0.0.1`. For a remote demo, use a trusted VPN or SSH tunnel to that host. Do not expose port 8080 directly to the public internet. A public or multi-user deployment needs authentication/authorization, TLS termination, protected backups and storage, secret/config redaction, rate limits, and an operational review before opening network access. No public cloud deployment has been performed.

## Demo workflow

1. Start backend and frontend as above.
2. Upload the three synthetic files from `samples/` together.
3. Open Audits and inspect device, framework, evidence line, status, and remediation.
4. Download a per-device PDF report.
5. Open a device's unrecognized lines; select one, map it to a supported security field, and confirm approval. Re-upload the sample to see how approved mappings are applied.
6. Explain that “Not Evaluated” means missing recognized evidence, never a pass. Framework coverage is intentionally a small demonstration set, not full certification.

## Supported prototype checks

A small set of deterministic checks is implemented in `backend/app.py` for CIS-style SSHv2 and HTTP-management checks, NIST SP 800-53 remote access and audit logging concepts, a generic administrative idle-timeout STIG-style check, and an ISO/IEC 27001 password protection concept. The IDs are prototype references and are not represented as authoritative benchmark mappings or complete framework coverage. Validate control applicability and exact framework mappings with a qualified assessor before production use.

The current parser recognizes a small syntax subset for Cisco IOS, Fortinet FortiOS and Juniper Junos. It preserves line-level evidence for recognized settings. Unrecognized configuration remains visible for review. Inputs are UTF-8 `.txt`, `.cfg`, or `.conf` up to 1 MB each. Do not upload production configurations or secrets to this demonstration.

## Architecture and responsibilities

See [ARCHITECTURE.md](ARCHITECTURE.md) for the architecture assessment, current boundaries, and a proposed four-person task split. The legacy dependency/SBOM/OSV module, if added by the team, should remain independently packaged and surfaced separately from network configuration audits.

## API

- `POST /api/audits` multipart `files` (one or many)
- `GET /api/audits`, `GET /api/dashboard`
- `POST /api/mappings` requires `confirmed: true`
- `GET /api/reports/{audit_id}.pdf`
- `GET /api/health`

Mappings use administrator-provided regular expressions and typed normalized values. This prototype has no authentication; bind it to localhost and do not expose it to a network.
