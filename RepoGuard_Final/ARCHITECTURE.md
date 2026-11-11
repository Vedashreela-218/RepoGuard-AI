# RepoGuard AI — architecture and assessment

## Assessment and boundaries

The supplied workspace was empty. There was no frontend, backend, dependency scanner, or existing team module to preserve. The SIH26155 statement calls for multi-vendor network configuration normalization, adaptation to unfamiliar syntax through an administrator training loop, selected-framework compliance checks, and actionable per-device PDF reporting. This prototype addresses those flows without network-device access. A dependency/SBOM/OSV scanner is a separate concern and should remain a separate module if introduced; it does not establish network configuration compliance.

## Data flow

```text
React dashboard → FastAPI upload/validation → vendor identification → vendor parsers
     ↑                                                       ↓
 audit history/PDF ← SQLite findings ← normalized security model ← approved mappings
```

The normalized model contains SSH version, Telnet and HTTP management state, logging, password-encryption signal, and administrative timeout. Parsers retain source line and evidence. Unknown lines enter the training queue. A mapping is only stored after the administrator checks confirmation; approved mappings are applied on subsequent uploads. Rule evaluation returns Pass, Fail, or Not Evaluated; the dashboard and report exclude Not Evaluated controls from the compliance percentage. The engine and mapping are local and deterministic; there is no LLM or external API.

## Modules and extension points

- `backend/app.py`: ingestion API, extension-limited Cisco/Fortinet/Juniper parsers, vendor identification, normalization, rules, SQLite audit history, mapping approval, and ReportLab PDFs. Separate these into `ingestion`, `parsers`, `normalization`, `rules`, `training`, `history`, and `reporting` packages as the prototype grows.
- `frontend/src/main.tsx`: React dashboard, audit/finding details, upload, report links, and mapping workflow.
- `samples/`: synthetic CLI examples with documentation-only IP addresses.

Rule metadata is an explicit list with framework label, control reference, expected value, severity, and remediation. Add a new vendor by implementing parser output for the same model; add a framework by contributing validated rule metadata. Do not infer compliance from an unrecognized line. Store parser and rule versions in future production audit records.

## Prototype gaps

Only a narrow syntax subset and six demonstration checks are implemented. The control IDs and framework associations are illustrative references; this is not a full CIS benchmark, NIST assessment, DISA STIG, or ISO audit. Fortinet block parsing and Juniper/Cisco syntax variants need broader fixtures. The demo has no authentication, tenant isolation, encryption-at-rest, secrets redaction, or mapping audit trail. The included Compose deployment binds to localhost only. Add those controls and perform an operational review before exposing it remotely. No uploaded command is executed, and no device connection is made. PDFs include evidence and remediation but do not claim device serial/hardware attributes that the text parser cannot establish.

## Four-person delivery plan

1. **Member 1 — Backend/ingestion:** input validation, vendor detection and parser packages; add syntax fixtures; maintain safe read-only processing.
2. **Member 2 — Existing dependency module:** retain SBOM/OSV work as a separate product area; define a separate navigation/API boundary, and never merge dependency findings into network compliance totals.
3. **Member 3 — Frontend:** React dashboard, bulk upload, audit review, human-approved training, and PDF-download UX; improve responsive and accessibility coverage.
4. **Member 4 — Security/QA:** validate framework citations and applicability with authoritative benchmarks, expand synthetic tests per vendor/version, threat-model uploads and mapping regexes, and check report evidence.

## Demo

Run the backend and frontend as described in README. Upload all files in `samples/`, inspect evidence and “Not Evaluated,” download a PDF, approve a mapping for an unknown line, then re-upload. Keep the explanation clear that six sample controls are demonstrated and framework coverage is not complete.
