# Deleting Footprints Using AI

A consent-based digital-footprint discovery, analysis, and remediation prototype with a locally hosted web interface. The system brings together public-source discovery, optional exposure checks, local browser privacy analysis, AI-assisted interpretation, human verification, and remediation tracking.

The application is intended for academic research and supervised personal privacy assessments. It does not claim to erase all online information automatically.

## Project workflow

```text
Phase 1: Identity inputs and consent
          |
          v
Phase 2: Evidence collection
         |-- 2A: Public web, GitHub, YouTube, and optional visual discovery
         |-- 2B: Authorised breach checks and data-broker review
         `-- 2C: Local browser privacy metadata audit
          |
          v
Phase 3: AI analysis, identity verification, and action recommendations
          |
          v
Phase 4: Approved remediation, evidence tracking, and re-scan verification
```

### Phase 1 — Identity and consent

An identity profile is provided using a full name, with optional email address, public username, telephone number, and context terms. Breach lookup, local browser audit, and reference-image matching require separate consent. The interface provides a cache-only mode for repeating a scan without live network queries.

### Phase 2 — Footprint discovery

- **Public sources (2A):** Searches publicly indexed pages, YouTube, and GitHub; extracts relevant webpage or PDF text; checks identity evidence; and records source URLs and match context. A local SQLite cache reduces repeated API queries.
- **Exposure checks (2B):** Performs authorised email breach lookups through configured providers and reviews potential data-broker findings. It does not retrieve breach passwords or access other accounts.
- **Local browser audit (2C):** Reviews supported Chrome, Edge, and Brave profile metadata on Windows, including tracking-related cookie metadata, site permissions, and aggregated history domains. It does not decrypt cookie values or collect saved passwords.
- **Optional visual discovery:** Uses a local reference photograph and dlib models to compare faces in accessible public images. Independent image discovery requires a Tavily API key. Candidate images are subject to human review.

### Phase 3 — Analysis and verification

The analysis layer uses an OpenAI model to classify findings, assess risk, and recommend actions. Uncertain identity matches can be verified as **Yes**, **No**, or **Unsure** before they are treated as belonging to the subject. Explicit rejection or uncertainty is not overridden by an earlier visual or automated match.

Accepted, subject-linked public evidence can also provide an organization/role association summary. The current interface displays **up to three association rows** and retains supporting source evidence rather than inferring employment from unrelated page content.

### Phase 4 — Remediation and follow-up

Actions are reviewed and recorded before execution. Supported workflows include manual privacy or account changes, assisted data-broker removal requests, optional Gmail-sent requests through OAuth 2.0, selective local tracker-cookie cleanup with confirmation and backup, and before/after re-scan verification.

Password changes, MFA setup, and account deletion remain actions performed through the relevant external services. A historical breach listing is not treated as removed simply because a password was changed.

## System requirements

- Python **3.10 or newer** (a current supported Python installation is recommended)
- Windows for the local Chrome/Edge/Brave profile audit and tracker-cookie cleanup
- Network access and appropriate service credentials for live searches and AI analysis
- A modern browser for the local Flask interface
- Optional: a compatible `dlib-bin` installation for reference-image matching

Other modules can be used without enabling the Windows-only local browser audit or the optional visual-matching feature.

## Installation

In PowerShell, open the extracted repository directory and create a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

For optional visual identity matching:

```powershell
python -m pip install -r requirements_visual.txt
```

The optional dlib model weights are not included in this source-only archive. Download them from the official [dlib-models repository](https://github.com/davisking/dlib-models), decompress them, and place them in `models/`:

- `shape_predictor_5_face_landmarks.dat`
- `dlib_face_recognition_resnet_model_v1.dat`

Visual-model installation may depend on Python version and platform-specific binary availability.

## Local configuration

Create the local environment file from the example:

```powershell
Copy-Item .env.example .env
```

Set the required service credentials in `.env` before running corresponding features:

| Variable | Purpose |
| --- | --- |
| `BRAVE_SEARCH_API_KEY` or `TAVILY_API_KEY` | Live public-web search in Phase 2A |
| `WEB_SEARCH_PROVIDER` | `auto`, `brave`, or `tavily` provider selection |
| `OPENAI_API_KEY` | Phase 3 AI interpretation |
| `YOUTUBE_API_KEY` | Optional YouTube search |
| `GITHUB_TOKEN` | Optional GitHub API access |
| `TAVILY_API_KEY` | Also required for independent visual image discovery |
| `HIBP_API_KEY` | Optional Have I Been Pwned lookup when enabled |
| `FLASK_SECRET_KEY` | Persistent local Flask session signing key |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Optional Gmail OAuth integration for Phase 4 |

The default breach provider is XposedOrNot; additional settings are documented in `.env.example`. Third-party API availability, quotas, and results are outside the application's control.

**Do not publish `.env`, OAuth tokens, raw reports, search caches, reference photos, or browser databases.** The supplied `.gitignore` excludes local runtime output and common credential files.

## Run the application

```powershell
python web_app.py
```

Open `http://127.0.0.1:5000` in a local browser, then proceed through the four phases. The included Flask server is for **local development and demonstration only**, not public internet deployment.

For a command-line Phase 2 collection instead of the web interface:

```powershell
python run_all.py
```

Other available commands:

```powershell
python run_all.py --cache-only
python run_phase4.py init
python run_phase4.py list
python repair_phase3_associations.py
```

The association repair command is preview-only unless `--apply` is explicitly supplied. It is intended for rebuilding an existing saved Phase 3 association panel without repeating a discovery scan. Inspect the reported source and decision audit before applying changes.

### Optional Gmail OAuth setup

To send an approved broker-removal request through Gmail:

1. Enable the Gmail API in a Google Cloud project and configure the OAuth consent screen.
2. Create an OAuth client of type **Web application**.
3. Register the redirect URI `http://localhost:5000/phase4/mail/callback`.
4. Set the client ID and client secret in the local `.env` file.
5. In Phase 4, connect the same Gmail account used in the Phase 1 identity profile and separately approve the specific message before sending.

The implementation uses the Gmail `gmail.send` scope and OpenID/email identity scopes. It does not require a Gmail password or mailbox-wide read access. For unsupported mail providers, the request remains a manual send-and-confirm workflow.

## Repository layout

| Path | Responsibility |
| --- | --- |
| `web_app.py` | Flask application and Phase 1–4 user interface routes |
| `templates/`, `static/` | Web templates, styles, and interface scripts |
| `run_all.py` | Phase 2 orchestration and aggregate report creation |
| `phase2_core_v4.py` | Search, identity matching, retrieval, and caching utilities |
| `phase2A_public.py`, `phase2B_exposure.py`, `phase2C_passive.py` | Public, exposure, and local-audit modules |
| `visual_identity.py`, `models/` | Optional image discovery and face comparison |
| `phase3_ai_analyzer.py`, `run_phase3.py` | AI analysis, verification, and action planning |
| `phase3_associations.py`, `repair_phase3_associations.py` | Source-bound association extraction and repair |
| `phase4_remediation.py`, `phase4_mail.py`, `phase4_verification.py` | Remediation, approved email handling, and re-scan comparison |
| `run_phase4.py` | Optional Phase 4 command-line utilities |
| `test_*.py` | Test and validation scripts |
| `reports/` | Runtime-created output; excluded from version control |

## Validation

Run the offline unit tests without performing live searches or sending email:

```powershell
python -m unittest -v test_phase2_parallel.py test_phase3_association_guard.py test_phase3_association_recall.py test_latest_discovery_status.py test_phase4_remediation.py test_phase4_completion.py
```

`test_phase3_llm.py` is a separate manual AI integration script. It requires an API key and may issue a paid network request; it is not included in the offline test command.

## Data handling and limitations

- Searches may miss profiles, private pages, unindexed content, and sites that block access. An absence of results does not establish an absence of digital footprints.
- Human confirmation is required where identity evidence is ambiguous. Organization and role extraction is evidence-based but not exhaustive, and neither search results nor face similarity are infallible identity proof.
- Internal aggregate reports may contain identity inputs and sensitive evidence. Even files labelled *shareable* should be inspected before disclosure.
- Reference photographs are processed locally during the scan. Public candidate images and reports may be cached locally for review; the reference image and face descriptor are not intentionally persisted in the reports.
- Local browser cleanup is selective, requires approval and confirmation, and creates a backup. It is not a general browser-history eraser.
- Removal requests depend on service policies and external processing. Verification records what can be observed in subsequent scans; it does not guarantee permanent removal from the internet.
- Use the system only for the individual's own data or with appropriate authorization and observe applicable service terms and privacy requirements.

## Third-party model attribution

The included pretrained facial landmark and face recognition weights originate from the [dlib-models repository](https://github.com/davisking/dlib-models). The upstream author describes these model files as released to the public domain. Model weights are third-party research assets; their inclusion does not imply that the rest of this repository is offered under the same terms.
