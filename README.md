# PyDrip — Cryptographic File Integrity & AI Investigation Engine

An evidence-driven, deterministic forensic investigation platform combining cryptographic integrity verification (SHA-256), multi-vector diff detection, local semantic intent analysis, and auditable risk scoring into forensic incident reports.

---

## Architecture Overview

The system follows a strict 5-stage unidirectional analytical pipeline designed for zero-trust forensic environments:

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ STAGE 1: CORE FILE INTEGRITY ENGINE                         │
 │ SHA-256 cryptographic verification against trusted baseline │
 └──────────────────────────────┬──────────────────────────────┘
                                │ Hash Mismatch / Status
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ STAGE 2: INVESTIGATION & DETECTION ENGINE                   │
 │ Metadata (mtime, size), Content diff, Structure (JSON/XML)  │
 └──────────────────────────────┬──────────────────────────────┘
                                │ Physical Evidence
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ STAGE 3: AI SEMANTIC ANALYSIS & INTENT DRIFT                │
 │ SentenceTransformer dense embeddings + Sequence Fallback    │
 └──────────────────────────────┬──────────────────────────────┘
                                │ Semantic Meaning & Drift
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ STAGE 4: SEVERITY & RISK ENGINE                             │
 │ 4-Factor normalized scoring model (Integrity, Semantic,     │
 │ Content mutation, Metadata/Structure)                       │
 └──────────────────────────────┬──────────────────────────────┘
                                │ Risk & Severity
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ STAGE 5: INCIDENT REPORT GENERATOR                          │
 │ Auditable evidence ledger, provenance tags, recommendations │
 └──────────────────────────────┬──────────────────────────────┘
                                │ Authoritative Report
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ STAGE 6: STREAMLIT FORENSIC DASHBOARD                       │
 │ Operator UI with IBM Plex Sans/Mono, dark technical theme   │
 └─────────────────────────────────────────────────────────────┘
```

### Analytical Responsibilities by Stage

| Stage | Question Answered | Technology / Implementation |
| :--- | :--- | :--- |
| **Stage 1** | *Did it change?* | SHA-256 hashing, chunked 64KB reads, `BaselineStore` abstraction |
| **Stage 2** | *What changed?* | Deterministic unified diff, JSON/XML parsing, metadata extraction |
| **Stage 3** | *What does the change mean?* | `all-MiniLM-L6-v2` dense embedding cosine similarity, deterministic `difflib.SequenceMatcher` fallback |
| **Stage 4** | *How risky is the change?* | 4-Factor weighted model ($0.40$ Integrity + $0.30$ Semantic + $0.15$ Content + $0.15$ Metadata/Structure) |
| **Stage 5** | *How is the incident reported?* | Auditable JSON ledger, explicit provenance markers (`[CRYPTOGRAPHIC]`, `[CONTENT]`, `[SEMANTIC]`, `[RISK]`), actionable recommendations |
| **Stage 6** | *How does an operator interact?* | Streamlit forensic console, SVG risk gauge, dark technical theme (IBM Plex Sans/Mono) |

---

## Core Guarantees & Constraints

1. **Strict Backend Authority**: The frontend never computes SHA-256 hashes, diffs, semantic drift, or risk scores. All analytical outputs originate from verified backend engines.
2. **Deterministic Fallback (Zero-Crash Guarantee)**: If GPU out-of-memory, network timeout, or model failure occurs, the pipeline automatically transitions (`PENDING -> ANALYZING -> FALLBACK -> AVAILABLE`) without crashing.
3. **No Ungrounded Claims**: The engine never attributes changes to "malware", "hackers", or "adversaries" without direct forensic proof. A cryptographic hash mismatch proves baseline divergence, which is an integrity change indicator, not standalone proof of authorization.
4. **Distinction of Null vs. Zero**: Zero drift ($0.00$) indicates identical semantic meaning; unavailable or skipped analysis is explicitly recorded as `NOT_REQUIRED` or `UNAVAILABLE`.

---

## Installation & Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.12)
- Virtual environment recommended

### 1. Clone and Install Dependencies
```bash
git clone <repo-url>
cd ai-investigation-engine

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

---

## Running the Application

### Option A: Start the FastAPI Backend
```bash
python main.py
```
- API Server listens on `http://0.0.0.0:8000`
- Interactive OpenAPI docs: `http://127.0.0.1:8000/docs`

### Option B: Launch the Streamlit Forensic Dashboard
```bash
streamlit run streamlit_app.py
```
- Opens the operator console in your browser (`http://localhost:8501`).
- Connects directly to the backend engines for live analysis, evidence inspection, and report export.

### Option C: Run the Live Hackathon Demo Script
```bash
python demo_incident.py
```
- Creates a temporary monitored environment with simulated Linux configuration files (`nginx.conf`, `sudoers`).
- Establishes cryptographic baselines, injects privilege escalation tampering, runs the full 5-stage pipeline, displays the auditable report, and demonstrates fallback resilience.

---

## Running the Test Suite

The test suite covers unit tests, regression tests, edge cases, and end-to-end integration scenarios across all stages:

```bash
# Run all 64 consolidated tests
python -m unittest discover -s . -p "test_*.py"

# Run specific test suites
python -m unittest test_core_integrity.py        # Stage 1 tests
python -m unittest test_investigation_engine.py  # Stage 2 tests
python -m unittest test_semantic_analysis.py     # Stage 3 tests
python -m unittest test_risk_engine.py           # Stage 4 tests
python -m unittest test_report_generator.py      # Stage 5 tests
python -m unittest test_e2e.py                   # Stage 7 E2E scenarios A-K
```

---

## API Reference

### 1. `POST /core/baseline`
Establishes a SHA-256 cryptographic baseline for a file.
```json
// Request
{
  "file_path": "/etc/nginx/nginx.conf"
}

// Response
{
  "file": {
    "name": "nginx.conf",
    "path": "/etc/nginx/nginx.conf",
    "type": ".conf",
    "size": 1024,
    "sha256": "ad1382e44770193520a9f8d75b0dae149d33a0219de1143f15cef60fc412b402"
  },
  "baseline_hash": "ad1382e44770193520a9f8d75b0dae149d33a0219de1143f15cef60fc412b402",
  "current_hash": "ad1382e44770193520a9f8d75b0dae149d33a0219de1143f15cef60fc412b402",
  "integrity_status": "UNCHANGED"
}
```

### 2. `POST /core/check`
Verifies current file hash against the stored baseline.

### 3. `POST /investigate`
Executes the full forensic investigation pipeline on a batch of file changes.
```json
// Request
{
  "input_data": {
    "scan_id": "SCAN-2026-001",
    "changes": [
      {
        "file_path": "/etc/sudoers",
        "change_type": "MODIFIED",
        "old_hash": "44db490ebcb70e2551130cbab20bab8e9dcf7fce5ed8a68a7c639dfed9ab814f",
        "new_hash": "3d6efd564e0b39df447814b10507efbc359c402120e2ef63a15c3272d5469493",
        "criticality": "Critical",
        "evidence": []
      }
    ]
  },
  "file_contents_map": {
    "/etc/sudoers": {
      "old": "%developers ALL=(ALL) /bin/systemctl restart app\n",
      "new": "%developers ALL=(ALL) NOPASSWD: ALL\n"
    }
  }
}
```
