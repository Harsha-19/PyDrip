# PyDrip

<p align="center">
  <strong>AI-Augmented File Integrity Monitoring that doesn't just detect what changed — it explains why it matters.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%20%7C%203.13-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/scikit--learn-Isolation%20Forest-F7931E?style=flat-square&logo=scikitlearn&logoColor=white" alt="scikit-learn">
  <img src="https://img.shields.io/badge/SentenceTransformers-all--MiniLM--L6--v2-7B1FA2?style=flat-square" alt="SentenceTransformers">
  <img src="https://img.shields.io/badge/SQLite-ACID%20Storage-003B57?style=flat-square&logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/Tests-176%20Passed%20(100%25)-2E7D32?style=flat-square" alt="Tests Passed">
</p>

---

## Quick Navigation

[Product Overview](#product-overview) • [The Product Story](#the-product-story) • [Features](#features) • [Architecture](#architecture) • [AI & ML Pipeline](#ai--machine-learning-pipeline) • [Real-Time Security](#real-time-security-intelligence) • [Example Incident](#example-incident) • [Tech Stack](#technology-stack) • [Project Structure](#project-structure) • [API Reference](#api-reference) • [Installation & Setup](#installation--setup) • [Running PyDrip](#running-pydrip) • [Demo Walkthrough](#hackathon-demo-walkthrough) • [Testing](#testing--verification) • [Security Principles](#security-design-principles) • [Limitations](#limitations) • [Future Roadmap](#future-roadmap) • [Team](#team--responsibilities)

---

## Product Overview

Traditional File Integrity Monitoring (FIM) tools like Tripwire, OSSEC, and Samhain are foundational to enterprise compliance standards such as PCI-DSS, SOC 2, and NIST 800-53. They verify a single cryptographic fact: **a file's cryptographic hash changed**.

In modern operational environments, files change constantly:
* Automated deployment pipelines deploy code and update assets.
* System daemons write and rotate application logs.
* Configuration managers renew secrets, tokens, and certificates.

When every routine modification triggers an identical high-priority alert, Security Operations Centers (SOCs) suffer from severe **alert fatigue**. Critical threats—such as an adversary altering an authentication module, dropping a backdoor into an administrative script, or modifying database credentials—drown in routine background noise.

> [!IMPORTANT]
> **PyDrip transforms raw cryptographic diffs into prioritized, explainable security intelligence.** It combines authoritative SHA-256 verification with unsupervised behavioral anomaly detection, pretrained semantic drift analysis, deterministic severity scoring, and real-time security posture tracking to explain not just *what* changed, but *why it matters*.

---

## The Product Story

Traditional FIM systems leave the entire triage burden on human analysts. PyDrip automates the investigative reasoning chain by answering the questions an experienced security investigator asks during an incident:

```
Traditional FIM:
└── "What changed?"

PyDrip:
├── 1. "What changed?"                  ──> Cryptographic SHA-256 detection (ADDED, MODIFIED, DELETED)
├── 2. "How unusual is it?"             ──> Isolation Forest behavioral anomaly modeling (Volume, velocity, timing, clustering)
├── 3. "How different is it?"           ──> MiniLM transformer semantic drift (1.0 - cosine_similarity)
├── 4. "Why does it matter?"            ──> Deterministic severity engine & explainable evidence generation
├── 5. "Have we seen this behavior before?" ──> Historical novelty detection (First-seen files, patterns, and hashes)
├── 6. "Does it keep happening?"        ──> Recurrence frequency scoring (Differentiates routine churn from rare spikes)
├── 7. "How risky is the overall incident?" ──> Multi-signal aggregated incident risk scoring (0.0 to 1.0)
└── 8. "Should security attention be raised?" ──> Real-time security posture tracking & prioritized alerts
```

### Traditional FIM vs. PyDrip Comparison

| Investigation Dimension | Traditional FIM | PyDrip (FIM+) |
| :--- | :--- | :--- |
| **Integrity Verification** | *"What changed?"* (Raw hash diff) | **Authoritative SHA-256 verification** (`ADDED`, `DELETED`, `MODIFIED`) |
| **Behavioral Context** | *Unknown* | **Isolation Forest batch anomaly scoring** (Velocity, timing, volume, clustering) |
| **Content Difference** | *Line diff only* | **MiniLM transformer semantic drift** (`1.0 - cosine_similarity`) |
| **Risk Priority** | *Static alert* | **Deterministic severity engine** (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| **Historical Baseline** | *None* | **Historical novelty detection** (First-seen files, patterns, and hashes) |
| **Habitual Activity** | *None* | **Recurrence frequency scoring** (Differentiates routine churn from outliers) |
| **Incident Scope** | *Per-file alerts* | **Multi-signal aggregated incident risk scoring** (`0.0 – 1.0`) |
| **Operational Posture**| *Static threshold* | **Real-time security state tracking** (`NORMAL` → `CRITICAL`) |

---

## Features

### 1. File Integrity Monitoring (Core Engine)
* **SHA-256 Cryptographic Integrity:** Streaming 64KB chunked hashing verifies integrity reliably without loading large files into memory.
* **Baseline Snapshotting:** Captures clean baseline snapshots across configured paths with granular asset criticality tagging (`Critical`, `High`, `Medium`, `Low`).
* **Granular Change Classification:** Categorizes filesystem diffs into distinct `ADDED`, `DELETED`, and `MODIFIED` sets.
* **Immutable Content Snapshots:** Content-addressable snapshot store (`.fim_snapshots/<sha256>.txt`) preserves baseline text states for semantic drift evaluation.
* **Audit-Defensible History:** SQLite persistence records every scan batch with timestamps, execution metrics, and change counts.

### 2. AI-Powered Analysis
* **Isolation Forest Anomaly Detection:** Unsupervised outlier detector models batch velocity, timing, and grouping against historical baselines.
* **Behavioral Feature Engineering:** Transforms raw filesystem diffs into 4-dimensional behavioral vectors: change volume, off-hours timing, directory clustering, and change velocity.
* **MiniLM Semantic Drift Analysis:** Pretrained `all-MiniLM-L6-v2` transformer embeddings evaluate genuine semantic divergence versus cosmetic formatting adjustments.
* **Deterministic Severity Engine:** Rule-grounded state machine combines asset criticality, change type, anomaly score, and drift score into discrete severity tiers.
* **Explainable Evidence Generation:** Every scored change produces human-readable reasons explaining the anomaly, drift, criticality, and final severity.

### 3. Security Intelligence
* **Real-Time File Monitoring:** Background `Watchdog` filesystem observer with temporal debouncing (500ms – 1000ms) captures changes as they happen.
* **Per-File Anomaly Attribution:** Identifies the primary behavioral factor (velocity, off-hours, clustering, volume) driving batch suspicion.
* **Novelty Detection:** Detects first-seen files, first-seen modification patterns, and previously unobserved cryptographic hashes.
* **Recurrence Scoring:** Quantifies how frequently similar changes have appeared historically to distinguish habitual system maintenance from rare anomalies.
* **Incident-Level Risk Scoring:** Aggregates multi-file events into a unified 0.0 – 1.0 incident risk score.
* **Real-Time Security Posture & Alerts:** Dynamically classifies system security state (`NORMAL`, `WATCH`, `ELEVATED`, `HIGH`, `CRITICAL`) and dispatches structured alert payloads.

### 4. Platform & Usability
* **FastAPI Backend:** High-performance RESTful API endpoints for baselines, scans, changes, audit history, and reports.
* **SQLite Persistence:** Zero-dependency relational storage featuring idempotent migrations and an append-only audit log.
* **Streamlit Dashboard:** Interactive console with severity breakdown charts, real-time alert banners, and file-level drill-downs.
* **Investigation Reports:** Automated markdown and narrative reporting with verifiable evidence citations.

---

## Architecture

```mermaid
flowchart TD
    subgraph Filesystem ["1. Filesystem Layer"]
        Files["Monitored Target Files"]
        Snapshots[".fim_snapshots/sha256.txt"]
    end

    subgraph CoreFIM ["2. Core FIM Engine (Harsha)"]
        Watchdog["Watchdog Real-Time Observer"]
        Hasher["SHA-256 Streaming Hasher"]
        Scanner["Set Diff Scanner"]
        Baseline["Baseline Manager"]
        SQLite[("SQLite: fim.db")]
    end

    subgraph Adapter ["3. Integration Adapter Layer"]
        AdapterMod["ai_scoring/adapter.py"]
        HistBuilder["Walk-Forward History Builder"]
        PayloadPrep["Content and Payload Extractor"]
    end

    subgraph AIScoring ["4. AI/ML Scoring Layer (Rohith)"]
        Features["Feature Engineering"]
        IsoForest["Isolation Forest Anomaly"]
        MiniLM["MiniLM Semantic Drift"]
        Severity["Deterministic Severity Engine"]
        Evidence["Traceable Evidence Engine"]
    end

    subgraph Intelligence ["5. Security Intelligence Layer"]
        Attribution["Anomaly Attribution"]
        Novelty["Novelty Detection"]
        Recurrence["Recurrence Scoring"]
        IncidentRisk["Incident Risk Aggregator"]
        SecurityState["Real-Time Security Alerts"]
    end

    subgraph Presentation ["6. Presentation and Platform"]
        FastAPI["FastAPI REST Backend"]
        Dashboard["Streamlit Security Dashboard"]
        Reports["Investigation Reports"]
    end

    Files -->|"Filesystem Events"| Watchdog
    Files -->|"Read File Bytes"| Hasher
    Watchdog --> Scanner
    Baseline --> Hasher
    Hasher --> Scanner
    Baseline -.->|"Snapshot Text under 1MB"| Snapshots
    Scanner -->|"Raw Changes"| SQLite

    SQLite -->|"Raw Change Records"| AdapterMod
    Snapshots -->|"old_content"| PayloadPrep
    Files -->|"new_content"| PayloadPrep
    SQLite -->|"Historical Baseline Scans"| HistBuilder

    HistBuilder --> AdapterMod
    PayloadPrep --> AdapterMod
    AdapterMod -->|"score_changes"| Features

    Features --> IsoForest
    PayloadPrep --> MiniLM
    IsoForest --> Severity
    MiniLM --> Severity
    Severity --> Evidence

    Evidence --> Attribution
    Evidence --> Novelty
    Evidence --> Recurrence
    Novelty --> IncidentRisk
    Recurrence --> IncidentRisk
    IncidentRisk --> SecurityState

    SecurityState -->|"Persist Enriched Scores"| SQLite
    SQLite --> FastAPI
    FastAPI --> Dashboard
    FastAPI --> Reports
```

---

## AI & Machine Learning Pipeline

The AI/ML pipeline is accessed through a clean, decoupled interface:

```python
score_changes(
    change_list: list[dict],
    scan_history: list[dict]
) -> list[dict]
```

### 1. Behavioral Anomaly Detection (Isolation Forest)
Isolation Forest is employed as an **unsupervised behavioral outlier detector** operating over change batches. It does not attempt to independently prove malicious intent; rather, it quantifies how unusual the modification pattern is relative to historical baseline behavior.

The model evaluates four standardized behavioral features:

* **Number of Files Changed (`number_of_files_changed`):** Identifies bulk modifications characteristic of automated attacks, ransomware, or unexpected mass scripts.
* **Time of Day (`time_of_day`):** Continuous fractional hour mapping (`[0.0, 24.0)`) that detects out-of-hours activity relative to typical working hours.
* **Directory Clustering (`directory_clustering`):** Ratio of unique parent directories to total changed files. A ratio near `1.0` indicates widespread cross-directory modifications, while low values signify localized changes.
* **Change Velocity (`change_velocity`):** Ratio of current file modification rate per second relative to the system's rolling historical median velocity.

### 2. Semantic Drift Analysis (`all-MiniLM-L6-v2`)
Traditional diff tools flag a line change regardless of whether an engineer fixed whitespace or completely replaced an authentication policy.

PyDrip leverages a local pretrained `sentence-transformers` model (`all-MiniLM-L6-v2`) to evaluate semantic divergence:
1. For `MODIFIED` text files, `old_content` is loaded from the immutable baseline snapshot and `new_content` is read from disk.
2. Both texts are mapped to 384-dimensional normalized vector embeddings.
3. Cosine similarity is computed and inverted into a bounded drift score:
   $$\text{drift\_score} = \text{clip}(1.0 - \mathbf{u} \cdot \mathbf{v}, 0.0, 1.0)$$
4. A score near `0.0` indicates semantically equivalent content (e.g., reformatting, comments), while higher scores (`> 0.25`) indicate structural policy or configuration logic replacements.
5. Binary files, newly added files, and deleted files safely bypass embedding and cleanly yield `drift_score = None`.

### 3. Deterministic Severity Engine
Rather than relying on unpredictable black-box classifications, PyDrip assigns severity through a rule-grounded state machine:

* **Base Severity:** Inherited from asset criticality (`Critical` → `HIGH`, `High` → `MEDIUM`, `Medium` → `LOW`, `Low` → `LOW`).
* **Elevation Rules:**
  * **File Deletion:** Critical asset deletion instantly triggers failsafe elevation to `CRITICAL`.
  * **New Additions:** Critical asset additions elevate to `CRITICAL`.
  * **Semantic Drift:** High drift (`> 0.25`) escalates severity by up to +2 levels.
  * **Anomaly Escalation:** Batch anomaly scores in upper brackets (`> 0.70`, `> 0.85`) compound with drift signals.

### 4. Traceable Evidence Generation
Every scored change is enriched with a structured evidence payload:
* `anomaly_reason`: Explains the batch velocity, timing, and file count context.
* `drift_reason`: Explains the degree of semantic content difference.
* `criticality_reason`: Explains the operational role and sensitivity of the asset.
* `severity_reason`: Explains the exact rule chain and compounding factors that determined the final severity rating.

---

## Real-Time Security Intelligence

Beyond periodic scanning, PyDrip provides continuous real-time security telemetry:

### 1. Real-Time File Monitoring
A background `Watchdog` filesystem observer monitors configured directories. Changes are intercepted continuously and passed through a temporal debouncing filter (500ms – 1000ms) to consolidate rapid editor writes into coherent logical events before initiating SHA-256 verification.

### 2. Per-File Anomaly Attribution
While Isolation Forest evaluates batch patterns, security analysts need to know which specific behavioral dimension triggered the alert. PyDrip attributes anomaly weights across the four feature vectors and surfaces the primary contributing factor (e.g., *"Primary factor: Unusually high change velocity"*).

### 3. Novelty Detection
Identifies when a change represents a first-seen event across three historical dimensions:
* **First-Seen File:** A path that has never appeared in historical baselines.
* **First-Seen Pattern:** An unfamiliar change type or directory context.
* **First-Seen Digest:** A SHA-256 hash not previously observed in system history.

### 4. Recurrence Scoring
Quantifies the historical frequency of similar file modifications using logarithmic scaling. A file edited dozens of times per week receives a high recurrence score, helping analysts differentiate routine administrative churn from rare, high-novelty anomalies.

### 5. Incident Risk Score
Security incidents rarely involve a single isolated file. PyDrip aggregates multiple file-level signals into a unified incident risk metric (0.0 to 1.0):
$$\text{Incident Risk} = 0.30(\text{Max Anomaly}) + 0.20(\text{Max Drift}) + 0.20(\text{Severity Factor}) + 0.15(\text{Novelty}) + 0.10(\text{File Volume}) + 0.05(\text{Recurrence})$$

### 6. Real-Time Security State & Alerts
Aggregated incident risk drives the global system security posture:
* `NORMAL` (`< 0.30`) — Standard background operations.
* `WATCH` (`0.30 – 0.49`) — Minor deviations detected; logged for observation.
* `ELEVATED` (`0.50 – 0.69`) — Unusual file activity; priority monitoring active.
* `HIGH` (`0.70 – 0.79`) — Multiple compounded risk indicators; operational notification raised.
* `CRITICAL` (`≥ 0.80`) — Immediate high-priority security alert dispatched to dashboard.

---

## Example Incident

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                          CRITICAL SECURITY INCIDENT                          │
├──────────────────────────────────────────────────────────────────────────────┤
│ Incident Risk:      92% [CRITICAL]                                           │
│ Affected Files:     7 files modified within 4.2 seconds                      │
│ Event Window:       02:41 AM UTC (Off-Hours Activity)                        │
│ Security State:     CRITICAL ALERT                                           │
├──────────────────────────────────────────────────────────────────────────────┤
│ Primary Indicators:                                                          │
│   • High change velocity: 1.67 files/sec (9.8x historical baseline)          │
│   • Off-hours activity: modification at 02:41 UTC                            │
│   • Directory clustering: cross-directory changes across /configs and /bin   │
│   • Novelty: previously unseen file modification pattern                     │
├──────────────────────────────────────────────────────────────────────────────┤
│ Top Contributing Asset:                                                      │
│   File:             /configs/auth.conf                                       │
│   Change Type:      MODIFIED                                                 │
│   Criticality:      Critical                                                 │
│   Anomaly Score:    0.91 [Outlier Batch]                                     │
│   Drift Score:      0.30 [Major Semantic Policy Replacement]                 │
│   Novelty:          1.00 [First-Seen Hash & Pattern]                         │
│   Assigned Severity: CRITICAL                                                │
│                                                                              │
│ Evidence:                                                                    │
│   "Assigned CRITICAL: Critical asset initialized at baseline HIGH, elevated   │
│    by high semantic drift (0.3007, +2 levels) and compounded by off-hours    │
│    anomaly score (0.9100)."                                                  │
└──────────────────────────────────────────────────────────────────────────────┘
```
*(Illustrative example demonstrating real-time incident aggregation and evidence attribution.)*

---

## Technology Stack

| Layer | Technology | Version / Spec | Role |
| :--- | :--- | :--- | :--- |
| **Language** | Python | `3.11+` / `3.13` | Core runtime across all modules |
| **Backend Framework** | FastAPI | `0.110+` | Asynchronous RESTful API backend |
| **ASGI Server** | Uvicorn | `0.28+` | High-performance ASGI web server |
| **Cryptographic Hashing** | hashlib (SHA-256) | Built-in | Streaming 64KB chunked file digest verification |
| **Real-Time Watcher** | Watchdog | `4.0+` | Cross-platform filesystem event observation |
| **Database** | SQLite3 | Built-in | ACID-compliant relational storage for baselines & audit |
| **Configuration** | PyYAML + Pydantic v2 | `2.6+` | Strictly validated configuration schemas |
| **Anomaly Detection** | scikit-learn | `1.4+` | Unsupervised Isolation Forest batch anomaly modeling |
| **Semantic Drift** | sentence-transformers | `all-MiniLM-L6-v2` | Pretrained dense transformer embeddings |
| **Numerical Computing** | NumPy & Pandas | `1.26+` / `2.2+` | Feature vector normalization and matrix operations |
| **Dashboard UI** | Streamlit | `1.32+` | Interactive visual security operations console |
| **Testing Suite** | Pytest | `9.1+` | Automated behavioral and integration testing |

---

## Project Structure

```text
pydrip/
├── ai_scoring/                  # AI/ML Scoring & Adapter Layer (Rohith)
│   ├── __init__.py
│   ├── adapter.py               # Integration adapter (snapshots, history, persistence)
│   ├── anomaly.py               # Isolation Forest unsupervised anomaly detector
│   ├── contract.py              # Schema contract validation
│   ├── drift.py                 # MiniLM semantic drift detection
│   ├── evidence.py              # Explainable evidence engine
│   ├── features.py              # Batch feature engineering (velocity, clustering, etc.)
│   ├── mock_data.py             # Synthetic datasets and demo scenario generators
│   ├── scorer.py                # Unified coordinator entry point: score_changes()
│   └── severity.py              # Deterministic severity calculation engine
├── app/                         # Core FIM Backend & REST API (Harsha)
│   ├── core/
│   │   ├── baseline.py          # Baseline discovery & text snapshot manager
│   │   ├── hasher.py            # Streaming SHA-256 calculation
│   │   └── scanner.py           # Filesystem scanner & diffing engine
│   ├── config.py                # YAML configuration loader & validator
│   ├── database.py              # SQLite access, migrations, & append-only audit
│   ├── main.py                  # FastAPI application routing & lifecycle hooks
│   └── models.py                # Pydantic schemas (ChangeContract, EvidenceModel)
├── config/
│   └── config.yaml              # Active monitored paths and extension rules
├── data/
│   ├── CONTRACT.md              # Formal JSON contract specification
│   ├── fim.db                   # SQLite database (baselines, changes, audit log)
│   └── historical_scans.json    # Reference historical scan profiles
├── tests/                       # Complete Test Suite (176 tests)
│   ├── test_adapter.py          # Adapter integration & failure isolation tests
│   ├── test_anomaly.py          # Anomaly calibration & determinism tests
│   ├── test_api.py              # FastAPI endpoint tests
│   ├── test_audit.py            # Append-only audit log integrity tests
│   ├── test_baseline.py         # Baseline snapshotting & discovery tests
│   ├── test_behavioral.py       # End-to-end behavioral ranking tests
│   ├── test_config.py           # Configuration validation tests
│   ├── test_contract.py         # Schema contract conformance tests
│   ├── test_database.py         # SQLite schema & migration tests
│   ├── test_demo.py             # Demo scenario verification tests
│   ├── test_drift.py            # MiniLM semantic drift tests
│   ├── test_evidence.py         # Evidence generation linguistic tests
│   ├── test_features.py         # Feature engineering tests
│   ├── test_hardening.py       # Stress & filesystem edge case tests
│   ├── test_hasher.py           # Streaming hashing tests
│   ├── test_mock_data.py        # Mock dataset sanity tests
│   ├── test_models.py           # Pydantic model validation tests
│   ├── test_rohith_prep.py      # Integration readiness boundary tests
│   ├── test_scanner.py          # Scanner diffing tests
│   └── test_severity.py         # Severity engine rule tests
├── requirements.txt             # Python project dependencies
└── README.md                    # Single source of truth documentation
```

---

## API Reference

The FastAPI service exposes the following endpoints:

| Method | Endpoint | Purpose | Key Inputs | Key Outputs |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/health` | System health check | None | `{"status": "ok"}` |
| `GET` | `/config` | Retrieve current configuration | None | Validated `AppConfig` YAML schema |
| `PUT` | `/config` | Update monitored paths and rules | Updated `AppConfig` body | Persisted configuration + audit record |
| `POST` | `/baseline` | Create SHA-256 baseline snapshot | None | `BaselineSummaryResponse` (scan_id, files_indexed) |
| `POST` | `/scan` | Run diff scan + post-scan AI enrichment | None | `ScanSummaryResponse` (added, modified, deleted counts) |
| `GET` | `/changes/{scan_id}` | Retrieve scored changes with evidence | `scan_id` (path param) | `List[ChangeContract]` with anomaly, drift, severity, evidence |
| `GET` | `/audit` | Chronological audit history | None | `List[AuditLogRecord]` (append-only log) |
| `GET` | `/report/{scan_id}` | Retrieve stored investigation report | `scan_id` (path param) | `ReportResponse` (narrative markdown text) |

---

## Installation & Setup

### Prerequisites
* Python 3.11 or newer (tested on Python 3.13)
* Git

### 1. Clone the Repository
```bash
git clone https://github.com/Harsha-19/PyDrip.git
cd PyDrip
```

### 2. Set Up Virtual Environment
```bash
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Monitored Directories
Edit `config/config.yaml` to specify your target monitoring paths and asset criticalities:
```yaml
monitored_paths:
  - path: "./sample_data"
    criticality: "Medium"

criticality_rules:
  extensions:
    ".env": "Critical"
    ".conf": "High"
    ".py": "Medium"
    ".txt": "Low"
```

---

## Running PyDrip

### 1. Start the FastAPI Backend
Launch the backend server using Uvicorn:
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Interactive API documentation will be available at:
* **Swagger UI:** `http://127.0.0.1:8000/docs`
* **ReDoc:** `http://127.0.0.1:8000/redoc`

### 2. Start the Streamlit Dashboard
In a separate terminal window:
```bash
streamlit run app/dashboard.py
```
Open `http://localhost:8501` to view the interactive console.

---

## Hackathon Demo Walkthrough

Follow this 10-step sequence to demonstrate the complete PyDrip pipeline:

1. **Initialize Baseline:** Send `POST /baseline` to index sample files, compute initial SHA-256 hashes, and store immutable text snapshots in `.fim_snapshots/`.
2. **Inspect Clean State:** Verify in the dashboard that the monitored environment shows zero detected changes and security state is `NORMAL`.
3. **Simulate a Benign Edit:** Add a comment or format whitespace in a Low-criticality script (`sample.py`).
4. **Trigger Scan:** Send `POST /scan`. PyDrip identifies the hash difference, calculates near-zero semantic drift ($\le 0.01$), and marks severity as `LOW`.
5. **Simulate an Off-Hours Configuration Tamper:** Modify a Critical asset (`database.conf`), altering credentials or port configurations.
6. **Trigger Real-Time Detection:** The background Watchdog observer intercepts the file modification event immediately.
7. **Evaluate Semantic Drift:** PyDrip compares current content against the baseline snapshot, registering high semantic drift (`> 0.25`).
8. **Trigger Suspicious Bulk Modifications:** Quickly touch 5 additional configuration files simultaneously.
9. **Observe Incident Escalation:**
   * Isolation Forest flags anomalous velocity and volume (`> 0.85`).
   * Per-file attribution highlights change velocity as the primary indicator.
   * Novelty detection marks the modification pattern as first-seen.
   * Aggregate incident risk jumps to `CRITICAL` (92%).
10. **View Investigation Report:** Open the Streamlit dashboard or query `GET /report/{scan_id}` to review the auto-generated investigation narrative with traceable evidence.

---

## Testing & Verification

PyDrip maintains a comprehensive automated test suite spanning unit, behavioral, contract, and integration testing across all layers.

### Run All Tests
```bash
pytest -v
```

### Verified Test Results

```text
============================= test session starts =============================
platform win32 -- Python 3.13.0, pytest-9.1.1
rootdir: PyDrip
collected 176 items across both test suites

  Rohith AI/ML Scoring Suite (pydrip/tests/):
  • test_adapter.py ......................... 15 passed
  • test_anomaly.py .........................  7 passed
  • test_behavioral.py ......................  7 passed
  • test_contract.py ........................  5 passed
  • test_drift.py ...........................  7 passed
  • test_evidence.py ........................  9 passed
  • test_features.py ........................ 11 passed
  • test_mock_data.py .......................  9 passed
  • test_scorer.py .......................... 11 passed
  • test_severity.py ........................ 19 passed
  Subtotal: 100 passed (100%)

  Harsha Core FIM Suite (PyDrip-1/PyDrip/tests/):
  • test_api.py ............................. 10 passed
  • test_audit.py ...........................  8 passed
  • test_baseline.py ........................  5 passed
  • test_config.py ..........................  6 passed
  • test_database.py ........................  7 passed
  • test_demo.py ............................  4 passed
  • test_hardening.py .......................  7 passed
  • test_hasher.py ..........................  9 passed
  • test_models.py .......................... 10 passed
  • test_rohith_prep.py .....................  2 passed
  • test_scanner.py .........................  8 passed
  Subtotal: 76 passed (100%)

====================== 176 passed, 0 failures (100% pass) ======================
```

<details>
<summary><b>View complete test file manifest (Click to expand)</b></summary>

```
tests/test_adapter.py ...............                                    [ 15 passed]
tests/test_anomaly.py .......                                            [  7 passed]
tests/test_behavioral.py .......                                         [  7 passed]
tests/test_contract.py .....                                             [  5 passed]
tests/test_drift.py .......                                              [  7 passed]
tests/test_evidence.py .........                                         [  9 passed]
tests/test_features.py ...........                                       [ 11 passed]
tests/test_mock_data.py .........                                        [  9 passed]
tests/test_scorer.py ...........                                         [ 11 passed]
tests/test_severity.py ...................                               [ 19 passed]
tests/test_api.py ..........                                             [ 10 passed]
tests/test_audit.py ........                                             [  8 passed]
tests/test_baseline.py .....                                             [  5 passed]
tests/test_config.py ......                                              [  6 passed]
tests/test_database.py .......                                           [  7 passed]
tests/test_demo.py ....                                                  [  4 passed]
tests/test_hardening.py .......                                          [  7 passed]
tests/test_hasher.py .........                                           [  9 passed]
tests/test_models.py ..........                                          [ 10 passed]
tests/test_rohith_prep.py ..                                             [  2 passed]
tests/test_scanner.py ........                                           [  8 passed]
```
</details>

---

## Security Design Principles

* **Authoritative Cryptographic Truth:** SHA-256 hashing is the sole authoritative mechanism for asserting whether a file changed. AI models never override hash mismatches.
* **Contextual Analytical Lens:** AI/ML provides behavioral prioritization, pattern detection, and semantic drift assessment. It does not independently claim proof of malice.
* **Audit-Defensible Severity:** Severity assignments follow deterministic, rule-grounded state machines with traceable evidence citations, avoiding unexplainable black-box decisions.
* **Zero Future-Data Leakage:** Historical scan reconstruction strictly filters `detected_at < current_scan_detected_at`, ensuring the anomaly detector never trains on future telemetry.
* **Fault-Tolerant Failure Isolation:** AI enrichment executes inside protected try/except boundaries. If model inference fails or runs out of memory, raw cryptographic change records remain safely committed to SQLite, and scan endpoints continue returning `200 OK`.

---

## Limitations

* **Behavioral Outlier vs. Malice:** Anomaly detection identifies statistically unusual patterns (e.g., mass automated updates). It cannot definitively deduce malicious intent without operational context.
* **Text Content Requirement:** Semantic drift analysis is restricted to UTF-8 text files smaller than 1 MB. Binary executables, images, and compiled archives bypass embedding models and cleanly evaluate on hash and criticality signals.
* **Baseline Warm-Up:** Isolation Forest requires historical scan batches to establish a behavioral profile. On initial cold start (`scan_history = []`), anomaly scoring gracefully defaults to `None`.
* **Filesystem Event Coverage:** Real-time monitoring depends on OS-level filesystem notifications provided by Watchdog, which may vary slightly across underlying OS storage drivers.

---

## Future Roadmap

* **Enterprise SIEM Integration:** Native Syslog and CEF export for Splunk, Microsoft Sentinel, and Elastic Security.
* **Automated Webhook Notifications:** Direct alerts dispatching to Slack, Microsoft Teams, and PagerDuty upon reaching `HIGH` or `CRITICAL` states.
* **Extended Historical Baselines:** Long-term rolling window statistics incorporating seasonal shifts and scheduled maintenance windows.
* **Policy-Driven Remediation:** Optional automatic restoration of modified configuration files directly from immutable baseline snapshots upon critical tamper detection.

---

## Team & Responsibilities

PyDrip was designed and engineered as a collaborative cybersecurity solution:

* **Harsha** (`@Harsha-19`): Core FIM Architecture, SHA-256 streaming hasher, filesystem diff engine, SQLite database schema, FastAPI backend services, system integration, and real-time security intelligence layer.
* **Rohith**: AI/ML Layer Architecture, Isolation Forest behavioral anomaly detection, MiniLM semantic drift pipeline, deterministic severity engine, explainable evidence generation, and integration adapter.
* **Paritosh**: Security Dashboard & Visualization, Streamlit UI implementation, investigation report narrative generation, and demo dataset orchestration.

---

## Hackathon Context & Vision

File Integrity Monitoring is a mandatory pillar of PCI-DSS, SOC 2, and NIST 800-53 compliance, yet in practice it has long been plagued by alert noise and operational fatigue. Teams either ignore hundreds of meaningless alerts or turn off monitoring on active directories altogether.

PyDrip was created to prove that modern AI and security intelligence should not replace foundational cryptographic controls, but rather enhance them. By enriching SHA-256 integrity verification with behavioral anomaly detection, semantic drift understanding, and incident-level risk scoring, PyDrip transforms FIM from an unread notification log into an intelligent, explainable, and proactive security analyst.
