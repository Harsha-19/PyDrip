# JP-018 — AI-Augmented File Integrity Monitoring (FIM+)

Before doing any implementation work, create a file at the project root:

`PROJECT_CONTEXT.md`

This file will be the **single source of truth for project context**. Every time you work on this repository, you must read `PROJECT_CONTEXT.md` before making architectural or implementation decisions.

Do NOT start implementing the application yet.

Your task right now is ONLY to create and populate `PROJECT_CONTEXT.md` based on the project information below.

---

# 1. PROJECT IDENTITY

Project:
JP-018 — AI-Augmented File Integrity Monitoring (FIM+)

Domain:
Cybersecurity / IT Compliance

Product framing:
A lightweight, local MVP of a SaaS-style File Integrity Monitoring system.

One-line pitch:

"Tripwire meets an AI security analyst — cryptographic proof of what changed, and a plain-English explanation of why it matters."

Core idea:

Traditional FIM tells us that a file changed.

FIM+ should additionally determine:

* whether the change pattern is unusual
* whether the content meaningfully changed
* how severe the change is
* why that severity was assigned

The final system must remain explainable.

---

# 2. OVERALL SYSTEM

The system has these major layers:

1. Configuration
2. File scanning
3. SHA-256 hashing
4. Baseline management
5. Change classification
6. AI/ML scoring
7. Severity scoring
8. Evidence generation
9. Investigation report generation
10. API
11. Dashboard
12. Audit history

High-level flow:

File System
↓
Scan Engine
↓
SHA-256 comparison
↓
ADDED / DELETED / MODIFIED changes
↓
AI/ML Scoring Layer
↓
Anomaly Detection
↓
Semantic Drift
↓
Explainable Severity
↓
Evidence
↓
Report Generator
↓
Dashboard/API

---

# 3. TEAM OWNERSHIP

There are three major areas.

## Harsha — Core FIM

Responsible for:

* hashing
* SHA-256
* baseline
* filesystem scanning
* change detection
* SQLite
* FastAPI
* core scan pipeline

## Rohith — AI/ML Scoring Layer

Responsible for:

* batch feature engineering
* Isolation Forest anomaly detection
* semantic drift detection
* deterministic severity scoring
* evidence generation
* standalone scoring module
* mock/synthetic testing

The main interface is:

```python
def score_changes(change_list: list[dict], scan_history: list[dict]) -> list[dict]:
    ...
```

## Paritosh — Reporting / Dashboard

Responsible for:

* report narrative generation
* LLM report generation
* fallback templated reports
* Streamlit dashboard
* demo dataset
* presentation/demo support

Do NOT duplicate another teammate's responsibility unless explicitly instructed.

---

# 4. ROHITH'S AI/ML MODULE

The AI/ML layer takes raw detected changes and turns them into risk intelligence.

Input:

```python
score_changes(
    change_list,
    scan_history
)
```

Output:

The same change objects enriched with:

* anomaly_score
* drift_score
* severity
* evidence

Example:

```json
{
  "file_path": "/configs/database.conf",
  "change_type": "MODIFIED",
  "criticality": "Critical",
  "anomaly_score": 0.91,
  "drift_score": 0.78,
  "severity": "CRITICAL",
  "evidence": {
    "anomaly_reason": "...",
    "drift_reason": "...",
    "criticality_reason": "...",
    "severity_reason": "..."
  }
}
```

---

# 5. AI/ML COMPONENTS

## A. Feature Engineering

Build batch-level features such as:

* number of files changed
* time of day
* directory clustering
* change velocity relative to historical behavior

Important:

Isolation Forest operates on CHANGE BATCHES / PATTERNS.

It is NOT intended to independently declare an individual file malicious.

---

## B. Isolation Forest

Technology:

`scikit-learn`

Purpose:

Identify change batches that look unusual compared with historical scan behavior.

Historical examples might look like:

1 file
2 files
1 file
3 files
2 files
1 file

A suspicious batch might look like:

10 files
same directory
02:00
very short time interval

The system should produce an interpretable `anomaly_score`.

---

## C. Semantic Drift

Technology:

`sentence-transformers`

Preferred model:

`all-MiniLM-L6-v2`

Process:

old content
↓
embedding
↓
vector A

new content
↓
embedding
↓
vector B

vector A + vector B
↓
cosine similarity/distance
↓
drift_score

Use semantic drift for appropriate text/config files.

Do not attempt semantic embeddings on arbitrary binary files.

---

# 6. SEVERITY ENGINE

Severity MUST NOT simply be the output of an ML model.

Severity must be deterministic and explainable.

Conceptually:

criticality
+
change_type
+
anomaly_score
+
drift_score
↓
deterministic severity rules
↓
LOW / MEDIUM / HIGH / CRITICAL

The exact weights and thresholds must be documented in code and tests.

A developer/judge should be able to understand why a score became HIGH or CRITICAL.

Never hide the final severity decision behind a black-box model.

---

# 7. EVIDENCE

Every severity result must have evidence.

Example:

```json
{
  "evidence": {
    "anomaly_reason": "8 files changed within a short interval at 02:14, which is unusual compared with historical scan behavior.",
    "drift_reason": "Semantic distance was high, indicating a substantial content change.",
    "criticality_reason": "The modified file is classified as Critical.",
    "severity_reason": "High anomaly + substantial semantic drift + Critical classification resulted in CRITICAL severity."
  }
}
```

Evidence must be human-readable.

Do not generate meaningless evidence such as:

"model score = 0.91"

Explain what the score means.

---

# 8. MOCK DATA

The AI/ML module must be independently testable before Harsha's real pipeline is available.

Create mock data matching the shared contract.

Required scenarios:

## Benign change

* one file
* low criticality
* normal time
* small change

Expected:
LOW or MEDIUM

## Suspicious bulk change

* multiple files
* critical files
* unusual time
* same directory
* high change velocity

Expected:
HIGH or CRITICAL

## Formatting-only change

Example:

```text
DB_HOST=localhost
```

to:

```text
DB_HOST = localhost
```

Expected:
relatively low drift

## Meaningful change

Example:

```text
ALLOW_LOGIN=true
```

to:

```text
ALLOW_LOGIN=false
```

Expected:
higher drift

---

# 9. SYNTHETIC HISTORICAL DATA

Isolation Forest requires historical behavior.

Create synthetic historical scan data so the module does not suffer from cold start during development/demo.

Historical data should represent mostly normal behavior with occasional unusual examples.

Keep the generator deterministic where practical so tests remain reproducible.

---

# 10. PROJECT STRUCTURE

The AI/ML module should initially follow:

```text
ai_scoring/
├── __init__.py
├── scorer.py
├── features.py
├── anomaly.py
├── drift.py
├── severity.py
├── evidence.py
└── mock_data.py

tests/
├── __init__.py
├── test_scorer.py
├── test_features.py
├── test_anomaly.py
├── test_drift.py
└── test_severity.py

data/
├── historical_scans.json
└── demo_changes.json

requirements.txt
README.md
PROJECT_CONTEXT.md
.gitignore
```

Do not create unnecessary architecture.

Prefer simple, readable Python.

---

# 11. TECHNOLOGY STACK

Core:

* Python 3.11+
* scikit-learn
* sentence-transformers
* NumPy
* Pandas
* pytest
* Git/GitHub

Overall application:

* FastAPI
* SQLite
* hashlib / SHA-256
* Streamlit
* PyYAML

Optional LLM:

* OpenAI API or Anthropic API

Stretch:

* watchdog
* reportlab / weasyprint
* Docker
* PostgreSQL

Do not add stretch technologies unless explicitly instructed.

---

# 12. IMPORTANT PROJECT CONSTRAINTS

1. SHA-256 hashing remains the authoritative mechanism for detecting that a file changed.

2. AI/ML does NOT independently declare that a file changed.

3. AI/ML scores and explains detected changes.

4. Severity must be deterministic and inspectable.

5. Every severity must have evidence.

6. Do not store sensitive raw file contents unnecessarily.

7. Semantic drift should only be applied to appropriate text/config content.

8. The AI/ML module must remain independently testable.

9. Do not tightly couple the module to FastAPI, SQLite, or Streamlit.

10. The public interface must remain easy for the core FIM pipeline to call.

11. Avoid unnecessary dependencies.

12. Prefer simple implementations that can be explained during a hackathon judging session.

13. Do not over-engineer for production SaaS.

14. A working MVP is more important than perfect architecture.

15. If a feature is not required for the core demo, do not prioritize it over core reliability.

---

# 13. 15-PHASE BUILD PLAN

This exact phase structure is the project's working roadmap.

## PHASE 1 — Environment Setup

Verify:

* Python
* Git
* virtual environment
* dependencies
* sentence-transformer model availability

---

## PHASE 2 — Project Scaffold

Create the project structure and verify imports/tests.

---

## PHASE 3 — Lock JSON Contract

Define the exact input/output structure shared between the FIM scanner and AI scoring layer.

Do not assume fields that are not part of the agreed contract.

**Finalized Contract:** See [data/CONTRACT.md](file:///c:/Users/rohit/Downloads/ALL%20projects/Hackathon%28SIMS%29/pydrip/data/CONTRACT.md) for the finalized JSON schema, examples, and rules.

---

## PHASE 4 — Mock / Demo Dataset

Create:

* mock change data
* historical scan data
* benign scenario
* suspicious bulk scenario
* semantic drift scenarios

---

## PHASE 5 — Feature Engineering

Convert historical scan/change batches into numerical features for anomaly detection.

---

## PHASE 6 — Isolation Forest

Implement and test batch anomaly detection.

---

## PHASE 7 — Semantic Drift

Implement text/config semantic comparison using sentence embeddings and cosine distance.

---

## PHASE 8 — Severity Engine

Implement deterministic severity rules using:

* criticality
* change type
* anomaly score
* drift score

---

## PHASE 9 — Evidence Engine

Generate human-readable explanations for:

* anomaly
* drift
* criticality
* final severity

---

## PHASE 10 — score_changes()

Combine all components behind:

```python
score_changes(change_list, scan_history)
```

---

## PHASE 11 — Testing

Verify behavior, not merely execution.

Required:

* benign → Low/Medium
* suspicious bulk → High/Critical
* formatting → low drift
* meaningful change → high drift
* ADDED handled
* DELETED handled
* MODIFIED handled
* evidence always present
* missing/unsupported content handled safely

---

## PHASE 12 — Harsha Integration

Replace mock input with the real FIM scanner output.

Do not unnecessarily rewrite the scoring module.

---

## PHASE 13 — Paritosh Integration

Expose enriched scoring results and evidence to the report generator/dashboard.

---

## PHASE 14 — Final Demo

Demo sequence:

1. Create baseline.
2. Show clean state.
3. Make benign change.
4. Make suspicious bulk critical changes.
5. Add unexpected file.
6. Run scan.
7. Show severity differences.
8. Open a critical event.
9. Show anomaly score.
10. Show drift score.
11. Show evidence.
12. Show investigation report.
13. Show audit trail.

---

## PHASE 15 — Polish

Only after all core functionality works.

Possible additions:

* UI improvements
* better demo data
* PDF
* watchdog
* Docker
* additional visualizations

Never sacrifice core functionality for stretch features.

---

# 14. DEVELOPMENT WORKFLOW

Antigravity must NOT blindly build the entire application from one prompt.

Work phase-by-phase.

For each task:

1. Read `PROJECT_CONTEXT.md`.
2. Inspect the existing repository.
3. Understand the current phase.
4. Implement only the requested task.
5. Run tests.
6. Fix failures.
7. Do not modify unrelated components.
8. Report exactly what changed.
9. Wait for the next instruction.

Do not jump ahead to later phases unless explicitly instructed.

---

# 15. DECISION RULE

When there are multiple implementation choices:

Prioritize:

1. Correctness
2. Explainability
3. Reliability
4. Simplicity
5. Demo quality
6. Performance
7. Architecture sophistication

Do NOT choose complexity just because it sounds more advanced.

---

# 16. CURRENT STATUS

Current project state:

NOT STARTED.

Current phase:

PHASE 1 — Environment Setup.

The immediate next action after creating this file is to verify the development environment and dependencies.

Do NOT implement the AI algorithms yet.

---

# 17. CONTEXT FILE RULE

`PROJECT_CONTEXT.md` is the persistent project context.

Before every substantial coding task:

* read it
* follow it
* preserve the phase structure
* preserve ownership boundaries
* preserve the `score_changes()` interface
* preserve explainability requirements

If a new requirement conflicts with this document, STOP and report the conflict instead of silently changing the architecture.

When a major architectural decision is officially changed by the project owner, update this file so future coding sessions have the latest context.
