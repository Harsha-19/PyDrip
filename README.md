# FIM+ (AI-Augmented File Integrity Monitoring) — Core Integrity Engine & Backend API

Core cryptographic integrity engine and REST API for FIM+ (JP-018), owned by Harsha.

## Architecture & Technology Stack
- **Python 3.11+**
- **FastAPI** (REST API & auto Swagger UI docs)
- **SQLite** (`sqlite3` parameterized transactional access layer)
- **SHA-256** (`hashlib` streaming binary reader)
- **PyYAML** (external configuration loader & validator)
- **Pydantic v2** (schema validation & shared data contract enforcement)

## Project Layout (Development Root: `d:/hackathon/pydrip`)
```text
pydrip/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app and endpoint routing
│   ├── config.py            # YAML configuration loader & validator
│   ├── database.py          # SQLite database schema, access, & migrations
│   ├── models.py            # Pydantic models & shared JSON contract
│   └── core/
│       ├── __init__.py
│       ├── hasher.py        # SHA-256 streaming hashing engine
│       ├── baseline.py      # Baseline snapshot creation engine
│       └── scanner.py       # Filesystem diff & change classification
├── config/
│   └── config.yaml          # External monitoring configuration
├── data/
│   └── fim.db               # SQLite database
├── tests/                   # Full unit & integration test suite (76 tests)
│   ├── test_models.py
│   ├── test_config.py
│   ├── test_database.py
│   ├── test_hasher.py
│   ├── test_baseline.py
│   ├── test_scanner.py
│   ├── test_audit.py
│   ├── test_api.py
│   ├── test_rohith_prep.py
│   ├── test_hardening.py
│   └── test_demo.py
├── requirements.txt
└── pytest.ini
```

## Running the Application
From `d:/hackathon/pydrip`:
```bash
# Start FastAPI backend development server
uvicorn app.main:app --reload

# Interactive Swagger UI Documentation
http://127.0.0.1:8000/docs
```

## Running the Test Suite
```bash
# Run all 76 regression & hardening tests
pytest -q
```

## Core API Endpoints
- `GET /health`: System health status (`{"status": "ok"}`).
- `GET /config`: Returns active YAML configuration (`monitored_paths`, `criticality_rules`).
- `PUT /config`: Validates and updates configuration YAML file; records `CONFIG_UPDATE` in audit log.
- `POST /baseline`: Scans configured paths, calculates SHA-256 digests, stores baseline snapshot in SQLite, and logs `BASELINE_CREATED`.
- `POST /scan`: Scans current filesystem, compares against latest baseline, classifies changes (`ADDED`, `DELETED`, `MODIFIED`), persists change records with nullable AI scoring fields, and logs `SCAN_COMPLETED`.
- `GET /changes/{scan_id}`: Returns changes for a scan adhering strictly to the shared JSON contract.
- `GET /report/{scan_id}`: Returns persisted investigation report from SQLite.
- `GET /audit`: Returns full append-only operational audit history in chronological order.

## Shared Change Contract
```json
{
  "scan_id": "string",
  "file_path": "string",
  "change_type": "ADDED | DELETED | MODIFIED",
  "old_hash": "string | null",
  "new_hash": "string | null",
  "criticality": "Critical | High | Medium | Low",
  "anomaly_score": null,
  "drift_score": null,
  "severity": null,
  "detected_at": "timestamp"
}
```
*Note: AI/ML scoring fields (`anomaly_score`, `drift_score`, `severity`) remain `null` until Rohith's scoring layer executes.*
