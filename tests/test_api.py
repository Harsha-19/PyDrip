"""Integration tests for all FastAPI endpoints (Phase 8)."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.config import DEFAULT_CONFIG_PATH, load_config, save_config
from app.database import (
    DEFAULT_DB_PATH,
    get_audit_history,
    initialize_database,
    insert_scan_report,
)
from app.main import app
from app.models import (
    AppConfig,
    Criticality,
    CriticalityRulesConfig,
    MonitoredPathConfig,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def preserve_config_and_db_state():
    """Ensure original configuration is preserved and test workspace is clean."""
    original_config = load_config()
    yield
    save_config(original_config)


@pytest.fixture
def sample_api_workspace(tmp_path: Path):
    """Fixture providing an isolated folder under sample_data for full API testing."""
    sample_dir = tmp_path / "sample_data"
    sample_dir.mkdir()

    # Seed files
    (sample_dir / "app.py").write_text("print('hello api')", encoding="utf-8")
    (sample_dir / ".env").write_text("DB_KEY=sec123", encoding="utf-8")
    (sample_dir / "readme.txt").write_text("readme file", encoding="utf-8")

    config = AppConfig(
        monitored_paths=[
            MonitoredPathConfig(path=str(sample_dir), criticality=Criticality.Medium)
        ],
        criticality_rules=CriticalityRulesConfig(
            extensions={
                ".env": Criticality.Critical,
                ".py": Criticality.Medium,
                ".txt": Criticality.Low,
            }
        ),
    )

    save_config(config)
    return {
        "sample_dir": sample_dir,
        "config": config,
        "tmp_path": tmp_path,
    }


def test_get_health():
    """Test 1: GET /health returns HTTP 200 with status: ok."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_get_config():
    """Test 2: GET /config returns HTTP 200 and valid AppConfig."""
    resp = client.get("/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "monitored_paths" in data
    assert "criticality_rules" in data


def test_put_config_valid(sample_api_workspace):
    """Test 3: PUT /config updates config and writes exactly one CONFIG_UPDATE audit event."""
    initial_audit_len = len(get_audit_history())
    orig_cfg = load_config()

    new_cfg = {
        "monitored_paths": [{"path": str(sample_api_workspace["sample_dir"]), "criticality": "High"}],
        "criticality_rules": {"extensions": {".env": "Critical"}}
    }

    try:
        put_resp = client.put("/config", json=new_cfg)
        assert put_resp.status_code == 200
        assert put_resp.json() == new_cfg

        get_resp = client.get("/config")
        assert get_resp.status_code == 200
        assert get_resp.json() == new_cfg

        audit_history = get_audit_history()
        assert len(audit_history) == initial_audit_len + 1
        assert audit_history[-1]["action"] == "CONFIG_UPDATE"
    finally:
        save_config(orig_cfg)


def test_put_config_invalid():
    """Test 4: PUT /config with invalid criticality returns 422 without logging audit event."""
    initial_audit_len = len(get_audit_history())

    invalid_cfg = {
        "monitored_paths": [{"path": "./sample_data", "criticality": "BogusLevel"}],
        "criticality_rules": {"extensions": {}}
    }

    resp = client.put("/config", json=invalid_cfg)
    assert resp.status_code == 422
    assert len(get_audit_history()) == initial_audit_len


def test_post_baseline(sample_api_workspace):
    """Test 5: POST /baseline creates a baseline in SQLite and records BASELINE_CREATED."""
    resp = client.post("/baseline")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["scan_id"].startswith("base-")
    assert data["files_indexed"] == 3

    # Check audit log
    audit_history = get_audit_history()
    assert any(a["action"] == "BASELINE_CREATED" and data["scan_id"] in a["details"] for a in audit_history)


def test_post_scan_without_baseline():
    """Test 6: POST /scan with no baseline returns 400 Bad Request."""
    # Temporarily point to a non-existent baseline ID or mock no baseline
    # By default, if DB has no baseline or invalid, returns 400
    # We can test by calling with an empty DB in isolated test
    from app.core.scanner import run_scan
    from unittest.mock import patch
    from app.core.scanner import NoBaselineFoundError

    with patch("app.main.run_scan", side_effect=NoBaselineFoundError("No baseline found")):
        resp = client.post("/scan")
        assert resp.status_code == 400
        assert "no baseline" in resp.json()["detail"].lower()


def test_full_baseline_scan_and_get_changes_flow(sample_api_workspace):
    """Test 7 & 8: Full flow POST /baseline -> modify/add/delete -> POST /scan -> GET /changes/{scan_id}."""
    ws = sample_api_workspace

    # 1. Create baseline
    base_resp = client.post("/baseline")
    assert base_resp.status_code == 200
    base_id = base_resp.json()["scan_id"]

    # 2. Introduce changes:
    # - Modify .env
    (ws["sample_dir"] / ".env").write_text("DB_KEY=hacked_key", encoding="utf-8")
    # - Add new script
    (ws["sample_dir"] / "malware.py").write_text("import os", encoding="utf-8")
    # - Delete readme.txt
    (ws["sample_dir"] / "readme.txt").unlink()
    # app.py remains UNTOUCHED

    # 3. Trigger POST /scan
    scan_resp = client.post("/scan")
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["scan_id"].startswith("scan-")
    assert scan_data["baseline_scan_id"] == base_id
    assert scan_data["total_changes"] == 3
    assert scan_data["modified_count"] == 1
    assert scan_data["added_count"] == 1
    assert scan_data["deleted_count"] == 1

    scan_id = scan_data["scan_id"]

    # 4. Fetch GET /changes/{scan_id}
    changes_resp = client.get(f"/changes/{scan_id}")
    assert changes_resp.status_code == 200
    changes = changes_resp.json()
    assert len(changes) == 3

    by_file = {Path(c["file_path"]).name: c for c in changes}

    # Verify .env MODIFIED
    assert ".env" in by_file
    env_c = by_file[".env"]
    assert env_c["scan_id"] == scan_id
    assert env_c["change_type"] == "MODIFIED"
    assert env_c["old_hash"] is not None
    assert env_c["new_hash"] is not None
    assert env_c["old_hash"] != env_c["new_hash"]
    assert env_c["criticality"] == "Critical"
    assert env_c["anomaly_score"] is None
    assert env_c["drift_score"] is None
    assert env_c["severity"] is None

    # Verify malware.py ADDED
    assert "malware.py" in by_file
    mal_c = by_file["malware.py"]
    assert mal_c["change_type"] == "ADDED"
    assert mal_c["old_hash"] is None
    assert mal_c["new_hash"] is not None
    assert mal_c["criticality"] == "Medium"
    assert mal_c["severity"] is None

    # Verify readme.txt DELETED
    assert "readme.txt" in by_file
    del_c = by_file["readme.txt"]
    assert del_c["change_type"] == "DELETED"
    assert del_c["old_hash"] is not None
    assert del_c["new_hash"] is None
    assert del_c["criticality"] == "Low"


def test_get_audit_endpoint(sample_api_workspace):
    """Test 9: GET /audit returns chronological audit records."""
    # Trigger baseline to populate audit
    client.post("/baseline")

    resp = client.get("/audit")
    assert resp.status_code == 200
    records = resp.json()
    assert len(records) >= 1
    # Check ordering
    ids = [r["id"] for r in records]
    assert ids == sorted(ids)


def test_get_report_existing_and_not_found():
    """Test 10 & 11: GET /report/{scan_id} returns stored report or 404."""
    # Seed a report in SQLite
    insert_scan_report("scan-test-rep-001", "Paritosh generated security report text")

    # Fetch existing report
    resp = client.get("/report/scan-test-rep-001")
    assert resp.status_code == 200
    data = resp.json()
    assert data["scan_id"] == "scan-test-rep-001"
    assert data["report_text"] == "Paritosh generated security report text"
    assert "created_at" in data

    # Fetch non-existing report -> 404
    resp404 = client.get("/report/scan-unknown-999")
    assert resp404.status_code == 404
    assert "not found" in resp404.json()["detail"].lower()


def test_get_changes_unknown_scan_id_returns_empty_list():
    """Test 12: GET /changes/{unknown_scan_id} returns empty list cleanly without fabricating data."""
    resp = client.get("/changes/scan-nonexistent-999")
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_changes_evidence_public_contract_regression(sample_api_workspace):
    """Test 13: Regression test verifying that post-scoring evidence returned by GET /changes/{scan_id}
    and persisted in SQLite contains EXACTLY the 3 public contract keys:
    - anomaly_reason
    - criticality_weight
    - drift_reason
    and contains NO occurrences of criticality_reason or severity_reason.
    """
    ws = sample_api_workspace
    import sqlite3
    import json
    from ai_scoring.adapter import enrich_scan

    # 1. Baseline
    base_resp = client.post("/baseline")
    assert base_resp.status_code == 200

    # 2. Modify file
    (ws["sample_dir"] / "app.py").write_text("print('hello modified api')", encoding="utf-8")

    # 3. Scan & Enrich
    scan_resp = client.post("/scan")
    assert scan_resp.status_code == 200
    scan_id = scan_resp.json()["scan_id"]

    # Enrich scan using authoritative scoring adapter
    enrich_scan(scan_id=scan_id, db_path=DEFAULT_DB_PATH, project_root=Path("."))

    # 4. HTTP API verification
    changes_resp = client.get(f"/changes/{scan_id}")
    assert changes_resp.status_code == 200
    changes = changes_resp.json()
    assert len(changes) == 1

    http_evidence = changes[0]["evidence"]
    assert isinstance(http_evidence, dict)
    assert sorted(http_evidence.keys()) == [
        "anomaly_reason",
        "criticality_weight",
        "drift_reason",
    ]
    assert "criticality_reason" not in http_evidence
    assert "severity_reason" not in http_evidence

    # 5. SQLite Direct query verification
    conn = sqlite3.connect(str(DEFAULT_DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT evidence FROM changes WHERE scan_id = ?;", (scan_id,)).fetchone()
    conn.close()

    assert row is not None
    assert row["evidence"] is not None
    db_evidence = json.loads(row["evidence"])
    assert isinstance(db_evidence, dict)
    assert sorted(db_evidence.keys()) == [
        "anomaly_reason",
        "criticality_weight",
        "drift_reason",
    ]
    assert "criticality_reason" not in db_evidence
    assert "severity_reason" not in db_evidence
