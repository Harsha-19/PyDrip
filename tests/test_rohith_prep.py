"""Integration boundary tests for Phase 9: Rohith AI/ML scoring integration readiness."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.config import load_config, save_config
from app.database import (
    get_changes_by_scan_id,
    initialize_database,
    insert_change_records,
)
from app.main import app
from app.models import (
    AppConfig,
    ChangeContract,
    ChangeType,
    Criticality,
    CriticalityRulesConfig,
    MonitoredPathConfig,
    Severity,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def preserve_config():
    """Ensure original configuration is preserved."""
    orig = load_config()
    yield
    save_config(orig)


@pytest.fixture
def rohith_prep_workspace(tmp_path: Path):
    """Fixture providing an isolated environment with files for integration testing."""
    db_file = tmp_path / "test_rohith_prep.db"
    initialize_database(db_file)

    sample_dir = tmp_path / "sample_data"
    sample_dir.mkdir()

    (sample_dir / "service.py").write_text("def run(): pass", encoding="utf-8")
    (sample_dir / "db.conf").write_text("host=127.0.0.1", encoding="utf-8")
    (sample_dir / ".env").write_text("API_KEY=testkey123", encoding="utf-8")
    (sample_dir / "obsolete.txt").write_text("old text", encoding="utf-8")

    config = AppConfig(
        monitored_paths=[
            MonitoredPathConfig(path=str(sample_dir), criticality=Criticality.Medium)
        ],
        criticality_rules=CriticalityRulesConfig(
            extensions={
                ".env": Criticality.Critical,
                ".conf": Criticality.High,
                ".py": Criticality.Medium,
                ".txt": Criticality.Low,
            }
        ),
    )

    save_config(config)
    return {
        "db_file": db_file,
        "sample_dir": sample_dir,
        "config": config,
        "tmp_path": tmp_path,
    }


def test_integration_boundary_contract_shape_and_null_scoring(rohith_prep_workspace):
    """Verify that Harsha's scanner outputs ChangeContract objects ready for Rohith's score_changes().

    Rohith's scoring layer requires:
    - scan_id, file_path, change_type, old_hash, new_hash, criticality, detected_at
    - anomaly_score = None (null)
    - drift_score = None (null)
    - severity = None (null)
    """
    ws = rohith_prep_workspace

    # 1. Baseline
    base_resp = client.post("/baseline")
    assert base_resp.status_code == 200

    # 2. Modify, Add, and Delete files
    (ws["sample_dir"] / "service.py").write_text("def run(): modified()", encoding="utf-8")
    (ws["sample_dir"] / "new_module.py").write_text("import sys", encoding="utf-8")
    (ws["sample_dir"] / "obsolete.txt").unlink()

    # 3. Scan
    scan_resp = client.post("/scan")
    assert scan_resp.status_code == 200
    scan_id = scan_resp.json()["scan_id"]

    # 4. Fetch changes
    changes_resp = client.get(f"/changes/{scan_id}")
    assert changes_resp.status_code == 200
    changes = changes_resp.json()
    assert len(changes) == 3

    # Validate each change record as ChangeContract
    for change_dict in changes:
        contract = ChangeContract.model_validate(change_dict)

        # Basic identity & metadata
        assert contract.scan_id == scan_id
        assert isinstance(contract.file_path, str)
        assert isinstance(contract.detected_at, str)

        # Criticality must be a valid Enum
        assert contract.criticality in {Criticality.Critical, Criticality.High, Criticality.Medium, Criticality.Low}

        # Null scoring fields (un-scored state)
        assert contract.anomaly_score is None
        assert contract.drift_score is None
        assert contract.severity is None

        # Verify hash contract rules
        if contract.change_type == ChangeType.ADDED:
            assert contract.old_hash is None
            assert contract.new_hash is not None
            assert len(contract.new_hash) == 64
        elif contract.change_type == ChangeType.DELETED:
            assert contract.old_hash is not None
            assert len(contract.old_hash) == 64
            assert contract.new_hash is None
        elif contract.change_type == ChangeType.MODIFIED:
            assert contract.old_hash is not None
            assert contract.new_hash is not None
            assert contract.old_hash != contract.new_hash
            assert len(contract.old_hash) == 64
            assert len(contract.new_hash) == 64


def test_database_persistence_supports_post_scoring_fields(tmp_path: Path):
    """Verify that the SQLite changes table schema is fully capable of storing post-scored fields.

    When Rohith's score_changes() completes, it will update anomaly_score, drift_score, and severity.
    """
    db_file = tmp_path / "scored_db.db"
    initialize_database(db_file)

    scored_change = {
        "scan_id": "scan-scored-001",
        "file_path": "./sample_data/.env",
        "change_type": "MODIFIED",
        "old_hash": "a" * 64,
        "new_hash": "b" * 64,
        "criticality": "Critical",
        "anomaly_score": 0.85,
        "drift_score": 0.72,
        "severity": "Critical",
        "detected_at": "2026-09-09T16:00:00Z",
    }

    insert_change_records([scored_change], db_path=db_file)

    retrieved = get_changes_by_scan_id("scan-scored-001", db_path=db_file)
    assert len(retrieved) == 1
    row = retrieved[0]

    assert row["scan_id"] == "scan-scored-001"
    assert row["criticality"] == "Critical"
    assert row["anomaly_score"] == 0.85
    assert row["drift_score"] == 0.72
    assert row["severity"] == "Critical"

    # Validate against ChangeContract model
    validated = ChangeContract.model_validate(row)
    assert validated.severity == Severity.Critical
    assert validated.anomaly_score == 0.85
    assert validated.drift_score == 0.72
