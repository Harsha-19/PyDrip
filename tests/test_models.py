"""Unit tests for Phase 0 models, enums, and JSON contract validation."""

import json
import pytest
from pydantic import ValidationError

from app.models import (
    ChangeContract,
    ChangeType,
    Criticality,
    Severity,
    AppConfig,
    MonitoredPathConfig,
    CriticalityRulesConfig,
    BaselineRecord,
    AuditLogRecord,
    HealthResponse,
    BaselineSummaryResponse,
    ScanSummaryResponse,
)


def test_change_types_enum():
    """Verify only ADDED, DELETED, MODIFIED exist as change types."""
    valid_types = {t.value for t in ChangeType}
    assert valid_types == {"ADDED", "DELETED", "MODIFIED"}


def test_criticality_enum():
    """Verify exact allowed criticality values: Critical, High, Medium, Low."""
    valid_criticalities = {c.value for c in Criticality}
    assert valid_criticalities == {"Critical", "High", "Medium", "Low"}


def test_severity_enum():
    """Verify exact allowed severity values: Critical, High, Medium, Low."""
    valid_severities = {s.value for s in Severity}
    assert valid_severities == {"Critical", "High", "Medium", "Low"}


def test_change_contract_valid_null_scoring():
    """Verify raw change contract with initially nullable AI/scoring fields."""
    change = ChangeContract(
        scan_id="scan-12345",
        file_path="./sample_data/app.py",
        change_type=ChangeType.MODIFIED,
        old_hash="a" * 64,
        new_hash="b" * 64,
        criticality=Criticality.Medium,
        anomaly_score=None,
        drift_score=None,
        severity=None,
        detected_at="2026-09-09T15:00:00Z",
    )

    serialized = json.loads(change.model_dump_json())
    assert serialized == {
        "scan_id": "scan-12345",
        "file_path": "./sample_data/app.py",
        "change_type": "MODIFIED",
        "old_hash": "a" * 64,
        "new_hash": "b" * 64,
        "criticality": "Medium",
        "anomaly_score": None,
        "drift_score": None,
        "severity": None,
        "detected_at": "2026-09-09T15:00:00Z",
        "evidence": None,
    }


def test_change_contract_added_null_old_hash():
    """Verify ADDED change contract has null old_hash."""
    change = ChangeContract(
        scan_id="scan-12345",
        file_path="./sample_data/new.txt",
        change_type=ChangeType.ADDED,
        old_hash=None,
        new_hash="c" * 64,
        criticality=Criticality.Low,
        anomaly_score=None,
        drift_score=None,
        severity=None,
        detected_at="2026-09-09T15:00:00Z",
    )
    assert change.old_hash is None
    assert change.new_hash == "c" * 64


def test_change_contract_deleted_null_new_hash():
    """Verify DELETED change contract has null new_hash."""
    change = ChangeContract(
        scan_id="scan-12345",
        file_path="./sample_data/old.txt",
        change_type=ChangeType.DELETED,
        old_hash="d" * 64,
        new_hash=None,
        criticality=Criticality.Low,
        anomaly_score=None,
        drift_score=None,
        severity=None,
        detected_at="2026-09-09T15:00:00Z",
    )
    assert change.old_hash == "d" * 64
    assert change.new_hash is None


def test_change_contract_forbids_extra_fields():
    """Verify that arbitrary extra fields are rejected per strict contract."""
    with pytest.raises(ValidationError):
        ChangeContract(
            scan_id="scan-12345",
            file_path="./sample_data/app.py",
            change_type=ChangeType.MODIFIED,
            criticality=Criticality.Medium,
            detected_at="2026-09-09T15:00:00Z",
            unauthorized_field="illegal",  # type: ignore
        )


def test_change_contract_invalid_criticality():
    """Verify invalid criticality string fails validation."""
    with pytest.raises(ValidationError):
        ChangeContract(
            scan_id="scan-12345",
            file_path="./sample_data/app.py",
            change_type=ChangeType.MODIFIED,
            criticality="Extreme",  # type: ignore
            detected_at="2026-09-09T15:00:00Z",
        )


def test_app_config_validation():
    """Verify AppConfig model validates monitored paths and rules."""
    config_dict = {
        "monitored_paths": [
            {"path": "./sample_data", "criticality": "Medium"}
        ],
        "criticality_rules": {
            "extensions": {
                ".env": "Critical",
                ".conf": "High",
                ".cfg": "High",
                ".py": "Medium",
                ".txt": "Low",
            }
        },
    }
    cfg = AppConfig(**config_dict)
    assert len(cfg.monitored_paths) == 1
    assert cfg.monitored_paths[0].path == "./sample_data"
    assert cfg.monitored_paths[0].criticality == Criticality.Medium
    assert cfg.criticality_rules.extensions[".env"] == Criticality.Critical


def test_health_and_summary_models():
    """Verify health and summary models."""
    health = HealthResponse()
    assert health.status == "ok"

    base_summary = BaselineSummaryResponse(
        scan_id="base-001",
        files_indexed=15,
        created_at="2026-09-09T15:00:00Z",
    )
    assert base_summary.files_indexed == 15

    scan_summary = ScanSummaryResponse(
        scan_id="scan-002",
        baseline_scan_id="base-001",
        added_count=1,
        deleted_count=1,
        modified_count=2,
        total_changes=4,
        scanned_at="2026-09-09T15:05:00Z",
    )
    assert scan_summary.total_changes == 4
