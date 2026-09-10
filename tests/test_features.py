"""
Tests for Phase 5 Feature Engineering module.
"""
import json
import math
from pathlib import Path
import pytest
import numpy as np

from ai_scoring import features


def test_build_features_exists():
    """Verify core API functions exist."""
    assert hasattr(features, "build_features")
    assert hasattr(features, "extract_batch_features")
    assert hasattr(features, "features_to_matrix")
    assert hasattr(features, "FEATURE_COLUMNS")


def test_number_of_files_changed():
    """Verify number of files changed counts all change events in batch."""
    # 1 file
    scan_1 = [{
        "scan_id": "scan_001",
        "detected_at": "2026-09-09T10:00:00",
        "changes": [{"file_path": "/configs/app.conf", "change_type": "MODIFIED"}]
    }]
    res_1 = features.extract_batch_features(scan_1)
    assert res_1[0]["number_of_files_changed"] == 1

    # 5 files
    scan_5 = [{
        "scan_id": "scan_002",
        "detected_at": "2026-09-09T10:00:00",
        "changes": [
            {"file_path": f"/configs/file_{i}.conf", "change_type": "MODIFIED"}
            for i in range(5)
        ]
    }]
    res_5 = features.extract_batch_features(scan_5)
    assert res_5[0]["number_of_files_changed"] == 5

    # 0 files (empty changes)
    scan_0 = [{
        "scan_id": "scan_003",
        "detected_at": "2026-09-09T10:00:00",
        "changes": []
    }]
    res_0 = features.extract_batch_features(scan_0)
    assert res_0[0]["number_of_files_changed"] == 0

    # Duplicate file path events (counts all change events per contract)
    scan_dup = [{
        "scan_id": "scan_004",
        "detected_at": "2026-09-09T10:00:00",
        "changes": [
            {"file_path": "/configs/app.conf", "change_type": "MODIFIED"},
            {"file_path": "/configs/app.conf", "change_type": "MODIFIED"}
        ]
    }]
    res_dup = features.extract_batch_features(scan_dup)
    assert res_dup[0]["number_of_files_changed"] == 2


def test_time_of_day():
    """Verify decimal-hour conversion and boundary conditions."""
    assert features.parse_time_of_day("2026-09-09T14:30:00") == 14.5
    assert features.parse_time_of_day("2026-09-09T02:00:00") == 2.0
    assert features.parse_time_of_day("2026-09-09T00:00:00") == 0.0
    assert features.parse_time_of_day("2026-09-09T12:15:00") == 12.25
    assert features.parse_time_of_day("2026-09-09T23:59:00") == pytest.approx(23.9833, abs=1e-3)


def test_directory_clustering():
    """Verify directory concentration ratio and path parsing."""
    # All files in single directory -> 1.0
    changes_clustered = [
        {"file_path": "/configs/app.conf"},
        {"file_path": "/configs/auth.conf"},
        {"file_path": "/configs/nginx.conf"}
    ]
    assert features.compute_directory_clustering(changes_clustered) == 1.0

    # Files spread evenly across 3 distinct directories -> 1/3
    changes_dispersed = [
        {"file_path": "/configs/app.conf"},
        {"file_path": "/scripts/deploy.sh"},
        {"file_path": "/reports/monthly.txt"}
    ]
    assert features.compute_directory_clustering(changes_dispersed) == pytest.approx(0.3333, abs=1e-3)

    # 4 files: 2 in /configs, 1 in /scripts, 1 in /reports -> 2/4 = 0.5
    changes_mixed = [
        {"file_path": "/configs/app.conf"},
        {"file_path": "/configs/auth.conf"},
        {"file_path": "/scripts/deploy.sh"},
        {"file_path": "/reports/monthly.txt"}
    ]
    assert features.compute_directory_clustering(changes_mixed) == 0.5

    # Single file -> 1.0
    assert features.compute_directory_clustering([{"file_path": "/app/config/file.conf"}]) == 1.0

    # Empty list -> 0.0
    assert features.compute_directory_clustering([]) == 0.0

    # Nested directories and root paths
    assert features.extract_directory("/app/config/security/auth.conf") == "/app/config/security"
    assert features.extract_directory("/file.conf") == "/"
    assert features.extract_directory("file.conf") == "/"
    assert features.extract_directory("C:\\configs\\app.conf") == "C:/configs"


def test_change_velocity_variations():
    """
    Verify:
    - Normal velocity ratio near 1.0
    - Slower activity < 1.0
    - Faster activity > 1.0
    - Extreme burst produces a large finite ratio (e.g. 100+, 500+, 1200+)
    - Zero/near-zero intervals do not produce infinity or NaN
    """
    scans = [
        # Baseline cadence: 2 files every 2 hours (velocity = 1.0 file/hr)
        {
            "scan_id": "scan_000",
            "detected_at": "2026-09-01T08:00:00",
            "changes": [{"file_path": "/configs/app.conf", "change_type": "MODIFIED"}, {"file_path": "/configs/db.conf", "change_type": "MODIFIED"}]
        },
        {
            "scan_id": "scan_001",
            "detected_at": "2026-09-01T10:00:00",
            "changes": [{"file_path": "/configs/app.conf", "change_type": "MODIFIED"}, {"file_path": "/configs/db.conf", "change_type": "MODIFIED"}]
        },
        # Scan 2: normal cadence (2 files in 2 hours -> 1.0 files/hr vs baseline 1.0 -> ratio 1.0)
        {
            "scan_id": "scan_002",
            "detected_at": "2026-09-01T12:00:00",
            "changes": [{"file_path": "/configs/app.conf", "change_type": "MODIFIED"}, {"file_path": "/configs/db.conf", "change_type": "MODIFIED"}]
        },
        # Scan 3: slower activity (1 file after 10 hours -> 0.1 files/hr vs baseline 1.0 -> ratio 0.1 < 1.0)
        {
            "scan_id": "scan_003",
            "detected_at": "2026-09-01T22:00:00",
            "changes": [{"file_path": "/configs/app.conf", "change_type": "MODIFIED"}]
        },
        # Scan 4: faster activity (5 files after 1 hour -> 5.0 files/hr vs baseline 1.0 -> ratio 5.0 > 1.0)
        {
            "scan_id": "scan_004",
            "detected_at": "2026-09-01T23:00:00",
            "changes": [
                {"file_path": f"/configs/file_{i}.conf", "change_type": "MODIFIED"}
                for i in range(5)
            ]
        },
        # Scan 5: extreme burst (10 files within 30 seconds -> clamped to 1 minute / 0.0167 hr -> velocity ~600 files/hr)
        # Ratio vs median baseline (~1.0) will be > 500, finite and not clamped
        {
            "scan_id": "scan_005",
            "detected_at": "2026-09-01T23:00:30",
            "changes": [
                {"file_path": f"/configs/burst_{i}.conf", "change_type": "MODIFIED"}
                for i in range(10)
            ]
        },
        # Scan 6: zero interval (identical timestamp as scan 5) -> must not produce inf or NaN
        {
            "scan_id": "scan_006",
            "detected_at": "2026-09-01T23:00:30",
            "changes": [{"file_path": "/configs/app.conf", "change_type": "MODIFIED"}]
        }
    ]

    records = features.extract_batch_features(scans)
    assert len(records) == 7

    # Scan 0: first scan -> 1.0
    assert records[0]["change_velocity"] == 1.0

    # Scan 1: second scan -> 1.0
    assert records[1]["change_velocity"] == 1.0

    # Scan 2: normal cadence near 1.0
    assert records[2]["change_velocity"] == pytest.approx(1.0, abs=0.05)

    # Scan 3: slower activity < 1.0
    assert records[3]["change_velocity"] < 1.0

    # Scan 4: faster activity > 1.0
    assert records[4]["change_velocity"] > 1.0

    # Scan 5: extreme burst produces large finite ratio (e.g. > 100)
    vel_5 = records[5]["change_velocity"]
    assert vel_5 > 100.0
    assert math.isfinite(vel_5)
    assert not math.isnan(vel_5)

    # Scan 6: zero interval does not produce infinity or NaN
    vel_6 = records[6]["change_velocity"]
    assert math.isfinite(vel_6)
    assert not math.isnan(vel_6)


def test_no_future_data_leakage():
    """
    Verify chronological integrity:
    Modifying or adding future scans (N+1, N+2) must NOT change the feature
    values of scan N.
    """
    scans_base = [
        {
            "scan_id": "scan_000",
            "detected_at": "2026-09-01T08:00:00",
            "changes": [{"file_path": "/configs/app.conf", "change_type": "MODIFIED"}]
        },
        {
            "scan_id": "scan_001",
            "detected_at": "2026-09-01T12:00:00",
            "changes": [{"file_path": "/configs/app.conf", "change_type": "MODIFIED"}]
        },
        {
            "scan_id": "scan_002",
            "detected_at": "2026-09-01T16:00:00",
            "changes": [{"file_path": "/configs/app.conf", "change_type": "MODIFIED"}]
        }
    ]

    records_base = features.extract_batch_features(scans_base)

    # Now append future scans with huge anomalies
    scans_extended = scans_base + [
        {
            "scan_id": "scan_003",
            "detected_at": "2026-09-01T16:01:00",
            "changes": [{"file_path": f"/configs/file_{i}.conf", "change_type": "MODIFIED"} for i in range(20)]
        },
        {
            "scan_id": "scan_004",
            "detected_at": "2026-09-01T16:02:00",
            "changes": [{"file_path": f"/configs/file_{i}.conf", "change_type": "MODIFIED"} for i in range(50)]
        }
    ]

    records_extended = features.extract_batch_features(scans_extended)

    # Scans 0, 1, 2 must have identical feature values regardless of future scans 3 and 4
    for i in range(3):
        assert records_base[i] == records_extended[i]


def test_determinism():
    """Verify calling extract_batch_features on identical input returns identical output."""
    scans = [
        {
            "scan_id": "scan_000",
            "detected_at": "2026-09-01T08:00:00",
            "changes": [{"file_path": "/configs/app.conf", "change_type": "MODIFIED"}]
        },
        {
            "scan_id": "scan_001",
            "detected_at": "2026-09-01T12:00:00",
            "changes": [{"file_path": "/configs/db.conf", "change_type": "MODIFIED"}]
        }
    ]
    run_1 = features.extract_batch_features(scans)
    run_2 = features.extract_batch_features(scans)
    assert run_1 == run_2


def test_invalid_input_handling():
    """Verify contract and malformed input handling raises ValueError."""
    # Not a list
    with pytest.raises(ValueError):
        features.extract_batch_features("invalid")

    # Scan without changes
    with pytest.raises(ValueError):
        features.extract_batch_features([{"scan_id": "s1"}])

    # Scan missing detected_at
    with pytest.raises(ValueError):
        features.extract_batch_features([{"scan_id": "s1", "changes": []}])


def test_build_features_single_batch():
    """Verify build_features handles single incoming batch relative to history."""
    history = [
        {
            "scan_id": "scan_000",
            "detected_at": "2026-09-01T08:00:00",
            "changes": [{"file_path": "/configs/app.conf", "change_type": "MODIFIED"}]
        },
        {
            "scan_id": "scan_001",
            "detected_at": "2026-09-01T12:00:00",
            "changes": [{"file_path": "/configs/db.conf", "change_type": "MODIFIED"}]
        }
    ]
    incoming = [
        {
            "file_path": "/configs/auth.conf",
            "change_type": "MODIFIED",
            "detected_at": "2026-09-01T16:00:00"
        }
    ]
    feat = features.build_features(incoming, history)
    assert feat["scan_id"] == "current_batch"
    assert feat["number_of_files_changed"] == 1
    assert feat["time_of_day"] == 16.0
    assert feat["directory_clustering"] == 1.0
    assert math.isfinite(feat["change_velocity"])


def test_features_to_matrix():
    """Verify features_to_matrix produces a clean 2D numpy float64 array."""
    records = [
        {
            "scan_id": "scan_000",
            "number_of_files_changed": 2,
            "time_of_day": 14.5,
            "directory_clustering": 0.5,
            "change_velocity": 1.0
        },
        {
            "scan_id": "scan_001",
            "number_of_files_changed": 5,
            "time_of_day": 2.0,
            "directory_clustering": 1.0,
            "change_velocity": 35.2
        }
    ]
    cols, matrix = features.features_to_matrix(records)
    assert cols == features.FEATURE_COLUMNS
    assert isinstance(matrix, np.ndarray)
    assert matrix.shape == (2, 4)
    assert matrix.dtype == np.float64
    assert matrix[0, 0] == 2.0
    assert matrix[0, 1] == 14.5
    assert matrix[1, 0] == 5.0
    assert matrix[1, 1] == 2.0
    assert matrix[1, 3] == 35.2


def test_mock_dataset_integration():
    """Verify all 70 scans in historical_scans.json produce clean, valid features."""
    data_path = Path("data/historical_scans.json")
    if not data_path.exists():
        pytest.skip("historical_scans.json not found")

    with open(data_path, "r", encoding="utf-8") as f:
        history = json.load(f)

    assert len(history) == 70

    records = features.extract_batch_features(history)
    assert len(records) == 70

    for i, rec in enumerate(records):
        assert rec["scan_id"] == history[i]["scan_id"]
        assert isinstance(rec["number_of_files_changed"], int)
        assert 0.0 <= rec["time_of_day"] < 24.0
        assert 0.0 <= rec["directory_clustering"] <= 1.0
        assert math.isfinite(rec["change_velocity"])
        assert not math.isnan(rec["change_velocity"])
        assert rec["change_velocity"] >= 0.0

    cols, matrix = features.features_to_matrix(records)
    assert cols == features.FEATURE_COLUMNS
    assert matrix.shape == (70, 4)
    assert not np.isnan(matrix).any()
    assert not np.isinf(matrix).any()
