"""
Mock data generation module.

Phase 4: Deterministic generation of historical scans and demo scenarios.
"""
import random
import datetime
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from ai_scoring.contract import validate_change, validate_scan_history

def _generate_hash(content: Optional[str]) -> Optional[str]:
    """Deterministically generate SHA-256 hash or return None if content is absent."""
    if content is None:
        return None
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def _create_change(
    file_path: str,
    change_type: str,
    criticality: Optional[str] = None,
    old_content: Optional[str] = None,
    new_content: Optional[str] = None,
    detected_at: Optional[str] = None
) -> Dict[str, Any]:
    return {
        "file_path": file_path,
        "change_type": change_type,
        "criticality": criticality,
        "old_hash": _generate_hash(old_content),
        "new_hash": _generate_hash(new_content),
        "old_content": old_content,
        "new_content": new_content,
        "detected_at": detected_at
    }

def generate_historical_history() -> List[Dict[str, Any]]:
    """Generates ~70 scan batches spanning ~14 days."""
    rng = random.Random(42)
    history = []
    base_time = datetime.datetime(2026, 9, 1, 8, 0, 0)
    
    paths = [
        "/app/config/app.conf",
        "/configs/database.conf",
        "/etc/nginx/nginx.conf",
        "/scripts/deploy.sh",
        "/reports/monthly.txt",
        "/var/log/syslog"
    ]
    
    scan_count = 70
    for i in range(scan_count):
        # 90% normal (1-2 files, Low/Medium), 10% varied (3-5 files, High/Critical)
        is_normal = rng.random() < 0.9
        num_files = rng.randint(1, 2) if is_normal else rng.randint(3, 5)
        
        # Advance time: usually 2-6 hours apart
        base_time += datetime.timedelta(hours=rng.randint(2, 6), minutes=rng.randint(0, 59))
        # Keep mostly business hours for normal
        if is_normal and (base_time.hour < 8 or base_time.hour >= 18):
            if base_time.hour >= 18:
                base_time += datetime.timedelta(days=1)
            base_time = base_time.replace(hour=rng.randint(8, 12))
            
        timestamp_str = base_time.isoformat()
        
        changes = []
        chosen_paths = rng.sample(paths, min(num_files, len(paths)))
        for path in chosen_paths:
            crit = rng.choice(["Low", "Medium"]) if is_normal else rng.choice(["Medium", "High", "Critical"])
            ch = _create_change(
                file_path=path,
                change_type="MODIFIED",
                criticality=crit,
                old_content=f"old_{i}_{path}",
                new_content=f"new_{i}_{path}",
                detected_at=timestamp_str
            )
            changes.append(ch)
            
        history.append({
            "scan_id": f"scan_{i:03d}",
            "detected_at": timestamp_str,
            "changes": changes
        })
        
    return history

def generate_demo_scenarios() -> Dict[str, List[Dict[str, Any]]]:
    """Generates the 7 exact demo scenarios."""
    scenarios = {}
    
    # 1. Benign
    scenarios["benign"] = [
        _create_change(
            file_path="/configs/nginx.conf",
            change_type="MODIFIED",
            criticality="Low",
            old_content="timeout=30\n",
            new_content="timeout=35\n",
            detected_at="2026-09-09T10:00:00"
        )
    ]
    
    # 2. Formatting-only
    scenarios["formatting_only"] = [
        _create_change(
            file_path="/configs/database.conf",
            change_type="MODIFIED",
            criticality="Medium",
            old_content="DB_HOST=localhost\nDB_PORT=5432\n",
            new_content="DB_HOST = localhost\nDB_PORT = 5432\n",
            detected_at="2026-09-09T10:05:00"
        )
    ]
    
    # 3. Meaningful
    scenarios["meaningful_change"] = [
        _create_change(
            file_path="/configs/auth.conf",
            change_type="MODIFIED",
            criticality="High",
            old_content="ALLOW_LOGIN=true\n",
            new_content="ALLOW_LOGIN=false\n",
            detected_at="2026-09-09T10:10:00"
        )
    ]
    
    # 4. Suspicious bulk (approx 02:00, related files, high/critical)
    scenarios["suspicious_bulk"] = [
        _create_change(f"/configs/{name}.conf", "MODIFIED", crit, f"old_{name}", f"new_{name}", f"2026-09-09T02:0{idx}:00")
        for idx, (name, crit) in enumerate([
            ("app", "High"), 
            ("database", "Critical"), 
            ("auth", "Critical"), 
            ("security", "High"), 
            ("nginx", "High")
        ])
    ]
    
    # 5. Added file
    added = _create_change(
        file_path="/scripts/malware.sh",
        change_type="ADDED",
        criticality="High",
        old_content=None,
        new_content="echo 'owned'",
        detected_at="2026-09-09T10:20:00"
    )
    scenarios["added_file"] = [added]
    
    # 6. Deleted file
    deleted = _create_change(
        file_path="/configs/backup.conf",
        change_type="DELETED",
        criticality="Medium",
        old_content="backup_enabled=true",
        new_content=None,
        detected_at="2026-09-09T10:25:00"
    )
    scenarios["deleted_file"] = [deleted]
    
    # 7. Binary modification
    binary = _create_change(
        file_path="/bin/app",
        change_type="MODIFIED",
        criticality="Critical",
        old_content=None,
        new_content=None,
        detected_at="2026-09-09T10:30:00"
    )
    # Binary might still have hashes even if content is missing
    binary["old_hash"] = hashlib.sha256(b"oldbin").hexdigest()
    binary["new_hash"] = hashlib.sha256(b"newbin").hexdigest()
    scenarios["binary_modified"] = [binary]
    
    return scenarios

def save_datasets(data_dir: str = "data"):
    """Validates and saves the datasets to JSON."""
    history = generate_historical_history()
    scenarios = generate_demo_scenarios()
    
    if not validate_scan_history(history):
        raise ValueError("Generated historical history failed contract validation.")
        
    for name, changes in scenarios.items():
        for change in changes:
            if not validate_change(change):
                raise ValueError(f"Generated scenario '{name}' failed contract validation.")
                
    out_dir = Path(data_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    with open(out_dir / "historical_scans.json", "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)
        
    with open(out_dir / "demo_changes.json", "w", encoding="utf-8") as f:
        json.dump(scenarios, f, indent=2)

if __name__ == "__main__":
    save_datasets()
