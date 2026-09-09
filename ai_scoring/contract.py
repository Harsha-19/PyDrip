"""
Data contract validation module.

Phase 3: Provides lightweight validation of incoming FIM changes and historical scans.
"""
from typing import Dict, Any, List

def validate_change(change: Dict[str, Any]) -> bool:
    """Validates an individual raw change."""
    if not isinstance(change, dict):
        return False
    if "file_path" not in change:
        return False
    
    change_type = change.get("change_type")
    if change_type not in ["ADDED", "DELETED", "MODIFIED"]:
        return False
        
    criticality = change.get("criticality")
    if criticality is not None and criticality not in ["Critical", "High", "Medium", "Low"]:
        return False
        
    return True

def validate_scan_history(history: List[Dict[str, Any]]) -> bool:
    """Validates historical scan structure."""
    if not isinstance(history, list):
        return False
    for scan in history:
        if not isinstance(scan, dict):
            return False
        if "changes" not in scan or not isinstance(scan["changes"], list):
            return False
    return True
