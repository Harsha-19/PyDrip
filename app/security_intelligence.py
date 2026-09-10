"""
Security Intelligence Engine.

Aggregates deterministic file integrity scoring into actionable,
human-readable security alerts, risk scores, and attribution without
modifying the core Isolation Forest or Semantic Drift layers.
"""
from typing import Any, Dict, List, Optional


def calculate_attribution(batch_features: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Identify the primary behavioral indicator for the anomaly."""
    attr = {
        "change_volume": 0.0,
        "time_anomaly": 0.0,
        "directory_clustering": 0.0,
        "change_velocity": 0.0,
        "primary_reason": "No behavioral features provided"
    }

    if not batch_features:
        return attr

    # Normalize volume (arbitrary max of 50 for capping)
    v = batch_features.get("number_of_files_changed", 0)
    attr["change_volume"] = min(v / 50.0, 1.0)

    # Time anomaly (e.g. 0-6 AM is highly anomalous, >18 is mildly)
    tod = batch_features.get("time_of_day", 12.0)
    if 0.0 <= tod <= 6.0:
        attr["time_anomaly"] = 1.0
    elif 18.0 <= tod <= 24.0:
        attr["time_anomaly"] = 0.5
    else:
        attr["time_anomaly"] = 0.0

    # Clustering directly bounded [0,1]
    attr["directory_clustering"] = min(max(batch_features.get("directory_clustering", 0.0), 0.0), 1.0)

    # Velocity (ratio vs historical median, could be large)
    vel = batch_features.get("change_velocity", 1.0)
    attr["change_velocity"] = min((vel - 1.0) / 10.0 if vel > 1.0 else 0.0, 1.0)

    # Determine primary indicator
    scores = {
        "Multiple files changed": attr["change_volume"],
        "Off-hours activity": attr["time_anomaly"],
        "Concentrated directory activity": attr["directory_clustering"],
        "High change velocity": attr["change_velocity"]
    }

    primary = max(scores.items(), key=lambda x: x[1])
    if primary[1] > 0.1:
        attr["primary_reason"] = primary[0]
    else:
        attr["primary_reason"] = "Routine behavioral activity"

    return attr


def calculate_novelty(current_event: Dict[str, Any], scan_history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic novelty detection. Has this file/change pattern been seen?"""
    fpath = current_event.get("file_path")
    ctype = current_event.get("change_type")
    
    seen_path = False
    seen_exact = False
    
    for hist_scan in scan_history:
        for ch in hist_scan.get("changes", []):
            if ch.get("file_path") == fpath:
                seen_path = True
                if ch.get("change_type") == ctype:
                    seen_exact = True

    if not seen_path:
        return {
            "novelty_score": 1.0,
            "is_novel": True,
            "novelty_reason": "Previously unseen file modified"
        }
    elif not seen_exact:
        return {
            "novelty_score": 0.5,
            "is_novel": True,
            "novelty_reason": f"Previously unseen change pattern ({ctype}) for this file"
        }
    else:
        return {
            "novelty_score": 0.0,
            "is_novel": False,
            "novelty_reason": "Previously observed file change pattern"
        }


def calculate_recurrence(current_event: Dict[str, Any], scan_history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Determine recurrence of identical changes for this file."""
    fpath = current_event.get("file_path")
    ctype = current_event.get("change_type")
    count = 0
    
    for hist_scan in scan_history:
        for ch in hist_scan.get("changes", []):
            if ch.get("file_path") == fpath and ch.get("change_type") == ctype:
                count += 1
                
    if count == 0:
        score = 0.0
    elif count == 1:
        score = 0.20
    elif 2 <= count <= 3:
        score = 0.40
    elif 4 <= count <= 6:
        score = 0.60
    elif 7 <= count <= 10:
        score = 0.80
    else:
        score = 1.00
        
    reason = "No previous matching changes observed" if count == 0 else f"Change pattern observed {count} previous times"
    
    return {
        "recurrence_score": score,
        "recurrence_count": count,
        "recurrence_reason": reason
    }


def calculate_incident_risk(changes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate per-file metrics into a single incident risk score."""
    if not changes:
        return {"incident_risk_score": 0.0, "incident_risk_level": "LOW", "affected_files": 0}
        
    max_anomaly = max([ch.get("anomaly_score") or 0.0 for ch in changes] + [0.0])
    max_drift = max([ch.get("drift_score") or 0.0 for ch in changes] + [0.0])
    max_novelty = max([ch.get("novelty_score") or 0.0 for ch in changes] + [0.0])
    max_recurrence = max([ch.get("recurrence_score") or 0.0 for ch in changes] + [0.0])
    
    # Severity factor
    sev_map = {"LOW": 0.25, "MEDIUM": 0.50, "HIGH": 0.75, "CRITICAL": 1.00}
    max_sev_factor = 0.0
    for ch in changes:
        sev_str = (ch.get("severity") or "LOW").upper()
        max_sev_factor = max(max_sev_factor, sev_map.get(sev_str, 0.25))
        
    affected_files = len(changes)
    affected_file_factor = min(affected_files / 20.0, 1.0)
    
    risk = (
        0.30 * max_anomaly +
        0.20 * max_drift +
        0.20 * max_sev_factor +
        0.15 * max_novelty +
        0.10 * affected_file_factor +
        0.05 * max_recurrence
    )
    risk = min(max(risk, 0.0), 1.0)
    
    if risk < 0.30:
        level = "LOW"
    elif risk < 0.60:
        level = "MEDIUM"
    elif risk < 0.80:
        level = "HIGH"
    else:
        level = "CRITICAL"
        
    return {
        "incident_risk_score": round(risk, 4),
        "incident_risk_level": level,
        "affected_files": affected_files
    }


def calculate_security_state(risk_score: float) -> str:
    if risk_score < 0.30:
        return "NORMAL"
    elif risk_score < 0.50:
        return "WATCH"
    elif risk_score < 0.70:
        return "ELEVATED"
    elif risk_score < 0.80:
        return "HIGH"
    else:
        return "CRITICAL"


def enrich_security_events(
    changes: List[Dict[str, Any]], 
    scan_history: List[Dict[str, Any]],
    batch_features: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Orchestrate security intelligence enrichment for an entire scan batch."""
    enriched_changes = []
    
    # Calculate attribution based on batch features
    attribution = calculate_attribution(batch_features)
    
    for ch in changes:
        novelty = calculate_novelty(ch, scan_history)
        recurrence = calculate_recurrence(ch, scan_history)
        
        # Merge intelligence directly onto the change record per PRD
        enriched_ch = {
            **ch,
            "attribution": attribution,
            "novelty_score": novelty["novelty_score"],
            "is_novel": novelty["is_novel"],
            "novelty_reason": novelty["novelty_reason"],
            "recurrence_score": recurrence["recurrence_score"],
            "recurrence_count": recurrence["recurrence_count"],
            "recurrence_reason": recurrence["recurrence_reason"]
        }
        
        # Update the evidence payload safely
        ev = enriched_ch.get("evidence", {})
        if not isinstance(ev, dict):
            ev = {}
        ev.update({
            "attribution": attribution,
            "novelty_score": novelty["novelty_score"],
            "is_novel": novelty["is_novel"],
            "novelty_reason": novelty["novelty_reason"],
            "recurrence_score": recurrence["recurrence_score"],
            "recurrence_count": recurrence["recurrence_count"],
            "recurrence_reason": recurrence["recurrence_reason"]
        })
        enriched_ch["evidence"] = ev
        
        enriched_changes.append(enriched_ch)
        
    incident = calculate_incident_risk(enriched_changes)
    state = calculate_security_state(incident["incident_risk_score"])
    alert = state in ("HIGH", "CRITICAL")
    
    # Extract primary indicators
    indicators = []
    if attribution.get("primary_reason") != "Routine behavioral activity":
        indicators.append(attribution.get("primary_reason"))
    if any(ch.get("is_novel") for ch in enriched_changes):
        indicators.append("Previously unseen behavior")
    
    incident.update({
        "security_state": state,
        "alert": alert,
        "primary_indicators": indicators
    })
    
    return {
        "changes": enriched_changes,
        "incident": incident
    }
