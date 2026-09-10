class SeverityScorer:
    """
    Deterministically calculates the severity of a file change based on a fixed, 
    transparent point system.
    
    Total Possible Score: 100
    
    1. Criticality (Max 40 points)
       - Critical: 40
       - High: 30
       - Medium: 15
       - Low: 0
       
    2. Cryptographic/Action State (Max 30 points)
       - MODIFIED with Hash Mismatch: 30
       - DELETED: 30
       - ADDED: 20
       - MODIFIED with Hash Match (metadata only): 5
       
    3. AI Context: Anomaly & Drift (Max 30 points)
       - Anomaly: Up to 15 points (anomaly_score * 15)
       - Drift: Up to 15 points (drift_score * 15)
       - If drift is missing (e.g., binary files), anomaly weight doubles to 30.
       - If anomaly is missing, drift weight doubles to 30.
       - If both are missing, AI context is 0.
       
    Thresholds:
    - 0-39: LOW
    - 40-69: MEDIUM
    - 70-89: HIGH
    - 90-100: CRITICAL
    """

    def calculate(self, 
                  criticality: str, 
                  change_type: str, 
                  hash_mismatch: bool, 
                  anomaly_score: float | None = None, 
                  drift_score: float | None = None) -> dict:
        
        score = 0.0
        reasons = []

        # 1. Criticality evaluation
        crit_map = {
            "Critical": 40.0,
            "High": 30.0,
            "Medium": 15.0,
            "Low": 0.0
        }
        # Fallback to 0 if unrecognized
        crit_points = crit_map.get(criticality, 0.0)
        score += crit_points
        reasons.append(f"File criticality '{criticality}' contributed {crit_points} points.")

        # 2. Cryptographic / Action State
        crypto_points = 0.0
        if change_type == "MODIFIED":
            if hash_mismatch:
                crypto_points = 30.0
                reasons.append("Change type MODIFIED with SHA-256 hash mismatch contributed 30.0 points.")
            else:
                crypto_points = 5.0
                reasons.append("Change type MODIFIED with matching hashes (file content unchanged) contributed 5.0 points.")
        elif change_type == "DELETED":
            crypto_points = 30.0
            reasons.append("Change type DELETED contributed 30.0 points.")
        elif change_type == "ADDED":
            crypto_points = 20.0
            reasons.append("Change type ADDED contributed 20.0 points.")
        else:
            reasons.append(f"Unrecognized change type '{change_type}'. No crypto points awarded.")
            
        score += crypto_points

        # 3. AI Context (Anomaly & Drift)
        ai_points = 0.0
        
        # Safe float casting and bounds checking
        a_val = float(anomaly_score) if anomaly_score is not None else None
        d_val = float(drift_score) if drift_score is not None else None
        
        if a_val is not None and d_val is not None:
            a_pts = a_val * 15.0
            d_pts = d_val * 15.0
            ai_points = a_pts + d_pts
            reasons.append(f"Anomaly score ({a_val:.2f}) contributed {a_pts:.1f} points.")
            reasons.append(f"Semantic drift score ({d_val:.2f}) contributed {d_pts:.1f} points.")
        elif a_val is not None and d_val is None:
            a_pts = a_val * 30.0
            ai_points = a_pts
            reasons.append(f"Anomaly score ({a_val:.2f}) contributed {a_pts:.1f} points (weighted heavily due to missing drift).")
            reasons.append("Semantic drift score was unavailable (e.g., binary file).")
        elif d_val is not None and a_val is None:
            d_pts = d_val * 30.0
            ai_points = d_pts
            reasons.append("Anomaly score was unavailable.")
            reasons.append(f"Semantic drift score ({d_val:.2f}) contributed {d_pts:.1f} points (weighted heavily due to missing anomaly).")
        else:
            reasons.append("Both anomaly and semantic drift scores were missing. AI context contributed 0 points.")
            
        score += ai_points

        # Ensure score does not exceed 100 for any unexpected reason
        final_numeric_score = min(100.0, max(0.0, score))

        # 4. Threshold mapping
        if final_numeric_score < 40.0:
            severity_label = "LOW"
        elif final_numeric_score < 70.0:
            severity_label = "MEDIUM"
        elif final_numeric_score < 90.0:
            severity_label = "HIGH"
        else:
            severity_label = "CRITICAL"

        return {
            "severity": severity_label,
            "numeric_score": round(final_numeric_score, 2),
            "reasons": reasons
        }
