from datetime import datetime, timezone
from app.investigation.report import FinalInvestigationReport, ReportGenerator

class TemplateReportGenerator(ReportGenerator):
    """
    Authoritative deterministic incident report generator.
    Produces a complete, intelligence-driven forensic report based purely on strict deterministic rules
    derived from the Stage 1–4 investigation context, without any generative LLM.
    """
    def generate(self, investigation_result: dict) -> FinalInvestigationReport:
        files = investigation_result.get("file_details", [])
        scan_id = investigation_result.get("scan_id", "UNKNOWN")
        report_id = f"REP-{scan_id}"
        generated_at = datetime.now(timezone.utc).isoformat()
        
        # 1. Determine overall severity & risk score deterministically from Stage 4
        severity_ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        overall_severity = "LOW"
        max_rank = 1
        max_risk = 0.0
        conf_sum = 0.0
        
        for f in files:
            # Check Stage 4 risk_assessment first, then fall back to severity_assessment
            risk_info = f.get("risk_assessment", {})
            sev = risk_info.get("severity") or f.get("severity_assessment", {}).get("severity", "LOW")
            if severity_ranks.get(sev, 1) > max_rank:
                max_rank = severity_ranks.get(sev, 1)
                overall_severity = sev
                
            risk_score = risk_info.get("score")
            if risk_score is None:
                # Calculate from numeric score if available
                numeric = f.get("severity_assessment", {}).get("numeric_score", 0.0)
                risk_score = numeric / 100.0 if numeric > 1.0 else numeric
            if risk_score > max_risk:
                max_risk = risk_score
                
            conf_sum += risk_info.get("confidence", 0.70)
            
        overall_confidence = round(conf_sum / max(1, len(files)), 2)
                
        # 2. Build sub-components using helper methods
        affected_files = self._build_affected_files(files)
        key_findings = self._build_key_findings(files)
        evidence_analysis = self._build_evidence_analysis(files)
        evidence_ledger = self._build_evidence_ledger(files)
        possible_causes = self._build_possible_causes(files)
        recommendations = self._build_recommendations(files)
        confidence_text = self._build_confidence_assessment(files)
        limitations = self._build_limitations(files)
        summary = self._build_executive_summary(files, overall_severity, max_risk, key_findings)
        
        return FinalInvestigationReport(
            report_id=report_id,
            scan_id=scan_id,
            generated_at=generated_at,
            generation_method="fallback",
            executive_summary=summary,
            incident_severity=overall_severity,
            risk_score=round(max_risk, 4),
            confidence=overall_confidence,
            key_findings=key_findings,
            evidence_analysis=evidence_analysis,
            evidence_ledger=evidence_ledger,
            affected_files=affected_files,
            possible_causes=possible_causes,
            confidence_assessment=confidence_text,
            recommended_actions=recommendations,
            limitations=limitations
        )

    def _build_affected_files(self, files: list[dict]) -> list[str]:
        return sorted(list({f.get('file_path', 'unknown') for f in files if f.get('file_path')}))
        
    def _build_key_findings(self, files: list[dict]) -> list[str]:
        findings = set()
        for f in files:
            path = f.get('file_path', 'unknown')
            c_type = f.get('change_type', 'UNKNOWN')
            hash_status = f.get('hash_status', '')
            
            # Change type logic (backward compatible)
            if c_type == "MODIFIED":
                findings.add(f"A {f.get('criticality', 'file').lower()} file was modified: {path}")
            elif c_type == "ADDED":
                findings.add(f"A {f.get('criticality', 'file').lower()} file was added: {path}")
            elif c_type == "DELETED":
                findings.add(f"A {f.get('criticality', 'file').lower()} file was deleted: {path}")
                
            # Hash logic (backward compatible)
            if "mismatch" in hash_status.lower():
                findings.add(f"File integrity verification detected a hash mismatch for {path}.")
                
            # Semantic drift logic (backward compatible)
            drift = f.get('semantic_drift_score')
            if drift is not None and drift > 0.0:
                findings.add(f"Semantic drift ({drift:.2f}) was detected in {path}.")

            # Stage-tagged provenance findings
            sem = f.get("semantic_analysis")
            if sem and sem.get("status") == "AVAILABLE":
                method = sem.get("analysis_method", "unknown")
                findings.add(f"[SEMANTIC] Stage 3 — SemanticAnalyzer ({method}): Semantic drift of {sem.get('semantic_drift', 0.0):.2f} detected in {path}.")
            elif sem and sem.get("status") == "UNAVAILABLE":
                findings.add(f"[SEMANTIC] Stage 3 — SemanticAnalyzer: Semantic analysis unavailable for {path}.")

            risk = f.get("risk_assessment")
            if risk:
                findings.add(f"[RISK] Stage 4 — RiskEngine: Evaluated risk score {risk.get('score', 0.0):.2f} ({risk.get('severity', 'LOW')}) for {path}.")

        return sorted(list(findings))

    def _build_evidence_analysis(self, files: list[dict]) -> list[str]:
        analysis = []
        for f in files:
            path = f.get('file_path', 'unknown')
            analysis.append(f"--- Analysis for {path} ---")
            
            # Change type
            analysis.append(f"Change Type: {f.get('change_type', 'UNKNOWN')}")
            
            # Hash Status
            hash_status = f.get('hash_status', 'Not available')
            analysis.append(f"Cryptographic Hash Status: {hash_status}")
            
            # Anomaly Score
            anomaly = f.get('anomaly_score')
            if anomaly is not None:
                analysis.append(f"Anomaly Score: {anomaly:.2f} (Note: The project defines 0.0 as normal and 1.0 as highly anomalous; no rigid categorical thresholds are defined).")
            else:
                analysis.append("Anomaly Score: Not available.")
                
            # Drift Score
            drift = f.get('semantic_drift_score')
            if drift is not None:
                analysis.append(f"Semantic Drift Score: {drift:.2f} (Note: The project defines 0.0 as identical and 1.0 as completely drifted).")
            else:
                analysis.append("Semantic Drift Score: Not available.")
                
            # Direct severity reasons (backward compatibility)
            for reason in f.get('severity_assessment', {}).get('reasons', []):
                analysis.append(f"Evidence applied to severity: {reason}")
                
        return analysis

    def _build_evidence_ledger(self, files: list[dict]) -> list[dict]:
        ledger = []
        for f in files:
            path = f.get('file_path', 'unknown')
            raw_evidence = f.get('evidence', [])
            item = {
                "file_path": path,
                "change_type": f.get('change_type'),
                "cryptographic": {
                    "hash_status": f.get('hash_status'),
                    "hash_mismatch": f.get('hash_mismatch', False),
                    "old_hash": f.get('old_hash'),
                    "new_hash": f.get('new_hash')
                },
                "content": [e for e in raw_evidence if e.get("evidence_type") == "ContentAnalysis"],
                "metadata": [e for e in raw_evidence if e.get("evidence_type") == "MetadataAnalysis"],
                "structure": [e for e in raw_evidence if e.get("evidence_type") == "StructureAnalysis"],
                "semantic": f.get('semantic_analysis'),
                "risk": f.get('risk_assessment')
            }
            ledger.append(item)
        return ledger

    def _build_possible_causes(self, files: list[dict]) -> list[str]:
        causes = set()
        for f in files:
            c_type = f.get('change_type', '')
            hash_status = f.get('hash_status', '')
            drift = f.get('semantic_drift_score')
            
            if "mismatch" in hash_status.lower():
                causes.add("Possible cause: Unauthorized or unexpected file modification altering content.")
            if "match" in hash_status.lower() and c_type == "MODIFIED":
                causes.add("Possible cause: Routine system administration or metadata update (content unchanged).")
            if drift is not None and drift > 0.1:
                causes.add("Possible cause: Content modification causing measurable semantic drift.")
            if c_type == "DELETED":
                causes.add("Possible cause: File removal via automated cleanup or malicious deletion.")
            if c_type == "ADDED":
                causes.add("Possible cause: New file creation via deployment or unauthorized drop.")
                
        if not causes:
            causes.add("Possible cause: Unknown system change.")
            
        return sorted(list(causes))

    def _build_recommendations(self, files: list[dict]) -> list[str]:
        recs = set()
        for f in files:
            risk = f.get("risk_assessment", {})
            sev = risk.get("severity") or f.get("severity_assessment", {}).get("severity", "LOW")
            hash_status = f.get('hash_status', '')
            drift = f.get('semantic_drift_score')
            sem = f.get('semantic_analysis', {})
            raw_ev = f.get('evidence', [])
            
            if "mismatch" in hash_status.lower():
                recs.add("Verify the affected file against a trusted known-good copy.")
                recs.add("Preserve the affected file and relevant evidence.")
            if sev in ["HIGH", "CRITICAL"]:
                recs.add("Prioritize investigation of the affected critical file.")
            if drift is not None and drift > 0.1:
                recs.add("Review the content changes against the expected version.")
            if any("permission" in e.get("description", "").lower() for e in raw_ev):
                recs.add("Audit filesystem permissions and ownership history.")
            if sem and sem.get("status") == "UNAVAILABLE":
                recs.add("Perform manual content review because automated semantic analysis was unavailable.")
        
        if len(files) > 1:
            recs.add("Correlate the event with system/access/deployment logs.")
            
        if not recs:
            recs.add("Review the changed file(s) during normal administrative cycles.")
            
        return sorted(list(recs))

    def _build_limitations(self, files: list[dict]) -> list[str]:
        limitations = [
            "A cryptographic hash mismatch proves baseline divergence, but does not independently establish user intent or authorization."
        ]
        for f in files:
            sem = f.get("semantic_analysis", {})
            if sem and sem.get("status") == "UNAVAILABLE":
                limitations.append(f"Semantic analysis was unavailable for {f.get('file_path', 'file')} (e.g., binary or unsupported format).")
            if sem and sem.get("analysis_method") == "fallback":
                limitations.append(f"Semantic interpretation for {f.get('file_path', 'file')} utilized deterministic sequence similarity fallback.")
        return sorted(list(set(limitations)))

    def _build_executive_summary(self, files: list[dict], overall_severity: str, risk_score: float, findings: list[str]) -> str:
        num_files = len(files)
        summary = f"The deterministic fallback investigation identified {num_files} affected file(s) resulting in an overall incident severity of {overall_severity} (risk score: {risk_score:.2f}). "
        
        indicators = []
        if any("mismatch" in f for f in findings):
            indicators.append("hash integrity changes")
        if any("semantic drift" in f.lower() for f in findings):
            indicators.append("semantic content drift")
        if any("added" in f for f in findings):
            indicators.append("file additions")
        if any("deleted" in f for f in findings):
            indicators.append("file deletions")
            
        if indicators:
            summary += f"Observed evidence indicators include {', '.join(indicators)}. "
            
        summary += "The event requires review according to the deterministic findings."
        return summary

    def _build_confidence_assessment(self, files: list[dict]) -> str:
        evidence_points = 0
        for f in files:
            if f.get('hash_status') and "Not available" not in f.get('hash_status', ''):
                evidence_points += 1
            if f.get('anomaly_score') is not None:
                evidence_points += 1
            if f.get('semantic_drift_score') is not None:
                evidence_points += 1
                
        total_possible = len(files) * 3
        if total_possible == 0:
            return "Limited confidence: No files processed."
            
        ratio = evidence_points / total_possible
        if ratio > 0.6:
            return "High confidence: Conclusion is strongly supported by cryptographic and ML evidence."
        elif ratio > 0.3:
            return "Moderate confidence: Conclusion is supported by partial evidence."
        else:
            return "Limited confidence: Investigation lacked significant cryptographic or ML evidence."
