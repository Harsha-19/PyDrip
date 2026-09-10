from app.investigation.schemas import InvestigationInput, ScoredChange, ChangeEvidence
from app.investigation.anomaly import IsolationForestDetector
from app.investigation.drift import SemanticDriftDetector
from app.investigation.semantic import SemanticAnalyzer
from app.investigation.severity import SeverityScorer
from app.investigation.risk import RiskEngine
from app.investigation.metadata import MetadataDetector
from app.investigation.content import ContentDetector
from app.investigation.structure import StructureDetector
import os

class InvestigationContextProcessor:
    """
    Processes the raw InvestigationInput into a structured investigation context,
    preparing the evidence and detecting basic discrepancies (like hash mismatches)
    without performing final severity evaluation.
    """

    def process(self, input_data: InvestigationInput) -> dict:
        context = {
            "scan_id": input_data.scan_id,
            "summary": {
                "total_changes": len(input_data.changes),
                "change_types": {"ADDED": 0, "DELETED": 0, "MODIFIED": 0},
                "criticality_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            },
            "file_details": []
        }

        for change in input_data.changes:
            # Update summary counts
            context["summary"]["change_types"][change.change_type] += 1
            context["summary"]["criticality_counts"][change.criticality] += 1

            # Determine hash status and mismatch logic
            hash_mismatch = False
            hash_status = "No hash available"
            
            if change.change_type == "MODIFIED":
                if change.old_hash and change.new_hash:
                    if change.old_hash != change.new_hash:
                        hash_mismatch = True
                        hash_status = "Hash mismatch detected"
                    else:
                        hash_status = "Hashes match"
                else:
                    hash_status = "Missing hash(es) for modified file"
            elif change.change_type == "ADDED":
                if change.new_hash:
                    hash_status = "New hash recorded"
                else:
                    hash_status = "No new hash provided"
            elif change.change_type == "DELETED":
                if change.old_hash:
                    hash_status = "Old hash recorded"
                else:
                    hash_status = "No old hash provided"

            # Build per-file context preserving the original data
            file_context = {
                "file_path": change.file_path,
                "change_type": change.change_type,
                "criticality": change.criticality,
                "old_hash": change.old_hash,
                "new_hash": change.new_hash,
                "hash_status": hash_status,
                "hash_mismatch": hash_mismatch,
                "anomaly_score": change.anomaly_score,
                "drift_score": change.drift_score,
                "evidence": [ev.model_dump() for ev in change.evidence]
            }
            context["file_details"].append(file_context)

        return context


class InvestigationEngine:
    """
    Orchestrates the end-to-end investigation pipeline:
    Evidence Processing -> Anomaly Detection -> Semantic Drift -> Severity Scoring
    """
    def __init__(self):
        self.context_processor = InvestigationContextProcessor()
        self.anomaly_detector = IsolationForestDetector()
        self.drift_detector = SemanticDriftDetector()
        self.severity_scorer = SeverityScorer()
        
        # Stage 2 Detectors
        self.metadata_detector = MetadataDetector()
        self.content_detector = ContentDetector()
        self.structure_detector = StructureDetector()
        
        # Stage 3 Semantic Analyzer
        self.semantic_analyzer = SemanticAnalyzer(self.drift_detector)
        
        # Stage 4 Severity & Risk Engine
        self.risk_engine = RiskEngine()
        
    def investigate(self, input_data: InvestigationInput, file_contents_map: dict | None = None) -> dict:
        """
        Executes the full deterministic investigation pipeline.
        
        Args:
            input_data: The FIM event input schema.
            file_contents_map: Optional dictionary mapping file_path to 
                                {"old": "...", "new": "..."} for Semantic Drift checks.
                                
        Returns:
            A structured dict representing the InvestigationResult.
        """
        file_contents_map = file_contents_map or {}
        
        # 1. Evidence Processing
        context = self.context_processor.process(input_data)
        
        # 2. Anomaly Detection (Scan-level batch evaluation)
        # Extract basic clustering features from the context
        dirs = {p.rsplit('/', 1)[0] for p in (f["file_path"] for f in context["file_details"]) if '/' in p}
        
        scan_features = {
            "files_changed": context["summary"]["total_changes"],
            "time_of_day": 12.0, # Defaulting for deterministic evaluation without input
            "directory_cluster_count": len(dirs),
            "change_velocity": 1.0 # Defaulting
        }
        
        anomaly_info = self.anomaly_detector.score(scan_features)
        context["anomaly_assessment"] = anomaly_info
        
        # 3. Semantic Drift and 4. Deterministic Severity & Risk Scoring
        for file_detail in context["file_details"]:
            file_path = file_detail["file_path"]
            
            # Semantic Drift Detection
            contents = file_contents_map.get(file_path, {})
            old_content = contents.get("old")
            new_content = contents.get("new")
            
            # Stage 2: Run Authoritative Investigation Detectors
            md_ev = self.metadata_detector.analyze(file_path)
            co_ev = self.content_detector.analyze(file_path, old_content)
            st_ev = self.structure_detector.analyze(file_path)
            
            for ev in md_ev + co_ev + st_ev:
                file_detail["evidence"].append(ev.model_dump())
            
            # Stage 3: AI Semantic Analysis
            evidence_models = [ChangeEvidence(**e) for e in file_detail["evidence"]]
            semantic_res = self.semantic_analyzer.analyze(
                change_type=file_detail["change_type"],
                old_content=old_content,
                new_content=new_content,
                evidence=evidence_models
            )
            
            file_detail["semantic_analysis"] = semantic_res.model_dump()
            
            # Keep legacy drift score for backward compatibility in existing tests
            drift_score = semantic_res.semantic_drift if semantic_res.status == "AVAILABLE" else None
            file_detail["semantic_drift_score"] = drift_score
            
            # Stage 4: Authoritative Severity & Risk Evaluation
            risk_res = self.risk_engine.evaluate(
                file_path=file_path,
                change_type=file_detail["change_type"],
                hash_mismatch=file_detail["hash_mismatch"],
                evidence=evidence_models,
                semantic_result=semantic_res
            )
            file_detail["risk_assessment"] = risk_res.model_dump()
            
            # Keep legacy severity_assessment dictionary for backward compatibility with existing report generators
            reasons = [f"{f.name}: {f.evidence} ({f.rationale})" for f in risk_res.factors if f.contribution > 0]
            if not reasons:
                reasons = ["No elevated risk factors detected."]
            file_detail["severity_assessment"] = {
                "severity": risk_res.severity,
                "numeric_score": round(risk_res.score * 100, 2),
                "reasons": reasons
            }

        return context

