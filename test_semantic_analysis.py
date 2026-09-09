import unittest
from unittest.mock import MagicMock, patch
import json

from app.investigation.drift import SemanticDriftDetector
from app.investigation.semantic import SemanticAnalyzer
from app.investigation.schemas import ChangeEvidence, ScoredChange, InvestigationInput, SemanticResult
from app.investigation.investigator import InvestigationEngine
from app.core.baseline import IntegrityEngine

class TestSemanticAnalysis(unittest.TestCase):
    def setUp(self):
        self.mock_drift = MagicMock(spec=SemanticDriftDetector)
        self.analyzer = SemanticAnalyzer(self.mock_drift)

    def test_a_high_similarity(self):
        """A. High Similarity: Content change with minimal semantic divergence."""
        self.mock_drift.calculate_similarity_and_drift.return_value = (0.95, 0.025)
        
        evidence = [ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 1", confidence=1.0)]
        res = self.analyzer.analyze("MODIFIED", "Access expires after 30 days.", "Access expires after thirty days.", evidence)
        
        self.assertEqual(res.status, "AVAILABLE")
        self.assertEqual(res.analysis_method, "sentence_transformer")
        self.assertEqual(res.semantic_similarity, 0.95)
        self.assertEqual(res.semantic_drift, 0.025)
        self.assertIn("superficial", res.explanation.lower())

    def test_b_low_similarity(self):
        """B. Low Similarity: Content change with substantial semantic divergence."""
        self.mock_drift.calculate_similarity_and_drift.return_value = (-0.20, 0.60)
        
        evidence = [ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 1", confidence=1.0)]
        res = self.analyzer.analyze("MODIFIED", "allow all incoming traffic", "deny all external traffic except port 443", evidence)
        
        self.assertEqual(res.status, "AVAILABLE")
        self.assertEqual(res.semantic_similarity, -0.20)
        self.assertEqual(res.semantic_drift, 0.60)
        self.assertIn("drastically alter", res.explanation.lower())

    def test_c_numeric_material_change(self):
        """C. Numeric/Material Change: Concrete configuration edit causing measurable drift."""
        self.mock_drift.calculate_similarity_and_drift.return_value = (0.40, 0.30)
        
        evidence = [ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 2", confidence=1.0)]
        res = self.analyzer.analyze("MODIFIED", "PORT=8080\nTIMEOUT=30", "PORT=9999\nTIMEOUT=3000", evidence)
        
        self.assertEqual(res.status, "AVAILABLE")
        self.assertEqual(res.semantic_drift, 0.30)
        self.assertIn("moderate shift", res.explanation.lower())

    def test_d_superficial_rewrite(self):
        """D. Superficial Rewrite: Passive/active voice or minor rephrasing with identical meaning."""
        self.mock_drift.calculate_similarity_and_drift.return_value = (0.98, 0.01)
        
        evidence = [ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 1", confidence=1.0)]
        res = self.analyzer.analyze("MODIFIED", "Admin restarted the server.", "The server was restarted by admin.", evidence)
        
        self.assertEqual(res.status, "AVAILABLE")
        self.assertEqual(res.semantic_drift, 0.01)
        self.assertIn("superficial wording", res.explanation.lower())

    def test_e_primary_model_success(self):
        """E. Primary Model Success: Preserves canonical (1 - similarity) / 2 formula and method-based confidence."""
        # 1. Verify canonical mathematical mapping on detector
        real_detector = SemanticDriftDetector()
        sim, drift = real_detector.calculate_similarity_and_drift("exact text", "exact text")
        self.assertEqual(sim, 1.0)
        self.assertEqual(drift, 0.0)
        
        # 2. Verify analyzer integration with primary model
        self.mock_drift.calculate_similarity_and_drift.return_value = (0.80, 0.10)
        evidence = [ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 1", confidence=1.0)]
        res = self.analyzer.analyze("MODIFIED", "short text", "modified short text", evidence)
        
        self.assertEqual(res.status, "AVAILABLE")
        self.assertEqual(res.analysis_method, "sentence_transformer")
        self.assertEqual(res.confidence, 0.90)
        self.assertEqual(res.transition_history, ["PENDING", "ANALYZING", "AVAILABLE"])

    def test_f_primary_model_failure_triggers_fallback(self):
        """F. Primary Model Failure -> Fallback: Primary fails, fallback produces sequence similarity."""
        self.mock_drift.calculate_similarity_and_drift.side_effect = RuntimeError("GPU out of memory")
        
        evidence = [ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 1", confidence=1.0)]
        res = self.analyzer.analyze("MODIFIED", "allow user alice to login", "allow user bob to login", evidence)
        
        # AVAILABLE + analysis_method=fallback is final state
        self.assertEqual(res.status, "AVAILABLE")
        self.assertEqual(res.analysis_method, "fallback")
        self.assertEqual(res.confidence, 0.60) # Method-based fallback estimate
        self.assertIsNotNone(res.semantic_similarity)
        self.assertIsNotNone(res.semantic_drift)
        # Sequence similarity ratio: 8 shared tokens out of 10 total tokens = 0.8
        self.assertEqual(res.semantic_similarity, 0.8)
        self.assertEqual(res.semantic_drift, 0.2)
        self.assertEqual(res.transition_history, ["PENDING", "ANALYZING", "FALLBACK", "AVAILABLE"])

    def test_g_primary_and_fallback_failure_triggers_error(self):
        """G. Primary + Fallback Failure -> ERROR: Both fail, result is ERROR with no fabricated scores."""
        self.mock_drift.calculate_similarity_and_drift.side_effect = RuntimeError("Primary failure")
        
        with patch.object(self.analyzer, '_fallback_analysis') as mock_fb:
            mock_fb.return_value = SemanticResult(
                status="ERROR",
                semantic_similarity=None,
                semantic_drift=None,
                analysis_method=None,
                confidence=None,
                explanation="Both primary model and deterministic sequence fallback failed.",
                transition_history=["PENDING", "ANALYZING", "FALLBACK", "ERROR"]
            )
            
            evidence = [ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 1", confidence=1.0)]
            res = self.analyzer.analyze("MODIFIED", "old text", "new text", evidence)
            
            self.assertEqual(res.status, "ERROR")
            self.assertIsNone(res.analysis_method)
            self.assertIsNone(res.semantic_similarity)
            self.assertIsNone(res.semantic_drift)
            self.assertEqual(res.transition_history, ["PENDING", "ANALYZING", "FALLBACK", "ERROR"])

    def test_h_binary_unsupported_yields_unavailable(self):
        """H. Binary/Unsupported -> UNAVAILABLE: No fabricated semantic scores."""
        # Binary modification
        evidence_bin = [ChangeEvidence(evidence_type="ContentAnalysis", description="Binary modification detected", confidence=1.0)]
        res_bin = self.analyzer.analyze("MODIFIED", "bin", "bin", evidence_bin)
        self.assertEqual(res_bin.status, "UNAVAILABLE")
        self.assertIsNone(res_bin.semantic_drift)
        self.assertIsNone(res_bin.semantic_similarity)
        self.assertEqual(res_bin.transition_history, ["UNAVAILABLE"])
        
        # Missing/empty extraction
        evidence_txt = [ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 1", confidence=1.0)]
        res_empty = self.analyzer.analyze("MODIFIED", None, "new content", evidence_txt)
        self.assertEqual(res_empty.status, "UNAVAILABLE")
        self.assertIsNone(res_empty.semantic_drift)

    def test_i_determinism(self):
        """I. Determinism: Repeated calls yield identical results, scores, and explanations."""
        self.mock_drift.calculate_similarity_and_drift.return_value = (0.75, 0.125)
        evidence = [ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 1", confidence=1.0)]
        
        results = [
            self.analyzer.analyze("MODIFIED", "First version of config", "Second version of config", evidence)
            for _ in range(5)
        ]
        
        first = results[0].model_dump()
        for r in results[1:]:
            self.assertEqual(r.model_dump(), first)

    def test_j_stage2_integration_metadata_and_content(self):
        """J. Stage 2 Integration: Metadata-only modification handled as NOT_REQUIRED without calling it 'unchanged'."""
        # 1. Metadata-only change (e.g. mtime/permissions changed, but content identical)
        meta_evidence = [
            ChangeEvidence(evidence_type="MetadataAnalysis", description="File permissions changed: 0644 -> 0755", confidence=1.0),
            ChangeEvidence(evidence_type="ContentAnalysis", description="Content is unchanged.", value="No differences found", confidence=1.0)
        ]
        res_meta = self.analyzer.analyze("MODIFIED", "identical content", "identical content", meta_evidence)
        self.assertEqual(res_meta.status, "NOT_REQUIRED")
        self.assertIn("metadata modification detected", res_meta.explanation.lower())
        self.assertNotIn("file content and metadata are unchanged", res_meta.explanation.lower())
        
        # 2. Truly unchanged (no metadata and no content changes)
        pure_unchanged = [
            ChangeEvidence(evidence_type="ContentAnalysis", description="Content is unchanged.", value="No differences found", confidence=1.0)
        ]
        res_unchanged = self.analyzer.analyze("MODIFIED", "identical", "identical", pure_unchanged)
        self.assertEqual(res_unchanged.status, "NOT_REQUIRED")
        self.assertIn("file content is unchanged", res_unchanged.explanation.lower())

    def test_k_api_compatibility(self):
        """K. API Compatibility: Schemas accept SemanticResult and backward-compatible drift_score."""
        semantic_res = SemanticResult(
            status="AVAILABLE",
            semantic_similarity=0.92,
            semantic_drift=0.04,
            analysis_method="sentence_transformer",
            confidence=0.90,
            explanation="Superficial text adjustment.",
            transition_history=["PENDING", "ANALYZING", "AVAILABLE"]
        )
        
        change = ScoredChange(
            file_path="/etc/app.conf",
            change_type="MODIFIED",
            old_hash="hash_a",
            new_hash="hash_b",
            criticality="High",
            drift_score=0.04, # Backward compatibility
            semantic_analysis=semantic_res,
            evidence=[]
        )
        
        inp = InvestigationInput(scan_id="SCAN-COMPAT-1", changes=[change])
        dumped = inp.model_dump()
        self.assertIn("semantic_analysis", dumped["changes"][0])
        self.assertEqual(dumped["changes"][0]["semantic_analysis"]["status"], "AVAILABLE")
        self.assertEqual(dumped["changes"][0]["drift_score"], 0.04)

    def test_l_exact_status_transitions(self):
        """L. Exact Status Transitions: Verifies complete state machine transitions."""
        evidence = [ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 1", confidence=1.0)]
        
        # 1. Primary Success
        self.mock_drift.calculate_similarity_and_drift.return_value = (0.85, 0.075)
        res_success = self.analyzer.analyze("MODIFIED", "old text", "new text", evidence)
        self.assertEqual(res_success.transition_history, ["PENDING", "ANALYZING", "AVAILABLE"])
        
        # 2. Fallback Success
        self.mock_drift.calculate_similarity_and_drift.side_effect = RuntimeError("Primary failure")
        res_fb = self.analyzer.analyze("MODIFIED", "old text", "new text", evidence)
        self.assertEqual(res_fb.transition_history, ["PENDING", "ANALYZING", "FALLBACK", "AVAILABLE"])
        
        # 3. Fallback Failure -> ERROR
        with patch.object(self.analyzer, '_fallback_analysis') as mock_fb:
            mock_fb.return_value = SemanticResult(
                status="ERROR",
                transition_history=["PENDING", "ANALYZING", "FALLBACK", "ERROR"]
            )
            res_err = self.analyzer.analyze("MODIFIED", "old text", "new text", evidence)
            self.assertEqual(res_err.transition_history, ["PENDING", "ANALYZING", "FALLBACK", "ERROR"])
            
        # 4. Binary -> UNAVAILABLE
        res_bin = self.analyzer.analyze("MODIFIED", "bin", "bin", [ChangeEvidence(evidence_type="ContentAnalysis", description="Binary modification detected", confidence=1.0)])
        self.assertEqual(res_bin.transition_history, ["UNAVAILABLE"])
        
        # 5. Non-modified (ADDED) -> NOT_REQUIRED
        res_added = self.analyzer.analyze("ADDED", None, "content", [])
        self.assertEqual(res_added.transition_history, ["NOT_REQUIRED"])

if __name__ == '__main__':
    unittest.main()

