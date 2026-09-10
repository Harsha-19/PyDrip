import unittest
import tempfile
import os
import json

from app.investigation.risk import RiskEngine
from app.investigation.schemas import (
    ChangeEvidence,
    SemanticResult,
    RiskResult,
    RiskFactor,
    ScoredChange,
    InvestigationInput
)
from app.investigation.compat import IntegrityEngine
from app.investigation.investigator import InvestigationEngine



class TestRiskEngine(unittest.TestCase):
    def setUp(self):
        self.risk_engine = RiskEngine()

    def test_a_unchanged_file(self):
        """A — Unchanged file: minimal/zero risk, LOW severity, deterministic output."""
        res = self.risk_engine.evaluate(
            file_path="/var/log/app.log",
            change_type="UNCHANGED",
            hash_mismatch=False,
            evidence=[ChangeEvidence(evidence_type="ContentAnalysis", description="Content is unchanged.", confidence=1.0)],
            semantic_result=SemanticResult(status="NOT_REQUIRED", explanation="File content is unchanged; semantic analysis is not required.")
        )
        self.assertEqual(res.severity, "LOW")
        self.assertEqual(res.score, 0.0)
        self.assertIn("LOW", res.explanation)
        self.assertGreaterEqual(res.confidence, 0.8)

    def test_b_metadata_only_change(self):
        """B — Metadata-only change: risk reflects metadata evidence, no semantic contribution."""
        ev = [
            ChangeEvidence(evidence_type="MetadataAnalysis", description="File permissions updated: 0644 -> 0755", confidence=1.0),
            ChangeEvidence(evidence_type="ContentAnalysis", description="Content is unchanged.", confidence=1.0)
        ]
        res = self.risk_engine.evaluate(
            file_path="/usr/bin/script.sh",
            change_type="MODIFIED",
            hash_mismatch=False, # Hash matches -> content is unchanged
            evidence=ev,
            semantic_result=SemanticResult(status="NOT_REQUIRED", explanation="Metadata modification detected; content unchanged.")
        )
        # Cryptographic matching: 0.05, Metadata permissions: 0.08 -> score = 0.13
        self.assertEqual(res.severity, "LOW")
        self.assertEqual(res.score, 0.13)
        # Confirm semantic factor contribution is 0.0
        sem_factor = next(f for f in res.factors if f.name == "semantic_impact")
        self.assertEqual(sem_factor.contribution, 0.0)
        self.assertIn("not_required", sem_factor.rationale)

    def test_c_content_modification(self):
        """C — Content modification: content evidence contributes to risk based on physical mutation volume."""
        ev = [
            ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 15, Deletions: 5", confidence=1.0)
        ]
        res = self.risk_engine.evaluate(
            file_path="/etc/hosts",
            change_type="MODIFIED",
            hash_mismatch=True,
            evidence=ev,
            semantic_result=None
        )
        content_factor = next(f for f in res.factors if f.name == "content_mutation")
        # 20 lines -> moderate -> 0.10
        self.assertEqual(content_factor.contribution, 0.10)
        self.assertIn("physical line modification", content_factor.rationale)

    def test_d_high_semantic_drift(self):
        """D — High semantic drift: semantic evidence contributes significantly to risk."""
        ev = [ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 2", confidence=1.0)]
        sem = SemanticResult(
            status="AVAILABLE",
            semantic_similarity=-0.20,
            semantic_drift=0.80,
            analysis_method="sentence_transformer",
            confidence=0.90
        )
        res = self.risk_engine.evaluate(
            file_path="/etc/security/access.conf",
            change_type="MODIFIED",
            hash_mismatch=True,
            evidence=ev,
            semantic_result=sem
        )
        sem_factor = next(f for f in res.factors if f.name == "semantic_impact")
        # drift 0.80 * 0.30 = 0.24
        self.assertEqual(sem_factor.contribution, 0.24)
        # Hash (0.40) + Semantic (0.24) + Content (0.05) = 0.69 -> HIGH
        self.assertEqual(res.severity, "HIGH")

    def test_e_low_semantic_drift(self):
        """E — Low semantic drift: lower semantic contribution."""
        ev = [ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 1", confidence=1.0)]
        sem = SemanticResult(
            status="AVAILABLE",
            semantic_similarity=0.96,
            semantic_drift=0.04,
            analysis_method="sentence_transformer",
            confidence=0.90
        )
        res = self.risk_engine.evaluate(
            file_path="/etc/motd",
            change_type="MODIFIED",
            hash_mismatch=True,
            evidence=ev,
            semantic_result=sem
        )
        sem_factor = next(f for f in res.factors if f.name == "semantic_impact")
        # drift 0.04 * 0.30 = 0.012
        self.assertEqual(sem_factor.contribution, 0.012)
        # Hash (0.40) + Semantic (0.012) + Content (0.05) = 0.462 -> MEDIUM
        self.assertEqual(res.severity, "MEDIUM")

    def test_f_hash_mismatch_and_major_content_change(self):
        """F — Hash mismatch + major content change: significantly elevated risk."""
        ev = [
            ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 75, Deletions: 10", confidence=1.0)
        ]
        sem = SemanticResult(
            status="AVAILABLE",
            semantic_similarity=0.30,
            semantic_drift=0.50,
            analysis_method="sentence_transformer",
            confidence=0.90
        )
        res = self.risk_engine.evaluate(
            file_path="/etc/sudoers",
            change_type="MODIFIED",
            hash_mismatch=True,
            evidence=ev,
            semantic_result=sem
        )
        # Hash (0.40) + Content >50 (0.15) + Semantic (0.50 * 0.30 = 0.15) = 0.70 -> HIGH
        self.assertGreaterEqual(res.score, 0.65)
        self.assertEqual(res.severity, "HIGH")

    def test_g_multiple_strong_signals_critical(self):
        """G — Multiple strong signals: hash mismatch + metadata + content + high drift -> CRITICAL."""
        ev = [
            ChangeEvidence(evidence_type="MetadataAnalysis", description="File permissions updated: 0600 -> 0777", confidence=1.0),
            ChangeEvidence(evidence_type="StructureAnalysis", description="Structure changed", value="JSON keys altered: 5 removed", confidence=1.0),
            ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 120, Deletions: 40", confidence=1.0)
        ]
        sem = SemanticResult(
            status="AVAILABLE",
            semantic_similarity=-0.40,
            semantic_drift=0.90,
            analysis_method="sentence_transformer",
            confidence=0.90
        )
        res = self.risk_engine.evaluate(
            file_path="/etc/auth_config.json",
            change_type="MODIFIED",
            hash_mismatch=True,
            evidence=ev,
            semantic_result=sem
        )
        # Hash (0.40) + Meta/Struct (0.08 + 0.07 = 0.15) + Content (0.15) + Semantic (0.90 * 0.30 = 0.27) = 0.97 -> CRITICAL
        self.assertGreaterEqual(res.score, 0.80)
        self.assertEqual(res.severity, "CRITICAL")
        self.assertIn("CRITICAL", res.explanation)

    def test_h_semantic_fallback_provenance(self):
        """H — Semantic fallback: provenance remains visible, discounted contribution, proper confidence."""
        ev = [ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 2", confidence=1.0)]
        sem = SemanticResult(
            status="AVAILABLE",
            semantic_similarity=0.50,
            semantic_drift=0.50,
            analysis_method="fallback",
            confidence=0.60
        )
        res = self.risk_engine.evaluate(
            file_path="/etc/app.conf",
            change_type="MODIFIED",
            hash_mismatch=True,
            evidence=ev,
            semantic_result=sem
        )
        sem_factor = next(f for f in res.factors if f.name == "semantic_impact")
        # Fallback discount: 0.50 * 0.20 = 0.10
        self.assertEqual(sem_factor.contribution, 0.10)
        self.assertIn("fallback", sem_factor.evidence.lower())
        self.assertIn("fallback", res.explanation.lower())

    def test_i_semantic_unavailable_distinguished_from_zero(self):
        """I — Semantic unavailable: risk works from available evidence, no fake zero drift score, confidence penalized."""
        ev = [ChangeEvidence(evidence_type="ContentAnalysis", description="Binary modification detected", confidence=1.0)]
        sem = SemanticResult(
            status="UNAVAILABLE",
            semantic_similarity=None,
            semantic_drift=None,
            explanation="Binary file content cannot undergo semantic analysis."
        )
        res = self.risk_engine.evaluate(
            file_path="/usr/bin/daemon",
            change_type="MODIFIED",
            hash_mismatch=True,
            evidence=ev,
            semantic_result=sem
        )
        # Hash (0.40) + Binary Content (0.12) = 0.52 -> MEDIUM
        self.assertEqual(res.severity, "MEDIUM")
        self.assertEqual(res.score, 0.52)
        sem_factor = next(f for f in res.factors if f.name == "semantic_impact")
        self.assertEqual(sem_factor.contribution, 0.0)
        self.assertIn("unavailable", sem_factor.rationale.lower())
        self.assertIn("unavailable", res.explanation.lower())
        # Confidence is penalized due to missing semantic visibility
        self.assertLess(res.confidence, 0.75)

    def test_j_determinism(self):
        """J — Determinism: identical evidence produces identical score, severity, factors, and explanation."""
        ev = [
            ChangeEvidence(evidence_type="MetadataAnalysis", description="File permissions updated", confidence=1.0),
            ChangeEvidence(evidence_type="ContentAnalysis", description="Content changed", value="Additions: 5", confidence=1.0)
        ]
        sem = SemanticResult(
            status="AVAILABLE",
            semantic_similarity=0.80,
            semantic_drift=0.20,
            analysis_method="sentence_transformer",
            confidence=0.90
        )
        results = [
            self.risk_engine.evaluate("/test.txt", "MODIFIED", True, ev, sem)
            for _ in range(5)
        ]
        first = results[0].model_dump()
        for r in results[1:]:
            self.assertEqual(r.model_dump(), first)

    def test_k_api_compatibility(self):
        """K — API compatibility: ScoredChange and InvestigationInput serialize and validate with risk_assessment."""
        risk = RiskResult(
            score=0.45,
            severity="MEDIUM",
            factors=[RiskFactor(name="cryptographic_integrity", contribution=0.40, evidence="Hash mismatch", rationale="Baseline violated.")],
            explanation="Risk is classified as MEDIUM.",
            confidence=0.85
        )
        change = ScoredChange(
            file_path="/etc/passwd",
            change_type="MODIFIED",
            old_hash="aaa",
            new_hash="bbb",
            criticality="Critical",
            risk_assessment=risk,
            evidence=[]
        )
        inp = InvestigationInput(scan_id="SCAN-STAGE4", changes=[change])
        dumped = inp.model_dump()
        self.assertIn("risk_assessment", dumped["changes"][0])
        self.assertEqual(dumped["changes"][0]["risk_assessment"]["severity"], "MEDIUM")
        self.assertEqual(dumped["changes"][0]["risk_assessment"]["score"], 0.45)

    def test_l_end_to_end_pipeline_integration(self):
        """L — End-to-end integration: Stage 1 + 2 + 3 + 4 pipeline runs without recalculating upstream data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = os.path.join(tmpdir, "config.txt")
            with open(fpath, "w") as f:
                f.write("PORT=8080\nTIMEOUT=30")
                
            core_engine = IntegrityEngine()
            core_engine.create_baseline(fpath)
            
            # Modify file
            with open(fpath, "w") as f:
                f.write("PORT=9000\nTIMEOUT=300")
                
            investigation_engine = InvestigationEngine()
            
            integrity = core_engine.check_integrity(fpath)
            change = ScoredChange(
                file_path=fpath,
                change_type="MODIFIED" if integrity.integrity_status == "MODIFIED" else "ADDED",
                old_hash=integrity.baseline_hash,
                new_hash=integrity.current_hash,
                criticality="High",
                evidence=[]
            )
            inp = InvestigationInput(scan_id="E2E-TEST", changes=[change])
            file_contents_map = {fpath: {"old": "PORT=8080\nTIMEOUT=30", "new": "PORT=9000\nTIMEOUT=300"}}
            
            result = investigation_engine.investigate(inp, file_contents_map)
            file_res = result["file_details"][0]
            
            # Verify Stage 1
            self.assertTrue(file_res["hash_mismatch"])
            # Verify Stage 2
            self.assertTrue(any(e["evidence_type"] == "ContentAnalysis" for e in file_res["evidence"]))
            # Verify Stage 3
            self.assertEqual(file_res["semantic_analysis"]["status"], "AVAILABLE")
            # Verify Stage 4
            self.assertIn("risk_assessment", file_res)
            self.assertIn("severity_assessment", file_res)
            self.assertIn(file_res["risk_assessment"]["severity"], ["MEDIUM", "HIGH"])
            self.assertGreater(file_res["risk_assessment"]["score"], 0.35)

if __name__ == '__main__':
    unittest.main()
