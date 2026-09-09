import unittest
import os
import tempfile

from app.investigation.report import FinalInvestigationReport, InvestigationReporter
from app.investigation.fallbackai import TemplateReportGenerator
from app.investigation.investigator import InvestigationEngine
from app.investigation.schemas import ScoredChange, InvestigationInput, SemanticResult, RiskResult, RiskFactor, ChangeEvidence
from app.core.baseline import IntegrityEngine

class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = TemplateReportGenerator()
        self.reporter = InvestigationReporter()

    def test_a_unchanged_file(self):
        """A — Unchanged file: LOW severity, risk score 0.0, clear explanation."""
        inv_res = {
            "scan_id": "SCAN-001",
            "file_details": [{
                "file_path": "/var/log/syslog",
                "change_type": "MODIFIED",
                "hash_status": "Hashes match",
                "hash_mismatch": False,
                "risk_assessment": {"score": 0.0, "severity": "LOW", "confidence": 0.95},
                "evidence": []
            }]
        }
        report = self.generator.generate(inv_res)
        self.assertEqual(report.incident_severity, "LOW")
        self.assertEqual(report.risk_score, 0.0)
        self.assertIn("/var/log/syslog", report.affected_files)

    def test_b_metadata_only_change(self):
        """B — Metadata-only change: reflects metadata, no false drift claims."""
        inv_res = {
            "scan_id": "SCAN-002",
            "file_details": [{
                "file_path": "/etc/shadow",
                "change_type": "MODIFIED",
                "hash_status": "Hashes match",
                "hash_mismatch": False,
                "evidence": [{"evidence_type": "MetadataAnalysis", "description": "File permissions changed: 0600 -> 0644"}],
                "semantic_analysis": {"status": "NOT_REQUIRED", "explanation": "Metadata modification detected; content unchanged."},
                "risk_assessment": {"score": 0.13, "severity": "LOW", "confidence": 0.90}
            }]
        }
        report = self.generator.generate(inv_res)
        self.assertEqual(report.incident_severity, "LOW")
        self.assertEqual(report.risk_score, 0.13)
        self.assertTrue(any("Audit filesystem permissions" in r for r in report.recommended_actions))

    def test_c_content_modification(self):
        """C — Content modification: captures content changes in key findings and ledger."""
        inv_res = {
            "scan_id": "SCAN-003",
            "file_details": [{
                "file_path": "/var/www/index.html",
                "change_type": "MODIFIED",
                "hash_status": "Hash mismatch detected",
                "hash_mismatch": True,
                "evidence": [{"evidence_type": "ContentAnalysis", "description": "Content changed", "value": "Additions: 5"}],
                "risk_assessment": {"score": 0.45, "severity": "MEDIUM", "confidence": 0.85}
            }]
        }
        report = self.generator.generate(inv_res)
        self.assertEqual(report.incident_severity, "MEDIUM")
        self.assertEqual(report.risk_score, 0.45)
        self.assertTrue(len(report.evidence_ledger) > 0)
        self.assertEqual(report.evidence_ledger[0]["file_path"], "/var/www/index.html")

    def test_d_semantic_available(self):
        """D — Semantic available: includes dense semantic embedding drift in findings and executive summary."""
        inv_res = {
            "scan_id": "SCAN-004",
            "file_details": [{
                "file_path": "/app/config.py",
                "change_type": "MODIFIED",
                "hash_status": "Hash mismatch detected",
                "hash_mismatch": True,
                "semantic_drift_score": 0.35,
                "semantic_analysis": {
                    "status": "AVAILABLE",
                    "semantic_drift": 0.35,
                    "analysis_method": "sentence_transformer",
                    "explanation": "Moderate semantic shift."
                },
                "risk_assessment": {"score": 0.60, "severity": "HIGH", "confidence": 0.90}
            }]
        }
        report = self.generator.generate(inv_res)
        self.assertEqual(report.incident_severity, "HIGH")
        self.assertTrue(any("[SEMANTIC]" in f for f in report.key_findings))
        self.assertIn("semantic content drift", report.executive_summary)

    def test_e_semantic_fallback(self):
        """E — Semantic fallback: provenance transparently disclosed in findings and limitations."""
        inv_res = {
            "scan_id": "SCAN-005",
            "file_details": [{
                "file_path": "/app/routes.py",
                "change_type": "MODIFIED",
                "hash_status": "Hash mismatch detected",
                "hash_mismatch": True,
                "semantic_analysis": {
                    "status": "AVAILABLE",
                    "semantic_drift": 0.25,
                    "analysis_method": "fallback",
                    "explanation": "Sequence similarity fallback."
                },
                "risk_assessment": {"score": 0.45, "severity": "MEDIUM", "confidence": 0.70}
            }]
        }
        report = self.generator.generate(inv_res)
        self.assertTrue(any("fallback" in f.lower() for f in report.key_findings))
        self.assertTrue(any("fallback" in l.lower() for l in report.limitations))

    def test_f_semantic_unavailable(self):
        """F — Semantic unavailable: disclosed in findings and limitations, recommends manual review."""
        inv_res = {
            "scan_id": "SCAN-006",
            "file_details": [{
                "file_path": "/usr/bin/binary_exec",
                "change_type": "MODIFIED",
                "hash_status": "Hash mismatch detected",
                "hash_mismatch": True,
                "semantic_analysis": {"status": "UNAVAILABLE", "explanation": "Binary content."},
                "risk_assessment": {"score": 0.52, "severity": "MEDIUM", "confidence": 0.60}
            }]
        }
        report = self.generator.generate(inv_res)
        self.assertTrue(any("unavailable" in f.lower() for f in report.key_findings))
        self.assertTrue(any("manual content review" in r.lower() for r in report.recommended_actions))
        self.assertTrue(any("unavailable" in l.lower() for l in report.limitations))

    def test_g_high_risk_report(self):
        """G — HIGH risk report: recommendations emphasize prioritized investigation."""
        inv_res = {
            "scan_id": "SCAN-007",
            "file_details": [{
                "file_path": "/etc/sudoers",
                "change_type": "MODIFIED",
                "hash_status": "Hash mismatch detected",
                "hash_mismatch": True,
                "risk_assessment": {"score": 0.75, "severity": "HIGH", "confidence": 0.90}
            }]
        }
        report = self.generator.generate(inv_res)
        self.assertEqual(report.incident_severity, "HIGH")
        self.assertTrue(any("Prioritize investigation" in r for r in report.recommended_actions))

    def test_h_critical_risk_report(self):
        """H — CRITICAL risk report: severity CRITICAL and high risk score."""
        inv_res = {
            "scan_id": "SCAN-008",
            "file_details": [{
                "file_path": "/boot/kernel.img",
                "change_type": "MODIFIED",
                "hash_status": "Hash mismatch detected",
                "hash_mismatch": True,
                "risk_assessment": {"score": 0.95, "severity": "CRITICAL", "confidence": 0.95}
            }]
        }
        report = self.generator.generate(inv_res)
        self.assertEqual(report.incident_severity, "CRITICAL")
        self.assertEqual(report.risk_score, 0.95)

    def test_i_deterministic_recommendations(self):
        """I — Deterministic recommendations: same inputs produce identical recommendations."""
        inv_res = {
            "scan_id": "SCAN-009",
            "file_details": [
                {"file_path": "/file_a", "hash_status": "mismatch", "risk_assessment": {"severity": "HIGH"}},
                {"file_path": "/file_b", "hash_status": "mismatch", "risk_assessment": {"severity": "LOW"}}
            ]
        }
        r1 = self.generator.generate(inv_res).recommended_actions
        r2 = self.generator.generate(inv_res).recommended_actions
        self.assertEqual(r1, r2)

    def test_j_deterministic_report(self):
        """J — Deterministic report: identical outputs except generated_at."""
        inv_res = {
            "scan_id": "SCAN-010",
            "file_details": [{
                "file_path": "/etc/pam.d/common-auth",
                "change_type": "MODIFIED",
                "hash_status": "Hash mismatch detected",
                "hash_mismatch": True,
                "semantic_drift_score": 0.40,
                "risk_assessment": {"score": 0.65, "severity": "HIGH", "confidence": 0.90}
            }]
        }
        r1 = self.generator.generate(inv_res).model_dump()
        r2 = self.generator.generate(inv_res).model_dump()
        del r1["generated_at"]
        del r2["generated_at"]
        self.assertEqual(r1, r2)

    def test_k_multi_file_report(self):
        """K — Multi-file report: aggregates affected files and takes max severity/risk."""
        inv_res = {
            "scan_id": "SCAN-011",
            "file_details": [
                {"file_path": "/etc/hosts", "change_type": "MODIFIED", "hash_status": "Hashes match", "risk_assessment": {"score": 0.05, "severity": "LOW"}},
                {"file_path": "/etc/passwd", "change_type": "MODIFIED", "hash_status": "Hash mismatch detected", "risk_assessment": {"score": 0.72, "severity": "HIGH"}},
                {"file_path": "/etc/issue", "change_type": "MODIFIED", "hash_status": "Hash mismatch detected", "risk_assessment": {"score": 0.40, "severity": "MEDIUM"}}
            ]
        }
        report = self.generator.generate(inv_res)
        self.assertEqual(len(report.affected_files), 3)
        self.assertEqual(report.incident_severity, "HIGH")
        self.assertEqual(report.risk_score, 0.72)
        self.assertEqual(len(report.evidence_ledger), 3)

    def test_l_backward_compatibility(self):
        """L — Backward compatibility: all original fields are present and typed."""
        inv_res = {"scan_id": "SCAN-012", "file_details": []}
        report = self.generator.generate(inv_res)
        self.assertTrue(hasattr(report, "scan_id"))
        self.assertTrue(hasattr(report, "generation_method"))
        self.assertTrue(hasattr(report, "executive_summary"))
        self.assertTrue(hasattr(report, "incident_severity"))
        self.assertTrue(hasattr(report, "key_findings"))
        self.assertTrue(hasattr(report, "evidence_analysis"))
        self.assertTrue(hasattr(report, "affected_files"))
        self.assertTrue(hasattr(report, "possible_causes"))
        self.assertTrue(hasattr(report, "confidence_assessment"))
        self.assertTrue(hasattr(report, "recommended_actions"))

    def test_m_full_pipeline_to_report_integration(self):
        """M — Full Stage 1 -> Stage 5 integration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = os.path.join(tmpdir, "service.conf")
            with open(fpath, "w") as f:
                f.write("status = active\nretries = 3")
                
            core = IntegrityEngine()
            core.create_baseline(fpath)
            
            with open(fpath, "w") as f:
                f.write("status = inactive\nretries = 9999")
                
            investigator = InvestigationEngine()
            check = core.check_integrity(fpath)
            change = ScoredChange(
                file_path=fpath,
                change_type="MODIFIED",
                old_hash=check.baseline_hash,
                new_hash=check.current_hash,
                criticality="High",
                evidence=[]
            )
            inp = InvestigationInput(scan_id="SCAN-E2E-5", changes=[change])
            inv_res = investigator.investigate(inp, {fpath: {"old": "status = active\nretries = 3", "new": "status = inactive\nretries = 9999"}})
            
            final_report = self.reporter.generate_report(inv_res)
            self.assertIn(final_report.incident_severity, ["MEDIUM", "HIGH"])
            self.assertGreater(final_report.risk_score, 0.35)
            self.assertEqual(len(final_report.affected_files), 1)
            self.assertTrue(len(final_report.key_findings) > 0)
            self.assertTrue(len(final_report.evidence_ledger) > 0)
            self.assertTrue(len(final_report.limitations) > 0)

if __name__ == '__main__':
    unittest.main()
