import os
import tempfile
import unittest
import json

from app.investigation.schemas import InvestigationInput, ScoredChange
from app.investigation.investigator import InvestigationEngine
from app.investigation.compat import IntegrityEngine


class TestInvestigationEngine(unittest.TestCase):
    def setUp(self):
        self.investigation_engine = InvestigationEngine()
        self.core_engine = IntegrityEngine()
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_file(self, filename, content, binary=False):
        fpath = os.path.join(self.temp_dir.name, filename)
        mode = "wb" if binary else "w"
        with open(fpath, mode) as f:
            f.write(content)
        return fpath

    def _run_pipeline(self, fpath, old_content=None, new_content=None):
        integrity = self.core_engine.check_integrity(fpath)
        change = ScoredChange(
            file_path=fpath,
            change_type="MODIFIED" if integrity.integrity_status == "MODIFIED" else "ADDED",
            old_hash=integrity.baseline_hash,
            new_hash=integrity.current_hash,
            criticality="Medium",
            evidence=[]
        )
        inp = InvestigationInput(scan_id="TEST", changes=[change])
        file_contents_map = {fpath: {"old": old_content, "new": new_content}}
        return self.investigation_engine.investigate(inp, file_contents_map)

    def test_b_metadata_only_modification(self):
        # A: Unchanged covered by default
        fpath = self._create_file("meta.txt", "same content")
        self.core_engine.create_baseline(fpath)
        
        # Modify mtime safely
        os.utime(fpath, (100, 100))
        
        res = self._run_pipeline(fpath, "same content", "same content")
        ev = res["file_details"][0]["evidence"]
        
        # Should have MetadataAnalysis but NO Content changes (content unchanged)
        has_meta = any(e["evidence_type"] == "MetadataAnalysis" for e in ev)
        has_content_diff = any(e["evidence_type"] == "ContentAnalysis" and "Additions" in (e.get("value") or "") for e in ev)
        self.assertTrue(has_meta)
        self.assertFalse(has_content_diff)

    def test_c_text_content_modification(self):
        fpath = self._create_file("text.txt", "line 1\nline 2")
        self.core_engine.create_baseline(fpath)
        
        self._create_file("text.txt", "line 1\nline 2\nline 3")
        
        res = self._run_pipeline(fpath, "line 1\nline 2", "line 1\nline 2\nline 3")
        ev = res["file_details"][0]["evidence"]
        
        has_diff = any(e["evidence_type"] == "ContentAnalysis" and "Additions: 1" in (e.get("value") or "") for e in ev)
        self.assertTrue(has_diff)

    def test_d_binary_file_modification(self):
        fpath = self._create_file("bin.dat", b'\x00\x01\x02', binary=True)
        self.core_engine.create_baseline(fpath)
        
        self._create_file("bin.dat", b'\x00\x01\x02\x03', binary=True)
        res = self._run_pipeline(fpath)
        ev = res["file_details"][0]["evidence"]
        
        has_bin = any("Binary modification detected" in e["description"] for e in ev)
        self.assertTrue(has_bin)

    def test_e_structure_parsing(self):
        fpath = self._create_file("config.json", '{"key": "value", "key2": "value2"}')
        self.core_engine.create_baseline(fpath)
        
        res = self._run_pipeline(fpath)
        ev = res["file_details"][0]["evidence"]
        has_struct = any(e["evidence_type"] == "StructureAnalysis" and "Root element count: 2" in (e.get("value") or "") for e in ev)
        self.assertTrue(has_struct)

    def test_f_unsupported_structure(self):
        fpath = self._create_file("unknown.xyz", "plain text")
        res = self._run_pipeline(fpath)
        ev = res["file_details"][0]["evidence"]
        has_unsupported = any("Unsupported analysis explicitly reported" in e["description"] for e in ev)
        self.assertTrue(has_unsupported)

    def test_g_detector_failure_does_not_crash(self):
        # Pass a missing file. Detectors should catch it and return safely without crashing.
        fpath = os.path.join(self.temp_dir.name, "missing.txt")
        res = self._run_pipeline(fpath)
        ev = res["file_details"][0]["evidence"]
        has_missing_meta = any("file does not exist" in e["description"] for e in ev)
        self.assertTrue(has_missing_meta)

if __name__ == '__main__':
    unittest.main()
