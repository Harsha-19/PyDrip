import os
import tempfile
import unittest
import stat
from app.investigation.compat import FileHasher, IntegrityEngine


class TestCoreIntegrity(unittest.TestCase):
    def setUp(self):
        self.engine = IntegrityEngine()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(self.temp_dir.name, "test.txt")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_a_new_file(self):
        with open(self.test_file, "w") as f:
            f.write("Hello, World!")
        
        hasher = FileHasher()
        res = hasher.hash_file(self.test_file)
        self.assertTrue(res["success"])
        self.assertIsNotNone(res["sha256"])

    def test_b_same_file(self):
        with open(self.test_file, "w") as f:
            f.write("unchanged content")
            
        res_baseline = self.engine.create_baseline(self.test_file)
        self.assertEqual(res_baseline.integrity_status, "UNCHANGED")
        
        res_check = self.engine.check_integrity(self.test_file)
        self.assertEqual(res_check.integrity_status, "UNCHANGED")

    def test_c_modified_file(self):
        with open(self.test_file, "w") as f:
            f.write("original content")
            
        self.engine.create_baseline(self.test_file)
        
        with open(self.test_file, "w") as f:
            f.write("modified content")
            
        res_check = self.engine.check_integrity(self.test_file)
        self.assertEqual(res_check.integrity_status, "MODIFIED")

    def test_d_empty_file(self):
        open(self.test_file, "w").close()
        
        res = self.engine.create_baseline(self.test_file)
        self.assertEqual(res.integrity_status, "UNCHANGED")
        self.assertEqual(res.file.size, 0)
        self.assertIsNotNone(res.current_hash) # e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

    def test_e_large_file(self):
        # Write slightly more than 64KB to test chunking
        with open(self.test_file, "wb") as f:
            f.write(os.urandom(70000))
            
        res = self.engine.create_baseline(self.test_file)
        self.assertTrue(res.integrity_status, "UNCHANGED")
        self.assertEqual(res.file.size, 70000)

    def test_f_missing_file(self):
        res = self.engine.create_baseline("does_not_exist.txt")
        self.assertEqual(res.integrity_status, "ERROR")
        self.assertTrue("does not exist" in res.error_message)

    def test_g_permission_failure(self):
        with open(self.test_file, "w") as f:
            f.write("secret")
            
        # Simulate lack of read permissions (Windows can be tricky, but we'll try)
        # Using mock to guarantee cross-platform success for the permission error simulation
        from unittest.mock import patch
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            res = self.engine.create_baseline(self.test_file)
            self.assertEqual(res.integrity_status, "ERROR")
            self.assertTrue("permission denied" in res.error_message)

    def test_h_binary_file(self):
        with open(self.test_file, "wb") as f:
            f.write(b'\x00\xFF\xAA\xBB')
            
        res = self.engine.create_baseline(self.test_file)
        self.assertEqual(res.integrity_status, "UNCHANGED")
        self.assertIsNotNone(res.current_hash)

if __name__ == '__main__':
    unittest.main()
