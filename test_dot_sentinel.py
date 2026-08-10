#!/usr/bin/env python3
"""Tests for Dot_Sentinel — .env security scanner."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "dot_sentinel.py"


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True, text=True
    )


class TestScan(unittest.TestCase):
    def test_detect_aws_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("DATABASE_URL=postgres://localhost/db\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
            f.flush()
            path = f.name
        try:
            result = _run("scan", path)
            self.assertEqual(result.returncode, 0)
            self.assertIn("AWS Access Key", result.stdout)
            self.assertNotIn("DATABASE_URL", result.stdout)
        finally:
            os.unlink(path)

    def test_detect_github_token(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef123456\n")
            f.flush()
            path = f.name
        try:
            result = _run("scan", path)
            self.assertEqual(result.returncode, 0)
            self.assertIn("GitHub Token (classic)", result.stdout)
        finally:
            os.unlink(path)

    def test_detect_stripe_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("STRIPE_KEY=sk_live_fake_test_key_12345\n")
            f.flush()
            path = f.name
        try:
            result = _run("scan", path)
            self.assertEqual(result.returncode, 0)
            self.assertIn("Stripe Live Secret", result.stdout)
        finally:
            os.unlink(path)

    def test_detect_jwt(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("AUTH_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n")
            f.flush()
            path = f.name
        try:
            result = _run("scan", path)
            self.assertEqual(result.returncode, 0)
            self.assertIn("JWT Token", result.stdout)
        finally:
            os.unlink(path)

    def test_detect_private_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("PRIV_KEY=-----BEGIN RSA PRIVATE KEY-----\n")
            f.flush()
            path = f.name
        try:
            result = _run("scan", path)
            self.assertEqual(result.returncode, 0)
            self.assertIn("Private Key", result.stdout)
        finally:
            os.unlink(path)

    def test_no_false_positives(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("APP_NAME=MyApp\nPORT=3000\nHOST=localhost\n")
            f.flush()
            path = f.name
        try:
            result = _run("scan", "--format", "json", path)
            self.assertEqual(result.returncode, 0)
            data = json.loads(result.stdout)
            self.assertEqual(data["findings_count"], 0)
        finally:
            os.unlink(path)

    def test_json_format(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
            f.flush()
            path = f.name
        try:
            result = _run("scan", "--format", "json", path)
            self.assertEqual(result.returncode, 0)
            data = json.loads(result.stdout)
            self.assertIn("findings", data)
        finally:
            os.unlink(path)

    def test_high_entropy(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("RANDOM=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\n")
            f.flush()
            path = f.name
        try:
            result = _run("scan", "--high-entropy", "--format", "json", path)
            self.assertEqual(result.returncode, 0)
            data = json.loads(result.stdout)
            # The entropy of this should be > 4.5
            self.assertGreater(len(data["findings"]), 0)
        finally:
            os.unlink(path)

    def test_custom_patterns(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("CUSTOM_TOKEN=ct_abcdef1234567890\n")
            f.flush()
            env_path = f.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as pf:
            pf.write("CustomToken: ct_[a-z0-9]{16}\n")
            pf.flush()
            pat_path = pf.name
        try:
            result = _run("scan", "--patterns", pat_path, "--format", "json", env_path)
            self.assertEqual(result.returncode, 0)
            data = json.loads(result.stdout)
            self.assertIn("CustomToken", [f["type"] for f in data["findings"]])
        finally:
            os.unlink(env_path)
            os.unlink(pat_path)

    def test_file_not_found(self):
        result = _run("scan", "/nonexistent/file.env")
        self.assertNotEqual(result.returncode, 0)


class TestCompare(unittest.TestCase):
    def test_compare_added_and_removed(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f1:
            f1.write("A=1\nB=2\nC=3\n")
            f1.flush()
            env1 = f1.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f2:
            f2.write("B=2\nC=3\nD=4\n")
            f2.flush()
            env2 = f2.name
        try:
            result = _run("compare", "--format", "json", env1, env2)
            self.assertEqual(result.returncode, 0)
            data = json.loads(result.stdout)
            self.assertEqual(data["added_keys"], ["D"])
            self.assertEqual(data["removed_keys"], ["A"])
            self.assertEqual(data["changed_keys"], [])
        finally:
            os.unlink(env1)
            os.unlink(env2)

    def test_compare_changed(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f1:
            f1.write("A=hello\n")
            f1.flush()
            env1 = f1.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f2:
            f2.write("A=world\n")
            f2.flush()
            env2 = f2.name
        try:
            result = _run("compare", "--format", "json", env1, env2)
            self.assertEqual(result.returncode, 0)
            data = json.loads(result.stdout)
            self.assertEqual(data["changed_keys"], ["A"])
        finally:
            os.unlink(env1)
            os.unlink(env2)

    def test_compare_text_format(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f1:
            f1.write("A=1\n")
            f1.flush()
            env1 = f1.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f2:
            f2.write("A=1\nB=2\n")
            f2.flush()
            env2 = f2.name
        try:
            result = _run("compare", env1, env2)
            self.assertEqual(result.returncode, 0)
            self.assertIn("added_keys", result.stdout)
        finally:
            os.unlink(env1)
            os.unlink(env2)


class TestTemplate(unittest.TestCase):
    def test_template_extracts_keys(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("# Database config\nDATABASE_URL=postgres://localhost/db\n# App config\nAPP_NAME=MyApp\nPORT=3000\n")
            f.flush()
            path = f.name
        try:
            result = _run("template", "--format", "json", path)
            self.assertEqual(result.returncode, 0)
            data = json.loads(result.stdout)
            self.assertIn("DATABASE_URL", data["keys"])
            self.assertIn("APP_NAME", data["keys"])
            self.assertIn("PORT", data["keys"])
            self.assertIn("DATABASE_URL=", data["template"])
            self.assertIn("# Database config", data["template"])
            self.assertNotIn("postgres://localhost/db", data["template"])
        finally:
            os.unlink(path)

    def test_template_text_format(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("KEY=value\n")
            f.flush()
            path = f.name
        try:
            result = _run("template", path)
            self.assertEqual(result.returncode, 0)
            self.assertIn("KEY=", result.stdout)
        finally:
            os.unlink(path)


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_audit_finds_env_files(self):
        root = Path(self.tmpdir.name)
        (root / ".env").write_text("A=1\n")
        (root / "sub").mkdir()
        (root / "sub" / ".env.local").write_text("B=2\n")
        (root / ".gitignore").write_text(".env.local\n")

        result = _run("audit", "--format", "json", str(root))
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["files_scanned"], 2)
        for f in data["files"]:
            fn = f["file"].replace("\\", "/")
            if fn.endswith(".env.local"):
                self.assertTrue(f["gitignored"], f"Expected {fn} to be gitignored")
            elif fn == ".env":
                self.assertFalse(f["gitignored"])

    def test_audit_detects_secrets(self):
        root = Path(self.tmpdir.name)
        (root / ".env").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        result = _run("audit", "--format", "json", str(root))
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertTrue(data["files"][0]["has_secrets"])

    def test_audit_directory_not_found(self):
        result = _run("audit", "/nonexistent")
        self.assertNotEqual(result.returncode, 0)


class TestMask(unittest.TestCase):
    def test_mask_replaces_values(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("# Config\nSECRET=abc123\nHOST=localhost\n")
            f.flush()
            path = f.name
        try:
            result = _run("mask", path)
            self.assertEqual(result.returncode, 0)
            self.assertIn("***", result.stdout)
            self.assertNotIn("abc123", result.stdout)
            self.assertNotIn("localhost", result.stdout)
            self.assertIn("# Config", result.stdout)
            self.assertIn("SECRET=", result.stdout)
        finally:
            os.unlink(path)

    def test_mask_json_format(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("KEY=val\n")
            f.flush()
            path = f.name
        try:
            result = _run("mask", "--format", "json", path)
            self.assertEqual(result.returncode, 0)
            data = json.loads(result.stdout)
            self.assertIn("masked", data)
        finally:
            os.unlink(path)

    def test_mask_file_not_found(self):
        result = _run("mask", "/nonexistent")
        self.assertNotEqual(result.returncode, 0)


class TestHelp(unittest.TestCase):
    def test_help(self):
        result = _run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("scan", result.stdout)
        self.assertIn("compare", result.stdout)
        self.assertIn("template", result.stdout)
        self.assertIn("audit", result.stdout)
        self.assertIn("mask", result.stdout)


if __name__ == "__main__":
    unittest.main()
