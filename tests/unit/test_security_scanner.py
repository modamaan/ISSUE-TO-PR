"""Unit tests for the security scanner module."""

from __future__ import annotations

from shared.verdict import Severity
from tools.security_scanner import scan_content_regex, scan_diff_regex


class TestScanDiffRegex:
    """Tests for scan_diff_regex — diff-aware scanning."""

    def test_detects_sql_injection_concatenation(self):
        diff = (
            '+++ b/db.py\n'
            '@@ -1,4 +1,5 @@\n'
            '+    query = "SELECT * FROM users WHERE id = " + user_id\n'
        )
        findings = scan_diff_regex(diff)
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("SQL injection" in f.message for f in findings)

    def test_detects_sql_injection_fstring(self):
        diff = (
            '+++ b/api.py\n'
            '@@ -1,3 +1,4 @@\n'
            '+    sql = f"SELECT * FROM users WHERE name = {name}"\n'
        )
        findings = scan_diff_regex(diff)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_hardcoded_password(self):
        diff = (
            '+++ b/config.py\n'
            '@@ -1,3 +1,4 @@\n'
            '+password = "supersecretpassword123"\n'
        )
        findings = scan_diff_regex(diff)
        assert any(f.severity == Severity.HIGH for f in findings)
        assert any("credential" in f.message.lower() for f in findings)

    def test_detects_aws_key(self):
        diff = (
            '+++ b/deploy.py\n'
            '@@ -1,3 +1,4 @@\n'
            '+AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        )
        findings = scan_diff_regex(diff)
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("AWS" in f.message for f in findings)

    def test_detects_command_injection(self):
        diff = (
            '+++ b/utils.py\n'
            '@@ -1,3 +1,4 @@\n'
            '+    os.system("rm -rf " + user_input)\n'
        )
        findings = scan_diff_regex(diff)
        assert any("Command injection" in f.message for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_detects_eval_with_variable(self):
        diff = (
            '+++ b/eval_test.py\n'
            '@@ -1,3 +1,4 @@\n'
            '+    result = eval(user_code)\n'
        )
        findings = scan_diff_regex(diff)
        assert any("eval" in f.message.lower() for f in findings)

    def test_ignores_removed_lines(self):
        """Lines starting with '-' (removed in diff) should NOT be scanned."""
        diff = (
            '+++ b/db.py\n'
            '@@ -1,4 +1,3 @@\n'
            '-    query = "SELECT * FROM users WHERE id = " + user_id\n'
            '+    query = "SELECT * FROM users WHERE id = ?"\n'
        )
        findings = scan_diff_regex(diff)
        # The fixed line (parameterized) should not trigger SQL injection
        assert not any(f.severity == Severity.CRITICAL for f in findings)

    def test_no_findings_on_clean_code(self):
        diff = (
            '+++ b/clean.py\n'
            '@@ -1,3 +1,5 @@\n'
            '+def greet(name: str) -> str:\n'
            '+    return f"Hello, {name}!"\n'
        )
        findings = scan_diff_regex(diff)
        assert len(findings) == 0

    def test_file_attribution(self):
        diff = (
            '+++ b/src/auth/login.py\n'
            '@@ -1,3 +1,4 @@\n'
            '+password = "hardcoded123"\n'
        )
        findings = scan_diff_regex(diff)
        assert len(findings) >= 1
        assert findings[0].file == "src/auth/login.py"

    def test_line_attribution(self):
        diff = (
            '+++ b/db.py\n'
            '@@ -10,3 +10,5 @@\n'
            '+pass\n'
            '+pass\n'
            '+    sql = "SELECT * FROM users WHERE id = " + uid\n'
        )
        findings = scan_diff_regex(diff)
        # Should point to line 12 (10 + 2)
        sql_finding = next((f for f in findings if "SQL" in f.message), None)
        assert sql_finding is not None
        assert sql_finding.line == 12


class TestScanContentRegex:
    """Tests for scan_content_regex — full file scanning."""

    def test_detects_multiple_findings_in_one_file(self):
        content = (
            'import hashlib\n'
            'password = "admin123"\n'
            'digest = hashlib.md5(data).hexdigest()\n'
            'conn.execute("SELECT * FROM t WHERE id = " + uid)\n'
        )
        findings = scan_content_regex(content, filename="app.py")
        assert len(findings) >= 3  # password, md5, SQL

    def test_filename_passed_through(self):
        content = 'password = "secret"\n'
        findings = scan_content_regex(content, filename="config/settings.py")
        assert all(f.file == "config/settings.py" for f in findings)

    def test_debug_true_detected(self):
        content = "DEBUG = True\n"
        findings = scan_content_regex(content)
        assert any("Debug" in f.message or "debug" in f.message.lower() for f in findings)

    def test_pickle_detected(self):
        content = "data = pickle.loads(user_data)\n"
        findings = scan_content_regex(content)
        assert any("pickle" in f.message.lower() for f in findings)

    def test_private_key_detected(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...\n"
        findings = scan_content_regex(content)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_auto_fixable_flags(self):
        content = 'password = "test123"\n'
        findings = scan_content_regex(content)
        assert any(f.auto_fixable for f in findings)
