#!/usr/bin/env python3
"""
Test cases for sshcheck - SSH Security Audit Client

These tests verify the functionality of the SSH audit client without
requiring actual SSH connections (uses mocking for network operations).
"""

import json
import os
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch, PropertyMock

import paramiko

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sshcheck import (
    SSHAuditClient,
    ScanResult,
    ScanStatistics,
    HostKeyInfo,
    AlgorithmInfo,
    FingerprintInfo,
    VulnerabilityInfo,
    ColorOutput,
    ProgressBar,
    parse_arguments,
    _parse_version,
    _version_lt,
    _version_gte,
    _version_in_range,
    SSH_VULNERABILITIES,
    SSH_FINGERPRINTS,
    WEAK_KEX_ALGORITHMS,
    WEAK_CIPHERS,
    WEAK_MACS,
    WEAK_HOST_KEY_TYPES,
    __version__,
    __program_name__
)


class TestScanResult(unittest.TestCase):
    """Test cases for ScanResult dataclass."""

    def test_scan_result_creation(self):
        """Test creating a ScanResult with default values."""
        result = ScanResult(
            host="192.168.1.1",
            port=22,
            username="admin",
            password="secret",
            success=True,
            timestamp="2026-01-01T12:00:00"
        )
        self.assertEqual(result.host, "192.168.1.1")
        self.assertEqual(result.port, 22)
        self.assertEqual(result.username, "admin")
        self.assertEqual(result.password, "secret")
        self.assertTrue(result.success)
        self.assertEqual(result.initial_output, "")
        self.assertEqual(result.error_message, "")
        self.assertEqual(result.auth_method, "password")
        self.assertEqual(result.key_file, "")

    def test_scan_result_with_output(self):
        """Test creating a ScanResult with initial output."""
        result = ScanResult(
            host="192.168.1.1",
            port=22,
            username="root",
            password="toor",
            success=True,
            timestamp="2026-01-01T12:00:00",
            initial_output="Welcome to Ubuntu 22.04 LTS",
            banner="SSH-2.0-OpenSSH_8.9"
        )
        self.assertEqual(result.initial_output, "Welcome to Ubuntu 22.04 LTS")
        self.assertEqual(result.banner, "SSH-2.0-OpenSSH_8.9")

    def test_scan_result_with_key_auth(self):
        """Test creating a ScanResult with key authentication."""
        result = ScanResult(
            host="192.168.1.1",
            port=22,
            username="admin",
            password="",
            success=True,
            timestamp="2026-01-01T12:00:00",
            auth_method="key",
            key_file="/home/user/.ssh/id_rsa"
        )
        self.assertEqual(result.auth_method, "key")
        self.assertEqual(result.key_file, "/home/user/.ssh/id_rsa")

    def test_scan_result_to_dict(self):
        """Test converting ScanResult to dictionary."""
        result = ScanResult(
            host="10.0.0.1",
            port=2222,
            username="user",
            password="pass",
            success=False,
            timestamp="2026-01-01T12:00:00",
            error_message="Connection refused"
        )
        data = result.to_dict()
        self.assertIsInstance(data, dict)
        self.assertEqual(data['host'], "10.0.0.1")
        self.assertEqual(data['port'], 2222)
        self.assertFalse(data['success'])
        self.assertEqual(data['error_message'], "Connection refused")
        self.assertEqual(data['auth_method'], "password")

    def test_scan_result_to_dict_key_auth_hides_password(self):
        """Test that key auth results hide password in dict."""
        result = ScanResult(
            host="10.0.0.1",
            port=22,
            username="user",
            password="passphrase",
            success=True,
            timestamp="2026-01-01T12:00:00",
            auth_method="key",
            key_file="/home/user/.ssh/id_rsa"
        )
        data = result.to_dict()
        self.assertEqual(data['password'], '')
        self.assertEqual(data['auth_method'], 'key')

    def test_scan_result_to_dict_with_extended_info(self):
        """Test converting ScanResult with extended info to dictionary."""
        result = ScanResult(
            host="10.0.0.1",
            port=22,
            username="user",
            password="pass",
            success=True,
            timestamp="2026-01-01T12:00:00",
            host_key_info=HostKeyInfo(
                key_type="ssh-ed25519",
                key_bits=256,
                fingerprint_sha256="SHA256:abc123",
                fingerprint_md5="MD5:aa:bb:cc"
            ),
            fingerprint_info=FingerprintInfo(
                software="OpenSSH",
                software_version="8.9p1",
                os_guess="Ubuntu Linux"
            ),
            vulnerabilities=[
                VulnerabilityInfo(
                    cve="CVE-2023-48795",
                    name="Terrapin Attack",
                    severity="MEDIUM"
                )
            ]
        )
        data = result.to_dict()
        self.assertIn('host_key_info', data)
        self.assertEqual(data['host_key_info']['key_type'], 'ssh-ed25519')
        self.assertIn('fingerprint_info', data)
        self.assertEqual(data['fingerprint_info']['software'], 'OpenSSH')
        self.assertIn('vulnerabilities', data)
        self.assertEqual(len(data['vulnerabilities']), 1)
        self.assertEqual(data['vulnerabilities'][0]['cve'], 'CVE-2023-48795')


class TestScanStatistics(unittest.TestCase):
    """Test cases for ScanStatistics dataclass."""

    def test_statistics_default_values(self):
        """Test default statistics values."""
        stats = ScanStatistics()
        self.assertEqual(stats.total_attempts, 0)
        self.assertEqual(stats.successful_logins, 0)
        self.assertEqual(stats.failed_logins, 0)
        self.assertEqual(stats.connection_errors, 0)
        self.assertIsNone(stats.start_time)
        self.assertIsNone(stats.end_time)

    def test_statistics_duration_calculation(self):
        """Test duration calculation."""
        from datetime import datetime, timedelta
        stats = ScanStatistics()
        stats.start_time = datetime(2026, 1, 1, 12, 0, 0)
        stats.end_time = datetime(2026, 1, 1, 12, 1, 30)
        self.assertEqual(stats.get_duration(), 90.0)

    def test_statistics_duration_no_times(self):
        """Test duration with no start/end times."""
        stats = ScanStatistics()
        self.assertEqual(stats.get_duration(), 0.0)


class TestHostKeyInfo(unittest.TestCase):
    """Test cases for HostKeyInfo dataclass."""

    def test_host_key_info_creation(self):
        """Test creating HostKeyInfo."""
        info = HostKeyInfo(
            key_type="ssh-ed25519",
            key_bits=256,
            fingerprint_sha256="SHA256:abc123",
            fingerprint_md5="MD5:aa:bb:cc"
        )
        self.assertEqual(info.key_type, "ssh-ed25519")
        self.assertEqual(info.key_bits, 256)

    def test_host_key_info_to_dict(self):
        """Test HostKeyInfo to dict conversion."""
        info = HostKeyInfo(key_type="ssh-rsa", key_bits=4096)
        d = info.to_dict()
        self.assertEqual(d['key_type'], 'ssh-rsa')
        self.assertEqual(d['key_bits'], 4096)


class TestAlgorithmInfo(unittest.TestCase):
    """Test cases for AlgorithmInfo dataclass."""

    def test_algorithm_info_creation(self):
        """Test creating AlgorithmInfo."""
        info = AlgorithmInfo(
            kex_algorithms=["curve25519-sha256"],
            ciphers=["aes256-gcm@openssh.com"],
            macs=["hmac-sha2-256"],
            host_key_types=["ssh-ed25519"]
        )
        self.assertEqual(len(info.kex_algorithms), 1)
        self.assertEqual(len(info.weak_kex), 0)

    def test_algorithm_info_to_dict(self):
        """Test AlgorithmInfo to dict conversion."""
        info = AlgorithmInfo(
            weak_ciphers=[{"algorithm": "arcfour", "reason": "RC4 is broken"}]
        )
        d = info.to_dict()
        self.assertIn('weak_ciphers', d)
        self.assertEqual(len(d['weak_ciphers']), 1)


class TestFingerprintInfo(unittest.TestCase):
    """Test cases for FingerprintInfo dataclass."""

    def test_fingerprint_info_creation(self):
        """Test creating FingerprintInfo."""
        info = FingerprintInfo(
            software="OpenSSH",
            software_version="8.9p1",
            os_guess="Ubuntu Linux",
            raw_banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
        )
        self.assertEqual(info.software, "OpenSSH")
        self.assertEqual(info.os_guess, "Ubuntu Linux")

    def test_fingerprint_info_to_dict(self):
        """Test FingerprintInfo to dict conversion."""
        info = FingerprintInfo(software="Dropbear", software_version="2022.83")
        d = info.to_dict()
        self.assertEqual(d['software'], 'Dropbear')


class TestVulnerabilityInfo(unittest.TestCase):
    """Test cases for VulnerabilityInfo dataclass."""

    def test_vulnerability_info_creation(self):
        """Test creating VulnerabilityInfo."""
        vuln = VulnerabilityInfo(
            cve="CVE-2024-6387",
            name="regreSSHion",
            severity="HIGH",
            affected="OpenSSH 8.5p1 - 9.7p1",
            description="Race condition in signal handler"
        )
        self.assertEqual(vuln.cve, "CVE-2024-6387")
        self.assertEqual(vuln.severity, "HIGH")

    def test_vulnerability_info_to_dict(self):
        """Test VulnerabilityInfo to dict conversion."""
        vuln = VulnerabilityInfo(cve="CVE-2023-48795", name="Terrapin")
        d = vuln.to_dict()
        self.assertEqual(d['cve'], 'CVE-2023-48795')


class TestVersionHelpers(unittest.TestCase):
    """Test cases for version comparison helper functions."""

    def test_parse_version_simple(self):
        """Test parsing simple version strings."""
        self.assertEqual(_parse_version("8.9"), (8, 9))
        self.assertEqual(_parse_version("9.6"), (9, 6))

    def test_parse_version_with_patch(self):
        """Test parsing version with patch level."""
        self.assertEqual(_parse_version("8.9p1"), (8, 9, 1))
        self.assertEqual(_parse_version("9.3p2"), (9, 3, 2))

    def test_parse_version_triple(self):
        """Test parsing triple version."""
        self.assertEqual(_parse_version("0.10.6"), (0, 10, 6))

    def test_parse_version_invalid(self):
        """Test parsing invalid version string."""
        self.assertEqual(_parse_version("invalid"), (0,))

    def test_version_lt(self):
        """Test version less-than comparison."""
        self.assertTrue(_version_lt("7.6", (8, 0)))
        self.assertTrue(_version_lt("8.9p1", (9, 0)))
        self.assertFalse(_version_lt("9.6", (9, 6)))
        self.assertFalse(_version_lt("9.7", (9, 6)))

    def test_version_gte(self):
        """Test version greater-than-or-equal comparison."""
        self.assertTrue(_version_gte("9.6", (9, 6)))
        self.assertTrue(_version_gte("9.7", (9, 6)))
        self.assertFalse(_version_gte("9.5", (9, 6)))

    def test_version_in_range(self):
        """Test version range check."""
        self.assertTrue(_version_in_range("8.9p1", (8, 5), (9, 7)))
        self.assertTrue(_version_in_range("8.5", (8, 5), (9, 7)))
        self.assertFalse(_version_in_range("8.4", (8, 5), (9, 7)))
        self.assertFalse(_version_in_range("9.8", (8, 5), (9, 7)))


class TestColorOutput(unittest.TestCase):
    """Test cases for ColorOutput class."""

    def test_color_enabled(self):
        """Test color output when enabled."""
        color = ColorOutput(enabled=True)
        # Force enabled for testing (isatty check may fail)
        color.enabled = True
        self.assertIn("\033[92m", color.green("test"))
        self.assertIn("\033[91m", color.red("test"))
        self.assertIn("\033[93m", color.yellow("test"))
        self.assertIn("\033[96m", color.cyan("test"))
        self.assertIn("\033[1m", color.bold("test"))

    def test_color_disabled(self):
        """Test color output when disabled."""
        color = ColorOutput(enabled=False)
        self.assertEqual(color.green("test"), "test")
        self.assertEqual(color.red("test"), "test")
        self.assertEqual(color.yellow("test"), "test")
        self.assertEqual(color.cyan("test"), "test")
        self.assertEqual(color.bold("test"), "test")
        self.assertEqual(color.dim("test"), "test")


class TestProgressBar(unittest.TestCase):
    """Test cases for ProgressBar class."""

    def test_progress_bar_creation(self):
        """Test creating a progress bar."""
        color = ColorOutput(enabled=False)
        pb = ProgressBar(total=100, color=color)
        self.assertEqual(pb.total, 100)

    def test_progress_bar_format_time(self):
        """Test time formatting."""
        color = ColorOutput(enabled=False)
        pb = ProgressBar(total=100, color=color)
        self.assertEqual(pb._format_time(90), "1:30")
        self.assertEqual(pb._format_time(3661), "1:01:01")
        self.assertEqual(pb._format_time(30), "0:30")
        self.assertEqual(pb._format_time(-1), "--:--")

    def test_progress_bar_update(self):
        """Test progress bar update output."""
        color = ColorOutput(enabled=False)
        pb = ProgressBar(total=10, color=color)
        # Should not raise
        with patch('sys.stdout', new_callable=StringIO):
            pb.update(5)
            pb.update(10, "status")

    def test_progress_bar_finish(self):
        """Test progress bar finish."""
        color = ColorOutput(enabled=False)
        pb = ProgressBar(total=10, color=color)
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            pb.finish()
        output = mock_out.getvalue()
        self.assertIn("100.0%", output)
        self.assertIn("Done!", output)

    def test_progress_bar_zero_total(self):
        """Test progress bar with zero total."""
        color = ColorOutput(enabled=False)
        pb = ProgressBar(total=0, color=color)
        with patch('sys.stdout', new_callable=StringIO):
            pb.update(0)  # Should not raise


class TestSSHAuditClientTargetParsing(unittest.TestCase):
    """Test cases for target parsing functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = SSHAuditClient()

    def test_parse_single_ip(self):
        """Test parsing a single IP address."""
        targets = list(self.client._parse_targets(["192.168.1.1"]))
        self.assertEqual(targets, ["192.168.1.1"])

    def test_parse_multiple_ips(self):
        """Test parsing multiple IP addresses."""
        targets = list(self.client._parse_targets([
            "192.168.1.1",
            "192.168.1.2",
            "10.0.0.1"
        ]))
        self.assertEqual(len(targets), 3)
        self.assertIn("192.168.1.1", targets)
        self.assertIn("192.168.1.2", targets)
        self.assertIn("10.0.0.1", targets)

    def test_parse_cidr_range(self):
        """Test parsing CIDR notation."""
        targets = list(self.client._parse_targets(["192.168.1.0/30"]))
        # /30 gives 2 usable hosts (excluding network and broadcast)
        self.assertEqual(len(targets), 2)
        self.assertIn("192.168.1.1", targets)
        self.assertIn("192.168.1.2", targets)

    def test_parse_ip_range(self):
        """Test parsing IP range notation."""
        targets = list(self.client._parse_targets(["192.168.1.1-5"]))
        self.assertEqual(len(targets), 5)
        self.assertIn("192.168.1.1", targets)
        self.assertIn("192.168.1.5", targets)

    def test_parse_hostname(self):
        """Test parsing hostname."""
        targets = list(self.client._parse_targets(["server.example.com"]))
        self.assertEqual(targets, ["server.example.com"])

    def test_parse_empty_lines(self):
        """Test that empty lines are skipped."""
        targets = list(self.client._parse_targets(["192.168.1.1", "", "  ", "192.168.1.2"]))
        self.assertEqual(len(targets), 2)

    def test_parse_comments(self):
        """Test that comment lines are skipped."""
        targets = list(self.client._parse_targets([
            "# This is a comment",
            "192.168.1.1",
            "# Another comment",
            "192.168.1.2"
        ]))
        self.assertEqual(len(targets), 2)

    def test_parse_mixed_targets(self):
        """Test parsing mixed target types."""
        targets = list(self.client._parse_targets([
            "192.168.1.1",
            "10.0.0.0/30",
            "172.16.0.1-3",
            "server.local"
        ]))
        # 1 + 2 (from /30) + 3 (from range) + 1 hostname = 7
        self.assertEqual(len(targets), 7)


class TestSSHAuditClientFileReading(unittest.TestCase):
    """Test cases for file reading functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = SSHAuditClient()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_read_valid_file(self):
        """Test reading a valid file."""
        filepath = os.path.join(self.temp_dir, "test.txt")
        with open(filepath, 'w') as f:
            f.write("line1\nline2\nline3\n")

        lines = self.client._read_file_lines(filepath, "test")
        self.assertEqual(lines, ["line1", "line2", "line3"])

    def test_read_file_with_comments(self):
        """Test reading file with comments."""
        filepath = os.path.join(self.temp_dir, "test.txt")
        with open(filepath, 'w') as f:
            f.write("# Comment\ndata1\n# Another comment\ndata2\n")

        lines = self.client._read_file_lines(filepath, "test")
        self.assertEqual(lines, ["data1", "data2"])

    def test_read_file_with_empty_lines(self):
        """Test reading file with empty lines."""
        filepath = os.path.join(self.temp_dir, "test.txt")
        with open(filepath, 'w') as f:
            f.write("data1\n\n\ndata2\n  \ndata3\n")

        lines = self.client._read_file_lines(filepath, "test")
        self.assertEqual(lines, ["data1", "data2", "data3"])

    def test_read_nonexistent_file(self):
        """Test reading non-existent file raises error."""
        with self.assertRaises(FileNotFoundError) as context:
            self.client._read_file_lines("/nonexistent/file.txt", "test")
        self.assertIn("not found", str(context.exception))

    def test_read_directory_raises_error(self):
        """Test reading directory instead of file raises error."""
        with self.assertRaises(ValueError) as context:
            self.client._read_file_lines(self.temp_dir, "test")
        self.assertIn("not a file", str(context.exception))


class TestComboFileParsing(unittest.TestCase):
    """Test cases for combo file parsing functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = SSHAuditClient()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_parse_basic_combo_file(self):
        """Test parsing basic user:password combo file."""
        filepath = os.path.join(self.temp_dir, "combos.txt")
        with open(filepath, 'w') as f:
            f.write("root:password\nadmin:admin123\ntest:test\n")

        combos = self.client._parse_combo_file(filepath)
        self.assertEqual(len(combos), 3)
        self.assertEqual(combos[0], ("root", "password"))
        self.assertEqual(combos[1], ("admin", "admin123"))
        self.assertEqual(combos[2], ("test", "test"))

    def test_parse_combo_file_with_colon_in_password(self):
        """Test parsing combo file where password contains colons."""
        filepath = os.path.join(self.temp_dir, "combos.txt")
        with open(filepath, 'w') as f:
            f.write("root:pass:word:123\nadmin:p@ss:w0rd\n")

        combos = self.client._parse_combo_file(filepath)
        self.assertEqual(len(combos), 2)
        self.assertEqual(combos[0], ("root", "pass:word:123"))
        self.assertEqual(combos[1], ("admin", "p@ss:w0rd"))

    def test_parse_combo_file_with_comments(self):
        """Test parsing combo file with comment lines."""
        filepath = os.path.join(self.temp_dir, "combos.txt")
        with open(filepath, 'w') as f:
            f.write("# This is a comment\nroot:password\n# Another\nadmin:admin\n")

        combos = self.client._parse_combo_file(filepath)
        self.assertEqual(len(combos), 2)

    def test_parse_combo_file_skips_invalid(self):
        """Test that lines without colon separator are skipped."""
        filepath = os.path.join(self.temp_dir, "combos.txt")
        with open(filepath, 'w') as f:
            f.write("root:password\ninvalidline\nadmin:admin\n")

        combos = self.client._parse_combo_file(filepath)
        self.assertEqual(len(combos), 2)

    def test_parse_combo_file_empty_username_skipped(self):
        """Test that entries with empty username are skipped."""
        filepath = os.path.join(self.temp_dir, "combos.txt")
        with open(filepath, 'w') as f:
            f.write(":password\nroot:pass\n")

        combos = self.client._parse_combo_file(filepath)
        self.assertEqual(len(combos), 1)
        self.assertEqual(combos[0], ("root", "pass"))


class TestBannerFingerprinting(unittest.TestCase):
    """Test cases for SSH banner fingerprinting."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = SSHAuditClient()

    def test_fingerprint_openssh_ubuntu(self):
        """Test fingerprinting OpenSSH on Ubuntu."""
        fp = self.client._fingerprint_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
        self.assertEqual(fp.software, "OpenSSH")
        self.assertEqual(fp.software_version, "8.9p1")
        self.assertEqual(fp.os_guess, "Ubuntu Linux")

    def test_fingerprint_openssh_debian(self):
        """Test fingerprinting OpenSSH on Debian."""
        fp = self.client._fingerprint_banner("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2")
        self.assertEqual(fp.software, "OpenSSH")
        self.assertEqual(fp.os_guess, "Debian Linux")

    def test_fingerprint_openssh_generic(self):
        """Test fingerprinting generic OpenSSH."""
        fp = self.client._fingerprint_banner("SSH-2.0-OpenSSH_9.6")
        self.assertEqual(fp.software, "OpenSSH")
        self.assertEqual(fp.software_version, "9.6")
        self.assertEqual(fp.os_guess, "Unknown (likely Linux/Unix)")

    def test_fingerprint_dropbear(self):
        """Test fingerprinting Dropbear SSH."""
        fp = self.client._fingerprint_banner("SSH-2.0-dropbear_2022.83")
        self.assertEqual(fp.software, "Dropbear")
        self.assertEqual(fp.software_version, "2022.83")
        self.assertEqual(fp.os_guess, "Embedded/Linux")

    def test_fingerprint_libssh(self):
        """Test fingerprinting libssh."""
        fp = self.client._fingerprint_banner("SSH-2.0-libssh_0.10.5")
        self.assertEqual(fp.software, "libssh")
        self.assertEqual(fp.software_version, "0.10.5")

    def test_fingerprint_empty_banner(self):
        """Test fingerprinting with empty banner."""
        fp = self.client._fingerprint_banner("")
        self.assertEqual(fp.software, "")
        self.assertEqual(fp.os_guess, "")

    def test_fingerprint_protocol_version(self):
        """Test protocol version extraction."""
        fp = self.client._fingerprint_banner("SSH-2.0-OpenSSH_9.6")
        self.assertEqual(fp.protocol_version, "2.0")

    def test_fingerprint_sshv1(self):
        """Test detection of SSHv1."""
        fp = self.client._fingerprint_banner("SSH-1.5-some_server")
        self.assertEqual(fp.software, "SSHv1")
        self.assertEqual(fp.os_guess, "Legacy (SSHv1 - INSECURE)")

    def test_fingerprint_cisco(self):
        """Test fingerprinting Cisco SSH."""
        fp = self.client._fingerprint_banner("SSH-2.0-Cisco-1.25")
        self.assertEqual(fp.software, "Cisco SSH")
        self.assertEqual(fp.os_guess, "Cisco IOS/IOS-XE")

    def test_fingerprint_windows_openssh(self):
        """Test fingerprinting Windows OpenSSH."""
        fp = self.client._fingerprint_banner("SSH-2.0-OpenSSH_for_Windows_8.1")
        self.assertEqual(fp.software, "OpenSSH")
        self.assertEqual(fp.os_guess, "Windows")


class TestVulnerabilityChecking(unittest.TestCase):
    """Test cases for vulnerability checking."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = SSHAuditClient()

    def test_check_openssh_regresshion(self):
        """Test detection of regreSSHion (CVE-2024-6387)."""
        fp = FingerprintInfo(software="OpenSSH", software_version="9.5p1")
        vulns = self.client._check_vulnerabilities(fp)
        cves = [v.cve for v in vulns]
        self.assertIn("CVE-2024-6387", cves)

    def test_check_openssh_patched(self):
        """Test that patched OpenSSH has no regreSSHion."""
        fp = FingerprintInfo(software="OpenSSH", software_version="9.8p1")
        vulns = self.client._check_vulnerabilities(fp)
        cves = [v.cve for v in vulns]
        self.assertNotIn("CVE-2024-6387", cves)

    def test_check_openssh_terrapin(self):
        """Test detection of Terrapin attack (CVE-2023-48795)."""
        fp = FingerprintInfo(software="OpenSSH", software_version="9.5")
        vulns = self.client._check_vulnerabilities(fp)
        cves = [v.cve for v in vulns]
        self.assertIn("CVE-2023-48795", cves)

    def test_check_openssh_no_terrapin_when_patched(self):
        """Test that patched OpenSSH has no Terrapin."""
        fp = FingerprintInfo(software="OpenSSH", software_version="9.6")
        vulns = self.client._check_vulnerabilities(fp)
        cves = [v.cve for v in vulns]
        self.assertNotIn("CVE-2023-48795", cves)

    def test_check_old_openssh_multiple_vulns(self):
        """Test that old OpenSSH has multiple vulnerabilities."""
        fp = FingerprintInfo(software="OpenSSH", software_version="7.5p1")
        vulns = self.client._check_vulnerabilities(fp)
        self.assertGreater(len(vulns), 3)

    def test_check_dropbear_terrapin(self):
        """Test Dropbear Terrapin detection."""
        fp = FingerprintInfo(software="Dropbear", software_version="2022.82")
        vulns = self.client._check_vulnerabilities(fp)
        cves = [v.cve for v in vulns]
        self.assertIn("CVE-2023-48795", cves)

    def test_check_no_version(self):
        """Test vulnerability check with no version info."""
        fp = FingerprintInfo(software="OpenSSH", software_version="")
        vulns = self.client._check_vulnerabilities(fp)
        self.assertEqual(len(vulns), 0)

    def test_check_unknown_software(self):
        """Test vulnerability check with unknown software."""
        fp = FingerprintInfo(software="Unknown", software_version="1.0")
        vulns = self.client._check_vulnerabilities(fp)
        self.assertEqual(len(vulns), 0)

    def test_vulnerability_severity_levels(self):
        """Test that vulnerabilities have valid severity levels."""
        fp = FingerprintInfo(software="OpenSSH", software_version="7.5p1")
        vulns = self.client._check_vulnerabilities(fp)
        valid_severities = {"HIGH", "MEDIUM", "LOW"}
        for v in vulns:
            self.assertIn(v.severity, valid_severities)


class TestSSHAuditClientConnection(unittest.TestCase):
    """Test cases for SSH connection functionality (mocked)."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = SSHAuditClient(timeout=5)

    @patch('sshcheck.paramiko.SSHClient')
    def test_successful_login(self, mock_ssh_class):
        """Test successful SSH login."""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        # Mock successful connection
        mock_client.connect.return_value = None

        # Mock channel for initial output
        mock_channel = MagicMock()
        mock_channel.recv_ready.side_effect = [True, False]
        mock_channel.recv.return_value = b"Welcome to the server\n"
        mock_client.invoke_shell.return_value = mock_channel

        with patch.object(self.client, '_get_ssh_banner', return_value="SSH-2.0-OpenSSH"):
            with patch.object(self.client, '_fingerprint_banner', return_value=FingerprintInfo()):
                with patch.object(self.client, '_check_vulnerabilities', return_value=[]):
                    with patch.object(self.client, '_get_host_key_info', return_value=HostKeyInfo()):
                        with patch.object(self.client, '_enumerate_algorithms', return_value=AlgorithmInfo()):
                            result = self.client._try_login("192.168.1.1", 22, "admin", "password")

        self.assertTrue(result.success)
        self.assertEqual(result.host, "192.168.1.1")
        self.assertEqual(result.username, "admin")
        self.assertEqual(result.auth_method, "password")

    @patch('sshcheck.paramiko.SSHClient')
    def test_successful_key_login(self, mock_ssh_class):
        """Test successful SSH key-based login."""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.return_value = None

        mock_channel = MagicMock()
        mock_channel.recv_ready.side_effect = [False]
        mock_client.invoke_shell.return_value = mock_channel

        with patch.object(self.client, '_get_ssh_banner', return_value="SSH-2.0-OpenSSH"):
            with patch.object(self.client, '_fingerprint_banner', return_value=FingerprintInfo()):
                with patch.object(self.client, '_check_vulnerabilities', return_value=[]):
                    with patch.object(self.client, '_get_host_key_info', return_value=HostKeyInfo()):
                        with patch.object(self.client, '_enumerate_algorithms', return_value=AlgorithmInfo()):
                            with patch.object(self.client, '_load_private_key', return_value=MagicMock()):
                                result = self.client._try_login(
                                    "192.168.1.1", 22, "admin", "", "/home/user/.ssh/id_rsa"
                                )

        self.assertTrue(result.success)
        self.assertEqual(result.auth_method, "key")
        self.assertEqual(result.key_file, "/home/user/.ssh/id_rsa")

    @patch('sshcheck.paramiko.SSHClient')
    def test_authentication_failure(self, mock_ssh_class):
        """Test authentication failure."""
        import paramiko
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        # Mock authentication failure
        mock_client.connect.side_effect = paramiko.AuthenticationException("Auth failed")

        with patch.object(self.client, '_get_ssh_banner', return_value=""):
            with patch.object(self.client, '_fingerprint_banner', return_value=FingerprintInfo()):
                with patch.object(self.client, '_check_vulnerabilities', return_value=[]):
                    with patch.object(self.client, '_get_host_key_info', return_value=HostKeyInfo()):
                        with patch.object(self.client, '_enumerate_algorithms', return_value=AlgorithmInfo()):
                            result = self.client._try_login("192.168.1.1", 22, "admin", "wrongpass")

        self.assertFalse(result.success)
        self.assertIn("Authentication failed", result.error_message)
        self.assertEqual(self.client.stats.authentication_errors, 1)

    @patch('sshcheck.paramiko.SSHClient')
    def test_connection_timeout(self, mock_ssh_class):
        """Test connection timeout."""
        import socket
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        # Mock timeout
        mock_client.connect.side_effect = socket.timeout()

        with patch.object(self.client, '_get_ssh_banner', return_value=""):
            with patch.object(self.client, '_fingerprint_banner', return_value=FingerprintInfo()):
                with patch.object(self.client, '_check_vulnerabilities', return_value=[]):
                    with patch.object(self.client, '_get_host_key_info', return_value=HostKeyInfo()):
                        with patch.object(self.client, '_enumerate_algorithms', return_value=AlgorithmInfo()):
                            result = self.client._try_login("192.168.1.1", 22, "admin", "password")

        self.assertFalse(result.success)
        self.assertIn("timed out", result.error_message)
        self.assertEqual(self.client.stats.timeout_errors, 1)

    @patch('sshcheck.paramiko.SSHClient')
    def test_connection_refused(self, mock_ssh_class):
        """Test connection refused error."""
        import socket
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        # Mock connection refused
        error = socket.error()
        error.errno = 111
        mock_client.connect.side_effect = error

        with patch.object(self.client, '_get_ssh_banner', return_value=""):
            with patch.object(self.client, '_fingerprint_banner', return_value=FingerprintInfo()):
                with patch.object(self.client, '_check_vulnerabilities', return_value=[]):
                    with patch.object(self.client, '_get_host_key_info', return_value=HostKeyInfo()):
                        with patch.object(self.client, '_enumerate_algorithms', return_value=AlgorithmInfo()):
                            result = self.client._try_login("192.168.1.1", 22, "admin", "password")

        self.assertFalse(result.success)
        self.assertIn("Connection refused", result.error_message)


class TestLoadPrivateKey(unittest.TestCase):
    """Test cases for SSH private key loading."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = SSHAuditClient()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_key_file_not_found(self):
        """Test loading non-existent key file."""
        with self.assertRaises(FileNotFoundError):
            self.client._load_private_key("/nonexistent/id_rsa")

    def test_key_file_is_directory(self):
        """Test loading directory as key file."""
        with self.assertRaises(ValueError):
            self.client._load_private_key(self.temp_dir)

    @patch('sshcheck.paramiko.RSAKey.from_private_key_file')
    def test_load_rsa_key(self, mock_rsa):
        """Test loading RSA key successfully."""
        key_file = os.path.join(self.temp_dir, "id_rsa")
        with open(key_file, 'w') as f:
            f.write("fake key content")

        mock_key = MagicMock()
        mock_rsa.return_value = mock_key

        result = self.client._load_private_key(key_file)
        self.assertEqual(result, mock_key)

    @patch('sshcheck.paramiko.ECDSAKey.from_private_key_file')
    @patch('sshcheck.paramiko.Ed25519Key.from_private_key_file')
    @patch('sshcheck.paramiko.RSAKey.from_private_key_file')
    def test_load_ed25519_key_fallback(self, mock_rsa, mock_ed25519, mock_ecdsa):
        """Test loading Ed25519 key after RSA fails."""
        key_file = os.path.join(self.temp_dir, "id_ed25519")
        with open(key_file, 'w') as f:
            f.write("fake key content")

        mock_rsa.side_effect = paramiko.SSHException("Not an RSA key")
        mock_key = MagicMock()
        mock_ed25519.return_value = mock_key

        result = self.client._load_private_key(key_file)
        self.assertEqual(result, mock_key)

    @patch('sshcheck.paramiko.RSAKey.from_private_key_file')
    def test_load_encrypted_key_no_passphrase(self, mock_rsa):
        """Test loading encrypted key without passphrase."""
        key_file = os.path.join(self.temp_dir, "id_rsa_enc")
        with open(key_file, 'w') as f:
            f.write("fake encrypted key")

        mock_rsa.side_effect = paramiko.PasswordRequiredException("need passphrase")

        with self.assertRaises(paramiko.SSHException) as ctx:
            self.client._load_private_key(key_file)
        self.assertIn("encrypted", str(ctx.exception))


class TestSSHAuditClientOutput(unittest.TestCase):
    """Test cases for output functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.client = SSHAuditClient()
        self.client.results = [
            ScanResult(
                host="192.168.1.1",
                port=22,
                username="admin",
                password="pass123",
                success=True,
                timestamp="2026-01-01T12:00:00",
                initial_output="Welcome",
                banner="SSH-2.0-OpenSSH_9.6",
                fingerprint_info=FingerprintInfo(
                    software="OpenSSH",
                    software_version="9.6",
                    os_guess="Ubuntu Linux"
                ),
                host_key_info=HostKeyInfo(
                    key_type="ssh-ed25519",
                    key_bits=256,
                    fingerprint_sha256="SHA256:testkey",
                    fingerprint_md5="MD5:aa:bb:cc"
                )
            ),
            ScanResult(
                host="192.168.1.2",
                port=22,
                username="root",
                password="toor",
                success=False,
                timestamp="2026-01-01T12:00:01",
                error_message="Auth failed"
            )
        ]
        from datetime import datetime
        self.client.stats.total_attempts = 2
        self.client.stats.successful_logins = 1
        self.client.stats.failed_logins = 1
        self.client.stats.start_time = datetime(2026, 1, 1, 12, 0, 0)
        self.client.stats.end_time = datetime(2026, 1, 1, 12, 0, 30)

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_save_json_output(self):
        """Test saving results in JSON format."""
        output_file = os.path.join(self.temp_dir, "results.json")
        self.client.output_file = output_file
        self.client.output_format = "json"
        self.client._save_results()

        with open(output_file, 'r') as f:
            data = json.load(f)

        self.assertIn("scan_info", data)
        self.assertIn("statistics", data)
        self.assertIn("results", data)
        self.assertEqual(len(data["results"]), 2)
        self.assertEqual(data["statistics"]["total_attempts"], 2)
        # Check extended fields in JSON
        self.assertIn("auth_method", data["results"][0])
        self.assertIn("fingerprint_info", data["results"][0])
        self.assertIn("host_key_info", data["results"][0])

    def test_save_csv_output(self):
        """Test saving results in CSV format."""
        import csv
        output_file = os.path.join(self.temp_dir, "results.csv")
        self.client.output_file = output_file
        self.client.output_format = "csv"
        self.client._save_results()

        with open(output_file, 'r') as f:
            reader = csv.reader(f)
            rows = list(reader)

        # Header + 2 data rows
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0][0], "host")
        # Check new columns exist in header
        self.assertIn("auth_method", rows[0])
        self.assertIn("software", rows[0])
        self.assertIn("host_key_type", rows[0])
        self.assertIn("vulnerabilities", rows[0])

    def test_save_text_output(self):
        """Test saving results in text format."""
        output_file = os.path.join(self.temp_dir, "results.txt")
        self.client.output_file = output_file
        self.client.output_format = "text"
        self.client._save_results()

        with open(output_file, 'r') as f:
            content = f.read()

        self.assertIn("SSH Security Audit Results", content)
        self.assertIn("SUCCESSFUL LOGINS", content)
        self.assertIn("192.168.1.1", content)

    def test_save_text_output_with_key_auth(self):
        """Test saving text output with key auth results."""
        self.client.results = [
            ScanResult(
                host="192.168.1.1",
                port=22,
                username="admin",
                password="",
                success=True,
                timestamp="2026-01-01T12:00:00",
                auth_method="key",
                key_file="/home/user/.ssh/id_rsa"
            )
        ]
        output_file = os.path.join(self.temp_dir, "results.txt")
        self.client.output_file = output_file
        self.client.output_format = "text"
        self.client._save_results()

        with open(output_file, 'r') as f:
            content = f.read()

        self.assertIn("key", content)
        self.assertIn("id_rsa", content)


class TestProxyParsing(unittest.TestCase):
    """Test cases for proxy URL parsing."""

    def test_parse_socks5_proxy(self):
        """Test parsing SOCKS5 proxy URL."""
        client = SSHAuditClient(proxy="socks5://127.0.0.1:9050")
        self.assertEqual(client._proxy_type, "socks5")
        self.assertEqual(client._proxy_host, "127.0.0.1")
        self.assertEqual(client._proxy_port, 9050)

    def test_parse_socks4_proxy(self):
        """Test parsing SOCKS4 proxy URL."""
        client = SSHAuditClient(proxy="socks4://proxy.example.com:1080")
        self.assertEqual(client._proxy_type, "socks4")
        self.assertEqual(client._proxy_host, "proxy.example.com")
        self.assertEqual(client._proxy_port, 1080)

    def test_parse_http_proxy(self):
        """Test parsing HTTP proxy URL."""
        client = SSHAuditClient(proxy="http://proxy.corp.com:8080")
        self.assertEqual(client._proxy_type, "http")
        self.assertEqual(client._proxy_host, "proxy.corp.com")
        self.assertEqual(client._proxy_port, 8080)

    def test_parse_https_proxy(self):
        """Test parsing HTTPS proxy URL as HTTP type."""
        client = SSHAuditClient(proxy="https://proxy.corp.com:3128")
        self.assertEqual(client._proxy_type, "http")
        self.assertEqual(client._proxy_host, "proxy.corp.com")
        self.assertEqual(client._proxy_port, 3128)

    def test_parse_socks5h_proxy(self):
        """Test parsing SOCKS5H proxy URL."""
        client = SSHAuditClient(proxy="socks5h://127.0.0.1:9050")
        self.assertEqual(client._proxy_type, "socks5")

    def test_parse_proxy_default_scheme(self):
        """Test proxy with no scheme defaults to SOCKS5."""
        client = SSHAuditClient(proxy="127.0.0.1:9050")
        self.assertEqual(client._proxy_type, "socks5")

    def test_parse_proxy_default_port_socks(self):
        """Test SOCKS proxy with default port."""
        client = SSHAuditClient(proxy="socks5://127.0.0.1")
        self.assertEqual(client._proxy_port, 1080)

    def test_parse_proxy_default_port_http(self):
        """Test HTTP proxy with default port."""
        client = SSHAuditClient(proxy="http://proxy.example.com")
        self.assertEqual(client._proxy_port, 8080)

    def test_parse_no_proxy(self):
        """Test client with no proxy."""
        client = SSHAuditClient()
        self.assertIsNone(client._proxy_type)
        self.assertIsNone(client._proxy_host)
        self.assertIsNone(client._proxy_port)

    def test_parse_proxy_invalid_port(self):
        """Test proxy with invalid port."""
        with self.assertRaises(ValueError):
            SSHAuditClient(proxy="socks5://127.0.0.1:notaport")


class TestArgumentParsing(unittest.TestCase):
    """Test cases for command line argument parsing."""

    def test_single_target(self):
        """Test parsing single target."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root', '-p', 'pass']):
            args = parse_arguments()
        self.assertEqual(args.targets, ['192.168.1.1'])

    def test_multiple_targets(self):
        """Test parsing multiple targets."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-t', '192.168.1.2',
                                '-u', 'root', '-p', 'pass']):
            args = parse_arguments()
        self.assertEqual(args.targets, ['192.168.1.1', '192.168.1.2'])

    def test_target_file(self):
        """Test parsing target file argument."""
        with patch('sys.argv', ['sshcheck', '-T', 'targets.txt', '-u', 'root', '-p', 'pass']):
            args = parse_arguments()
        self.assertEqual(args.target_file, 'targets.txt')

    def test_multiple_users(self):
        """Test parsing multiple usernames."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1',
                                '-u', 'root', '-u', 'admin', '-p', 'pass']):
            args = parse_arguments()
        self.assertEqual(args.users, ['root', 'admin'])

    def test_multiple_passwords(self):
        """Test parsing multiple passwords."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass1', '-p', 'pass2']):
            args = parse_arguments()
        self.assertEqual(args.passwords, ['pass1', 'pass2'])

    def test_custom_port(self):
        """Test parsing custom port."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--port', '2222']):
            args = parse_arguments()
        self.assertEqual(args.ports, [2222])

    def test_multiple_ports(self):
        """Test parsing multiple ports."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--port', '22', '--port', '2222']):
            args = parse_arguments()
        self.assertEqual(args.ports, [22, 2222])

    def test_timeout_option(self):
        """Test parsing timeout option."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--timeout', '30']):
            args = parse_arguments()
        self.assertEqual(args.timeout, 30)

    def test_threads_option(self):
        """Test parsing threads option."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '-n', '10']):
            args = parse_arguments()
        self.assertEqual(args.threads, 10)

    def test_output_options(self):
        """Test parsing output options."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '-o', 'results.json', '-f', 'json']):
            args = parse_arguments()
        self.assertEqual(args.output, 'results.json')
        self.assertEqual(args.format, 'json')

    def test_verbose_flag(self):
        """Test parsing verbose flag."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '-v']):
            args = parse_arguments()
        self.assertTrue(args.verbose)

    def test_default_values(self):
        """Test default argument values."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root', '-p', 'pass']):
            args = parse_arguments()
        self.assertEqual(args.timeout, 10)
        self.assertEqual(args.threads, 1)
        self.assertEqual(args.format, 'text')
        self.assertFalse(args.verbose)
        self.assertIsNone(args.ports)
        self.assertFalse(args.no_color)
        self.assertIsNone(args.proxy)
        self.assertIsNone(args.key_files)
        self.assertIsNone(args.combo_file)

    def test_key_file_option(self):
        """Test parsing key file option."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-k', '/home/user/.ssh/id_rsa']):
            args = parse_arguments()
        self.assertEqual(args.key_files, ['/home/user/.ssh/id_rsa'])

    def test_multiple_key_files(self):
        """Test parsing multiple key files."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-k', '/home/user/.ssh/id_rsa',
                                '-k', '/home/user/.ssh/id_ed25519']):
            args = parse_arguments()
        self.assertEqual(len(args.key_files), 2)

    def test_combo_file_option(self):
        """Test parsing combo file option."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-C', 'combos.txt']):
            args = parse_arguments()
        self.assertEqual(args.combo_file, 'combos.txt')

    def test_no_color_flag(self):
        """Test parsing --no-color flag."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--no-color']):
            args = parse_arguments()
        self.assertTrue(args.no_color)

    def test_proxy_option(self):
        """Test parsing proxy option."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--proxy', 'socks5://127.0.0.1:9050']):
            args = parse_arguments()
        self.assertEqual(args.proxy, 'socks5://127.0.0.1:9050')

    def test_key_list_file_option(self):
        """Test parsing key list file option."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-K', 'keys.txt']):
            args = parse_arguments()
        self.assertEqual(args.key_file, 'keys.txt')


class TestIntegration(unittest.TestCase):
    """Integration tests with mocked SSH connections."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('sshcheck.paramiko.SSHClient')
    def test_full_scan_with_file_inputs(self, mock_ssh_class):
        """Test full scan using file inputs."""
        # Create test files
        targets_file = os.path.join(self.temp_dir, "targets.txt")
        users_file = os.path.join(self.temp_dir, "users.txt")
        passwords_file = os.path.join(self.temp_dir, "passwords.txt")
        output_file = os.path.join(self.temp_dir, "results.json")

        with open(targets_file, 'w') as f:
            f.write("192.168.1.1\n192.168.1.2\n")
        with open(users_file, 'w') as f:
            f.write("root\nadmin\n")
        with open(passwords_file, 'w') as f:
            f.write("password123\nadmin\n")

        # Mock SSH client
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Connection failed")

        client = SSHAuditClient(output_file=output_file, output_format='json')

        targets = client._read_file_lines(targets_file, "targets")
        users = client._read_file_lines(users_file, "users")
        passwords = client._read_file_lines(passwords_file, "passwords")

        with patch.object(client, '_get_ssh_banner', return_value=""):
            with patch.object(client, '_fingerprint_banner', return_value=FingerprintInfo()):
                with patch.object(client, '_check_vulnerabilities', return_value=[]):
                    with patch.object(client, '_get_host_key_info', return_value=HostKeyInfo()):
                        with patch.object(client, '_enumerate_algorithms', return_value=AlgorithmInfo()):
                            # Capture stdout
                            with patch('sys.stdout', new_callable=StringIO):
                                results = client.scan(targets, users, passwords, [22])

        # Should have 2 hosts * 2 users * 2 passwords = 8 attempts
        self.assertEqual(len(results), 8)
        self.assertEqual(client.stats.total_attempts, 8)

        # Check output file was created
        self.assertTrue(os.path.exists(output_file))

    @patch('sshcheck.paramiko.SSHClient')
    def test_scan_with_multiple_ports(self, mock_ssh_class):
        """Test scanning with multiple ports."""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Connection failed")

        client = SSHAuditClient()

        with patch.object(client, '_get_ssh_banner', return_value=""):
            with patch.object(client, '_fingerprint_banner', return_value=FingerprintInfo()):
                with patch.object(client, '_check_vulnerabilities', return_value=[]):
                    with patch.object(client, '_get_host_key_info', return_value=HostKeyInfo()):
                        with patch.object(client, '_enumerate_algorithms', return_value=AlgorithmInfo()):
                            with patch('sys.stdout', new_callable=StringIO):
                                results = client.scan(
                                    ["192.168.1.1"],
                                    ["root"],
                                    ["password"],
                                    [22, 2222, 22222]
                                )

        # Should have 1 host * 1 user * 1 password * 3 ports = 3 attempts
        self.assertEqual(len(results), 3)
        ports_tried = {r.port for r in results}
        self.assertEqual(ports_tried, {22, 2222, 22222})

    @patch('sshcheck.paramiko.SSHClient')
    def test_scan_with_combo_file(self, mock_ssh_class):
        """Test scanning with combo file."""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Connection failed")

        # Create combo file
        combo_file = os.path.join(self.temp_dir, "combos.txt")
        with open(combo_file, 'w') as f:
            f.write("root:password\nadmin:admin123\n")

        client = SSHAuditClient()
        combo_list = client._parse_combo_file(combo_file)

        with patch.object(client, '_get_ssh_banner', return_value=""):
            with patch.object(client, '_fingerprint_banner', return_value=FingerprintInfo()):
                with patch.object(client, '_check_vulnerabilities', return_value=[]):
                    with patch.object(client, '_get_host_key_info', return_value=HostKeyInfo()):
                        with patch.object(client, '_enumerate_algorithms', return_value=AlgorithmInfo()):
                            with patch('sys.stdout', new_callable=StringIO):
                                results = client.scan(
                                    ["192.168.1.1"],
                                    [],  # No separate users
                                    [],  # No separate passwords
                                    [22],
                                    combo_list=combo_list
                                )

        # Should have 1 host * 2 combos = 2 attempts
        self.assertEqual(len(results), 2)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = SSHAuditClient()

    def test_empty_targets(self):
        """Test scanning with empty targets."""
        with patch('sys.stdout', new_callable=StringIO):
            with patch('sys.stderr', new_callable=StringIO):
                results = self.client.scan([], ["root"], ["pass"], [22])
        self.assertEqual(len(results), 0)

    def test_empty_users(self):
        """Test scanning with empty users and no other creds."""
        with patch('sys.stdout', new_callable=StringIO):
            with patch('sys.stderr', new_callable=StringIO):
                results = self.client.scan(["192.168.1.1"], [], ["pass"], [22])
        self.assertEqual(len(results), 0)

    def test_empty_passwords(self):
        """Test scanning with empty passwords and no other creds."""
        with patch('sys.stdout', new_callable=StringIO):
            with patch('sys.stderr', new_callable=StringIO):
                results = self.client.scan(["192.168.1.1"], ["root"], [], [22])
        self.assertEqual(len(results), 0)

    def test_ipv6_address(self):
        """Test parsing IPv6 address."""
        targets = list(self.client._parse_targets(["::1"]))
        self.assertEqual(targets, ["::1"])

    def test_large_cidr_range(self):
        """Test parsing large CIDR range."""
        targets = list(self.client._parse_targets(["192.168.0.0/24"]))
        # /24 gives 254 usable hosts
        self.assertEqual(len(targets), 254)

    def test_no_color_client_creation(self):
        """Test creating client with color disabled."""
        client = SSHAuditClient(color=False)
        self.assertFalse(client.color.enabled)

    def test_quiet_mode_client_creation(self):
        """Test creating client with quiet mode."""
        client = SSHAuditClient(quiet=True)
        self.assertTrue(client.quiet)


class TestWeakAlgorithmDatabases(unittest.TestCase):
    """Test that weak algorithm databases are properly populated."""

    def test_weak_kex_algorithms_populated(self):
        """Test that weak KEX algorithms database is populated."""
        self.assertGreater(len(WEAK_KEX_ALGORITHMS), 0)
        self.assertIn("diffie-hellman-group1-sha1", WEAK_KEX_ALGORITHMS)

    def test_weak_ciphers_populated(self):
        """Test that weak ciphers database is populated."""
        self.assertGreater(len(WEAK_CIPHERS), 0)
        self.assertIn("arcfour", WEAK_CIPHERS)
        self.assertIn("3des-cbc", WEAK_CIPHERS)

    def test_weak_macs_populated(self):
        """Test that weak MACs database is populated."""
        self.assertGreater(len(WEAK_MACS), 0)
        self.assertIn("hmac-md5", WEAK_MACS)

    def test_weak_host_key_types_populated(self):
        """Test that weak host key types database is populated."""
        self.assertGreater(len(WEAK_HOST_KEY_TYPES), 0)
        self.assertIn("ssh-dss", WEAK_HOST_KEY_TYPES)

    def test_vulnerability_database_populated(self):
        """Test that vulnerability database is populated."""
        self.assertIn("OpenSSH", SSH_VULNERABILITIES)
        self.assertIn("Dropbear", SSH_VULNERABILITIES)
        self.assertIn("libssh", SSH_VULNERABILITIES)
        self.assertGreater(len(SSH_VULNERABILITIES["OpenSSH"]), 5)

    def test_fingerprint_database_populated(self):
        """Test that fingerprint database is populated."""
        self.assertGreater(len(SSH_FINGERPRINTS), 10)


if __name__ == '__main__':
    unittest.main(verbosity=2)
