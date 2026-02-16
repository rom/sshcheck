#!/usr/bin/env python3
"""
Test cases for sshcheck - SSH Security Audit Client

These tests verify the functionality of the SSH audit client without
requiring actual SSH connections (uses mocking for network operations).
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch, PropertyMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sshcheck import (
    SSHAuditClient,
    ScanResult,
    ScanStatistics,
    SeverityLevel,
    VULNERABLE_VERSIONS,
    WEAK_ALGORITHMS,
    OS_FINGERPRINTS,
    HONEYPOT_SIGNATURES,
    COMMON_PASSWORDS,
    COMMON_SSH_PORTS,
    parse_arguments,
    load_config_file,
    apply_config,
    _severity_rank,
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
        self.assertEqual(result.host_key_type, "")
        self.assertEqual(result.host_key_fingerprint, "")
        self.assertEqual(result.os_info, "")
        self.assertEqual(result.severity, "")
        self.assertEqual(result.command_output, "")

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

    def test_scan_result_with_new_fields(self):
        """Test creating a ScanResult with new v2 fields."""
        result = ScanResult(
            host="192.168.1.1",
            port=22,
            username="root",
            password="toor",
            success=True,
            timestamp="2026-01-01T12:00:00",
            host_key_type="ssh-ed25519",
            host_key_fingerprint="SHA256:ab:cd:ef",
            host_key_bits=256,
            os_info="Ubuntu Linux",
            os_family="Linux",
            ssh_version="OpenSSH_8.9p1 Ubuntu-3",
            severity="critical",
            severity_reasons=["Root login successful"],
            command_output="uid=0(root) gid=0(root)",
            algorithms={"kex": ["curve25519-sha256"]},
            weak_algorithms={"ciphers": ["aes128-cbc: CBC mode"]}
        )
        self.assertEqual(result.host_key_type, "ssh-ed25519")
        self.assertEqual(result.host_key_bits, 256)
        self.assertEqual(result.os_info, "Ubuntu Linux")
        self.assertEqual(result.severity, "critical")
        self.assertEqual(result.command_output, "uid=0(root) gid=0(root)")
        self.assertEqual(len(result.severity_reasons), 1)

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
        # None values should be converted to empty structures
        self.assertEqual(data['algorithms'], {})
        self.assertEqual(data['weak_algorithms'], {})
        self.assertEqual(data['severity_reasons'], [])


class TestScanStatistics(unittest.TestCase):
    """Test cases for ScanStatistics dataclass."""

    def test_statistics_default_values(self):
        """Test default statistics values."""
        stats = ScanStatistics()
        self.assertEqual(stats.total_attempts, 0)
        self.assertEqual(stats.successful_logins, 0)
        self.assertEqual(stats.failed_logins, 0)
        self.assertEqual(stats.connection_errors, 0)
        self.assertEqual(stats.skipped_lockout, 0)
        self.assertEqual(stats.skipped_stop_on_success, 0)
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


class TestSeverity(unittest.TestCase):
    """Test cases for severity levels and scoring."""

    def test_severity_levels(self):
        """Test SeverityLevel enum values."""
        self.assertEqual(SeverityLevel.CRITICAL.value, "critical")
        self.assertEqual(SeverityLevel.HIGH.value, "high")
        self.assertEqual(SeverityLevel.MEDIUM.value, "medium")
        self.assertEqual(SeverityLevel.LOW.value, "low")
        self.assertEqual(SeverityLevel.INFO.value, "info")

    def test_severity_rank(self):
        """Test severity ranking function."""
        self.assertGreater(_severity_rank(SeverityLevel.CRITICAL), _severity_rank(SeverityLevel.HIGH))
        self.assertGreater(_severity_rank(SeverityLevel.HIGH), _severity_rank(SeverityLevel.MEDIUM))
        self.assertGreater(_severity_rank(SeverityLevel.MEDIUM), _severity_rank(SeverityLevel.LOW))
        self.assertGreater(_severity_rank(SeverityLevel.LOW), _severity_rank(SeverityLevel.INFO))

    def test_severity_root_login(self):
        """Test severity for root login."""
        client = SSHAuditClient()
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="toor", success=True, timestamp="2026-01-01T12:00:00"
        )
        severity, reasons = client._assess_severity(result)
        self.assertEqual(severity, "critical")
        self.assertTrue(any("Root/admin" in r for r in reasons))

    def test_severity_empty_password(self):
        """Test severity for empty password login."""
        client = SSHAuditClient()
        result = ScanResult(
            host="192.168.1.1", port=22, username="user1",
            password="", success=True, timestamp="2026-01-01T12:00:00"
        )
        severity, reasons = client._assess_severity(result)
        self.assertEqual(severity, "critical")
        self.assertTrue(any("Empty/null" in r for r in reasons))

    def test_severity_user_as_password(self):
        """Test severity for username-as-password."""
        client = SSHAuditClient()
        result = ScanResult(
            host="192.168.1.1", port=22, username="admin",
            password="admin", success=True, timestamp="2026-01-01T12:00:00"
        )
        severity, reasons = client._assess_severity(result)
        self.assertEqual(severity, "critical")
        self.assertTrue(any("Username used as password" in r for r in reasons))

    def test_severity_normal_user(self):
        """Test severity for normal user login with non-default password."""
        client = SSHAuditClient()
        result = ScanResult(
            host="192.168.1.1", port=22, username="john",
            password="s3cur3P@ss!", success=True, timestamp="2026-01-01T12:00:00"
        )
        severity, reasons = client._assess_severity(result)
        self.assertEqual(severity, "high")

    def test_severity_failed_login(self):
        """Test severity for failed login."""
        client = SSHAuditClient()
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="wrong", success=False, timestamp="2026-01-01T12:00:00"
        )
        severity, reasons = client._assess_severity(result)
        self.assertEqual(severity, "info")

    def test_severity_weak_host_key(self):
        """Test severity for weak DSA host key."""
        client = SSHAuditClient()
        result = ScanResult(
            host="192.168.1.1", port=22, username="user",
            password="wrong", success=False, timestamp="2026-01-01T12:00:00",
            host_key_type="ssh-dss"
        )
        severity, reasons = client._assess_severity(result)
        self.assertTrue(any("DSA" in r for r in reasons))

    def test_severity_weak_algorithms(self):
        """Test severity for weak algorithms."""
        client = SSHAuditClient()
        result = ScanResult(
            host="192.168.1.1", port=22, username="user",
            password="wrong", success=False, timestamp="2026-01-01T12:00:00",
            weak_algorithms={"ciphers": ["arcfour: RC4 stream cipher, broken"]}
        )
        severity, reasons = client._assess_severity(result)
        self.assertTrue(any("weak algorithm" in r for r in reasons))


class TestOSFingerprinting(unittest.TestCase):
    """Test cases for OS fingerprinting from banners."""

    def setUp(self):
        self.client = SSHAuditClient()

    def test_ubuntu_banner(self):
        """Test Ubuntu detection."""
        os_info, os_family, ssh_ver = self.client._fingerprint_os(
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
        )
        self.assertEqual(os_info, "Ubuntu Linux")
        self.assertEqual(os_family, "Linux")
        self.assertIn("OpenSSH_8.9p1", ssh_ver)

    def test_debian_banner(self):
        """Test Debian detection."""
        os_info, os_family, _ = self.client._fingerprint_os(
            "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1"
        )
        self.assertEqual(os_info, "Debian Linux")
        self.assertEqual(os_family, "Linux")

    def test_freebsd_banner(self):
        """Test FreeBSD detection."""
        os_info, os_family, _ = self.client._fingerprint_os(
            "SSH-2.0-OpenSSH_8.8 FreeBSD-20211221"
        )
        self.assertEqual(os_info, "FreeBSD")
        self.assertEqual(os_family, "BSD")

    def test_dropbear_banner(self):
        """Test Dropbear (embedded) detection."""
        os_info, os_family, _ = self.client._fingerprint_os(
            "SSH-2.0-dropbear_2020.81"
        )
        self.assertEqual(os_family, "Embedded")

    def test_windows_banner(self):
        """Test Windows detection."""
        os_info, os_family, _ = self.client._fingerprint_os(
            "SSH-2.0-OpenSSH_for_Windows_8.1"
        )
        self.assertEqual(os_family, "Windows")

    def test_empty_banner(self):
        """Test empty banner."""
        os_info, os_family, ssh_ver = self.client._fingerprint_os("")
        self.assertEqual(os_info, "")
        self.assertEqual(os_family, "")
        self.assertEqual(ssh_ver, "")

    def test_generic_openssh(self):
        """Test generic OpenSSH banner."""
        os_info, os_family, _ = self.client._fingerprint_os(
            "SSH-2.0-OpenSSH_9.0"
        )
        self.assertEqual(os_info, "OpenSSH (generic)")
        self.assertEqual(os_family, "Unix")

    def test_ssh_version_extraction(self):
        """Test SSH version extraction from banner."""
        _, _, ssh_ver = self.client._fingerprint_os("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        self.assertEqual(ssh_ver, "OpenSSH_8.9p1 Ubuntu-3")


class TestWeakAlgorithms(unittest.TestCase):
    """Test cases for weak algorithm detection."""

    def setUp(self):
        self.client = SSHAuditClient()

    def test_find_weak_kex(self):
        """Test detection of weak key exchange algorithms."""
        algorithms = {
            'kex': ['curve25519-sha256', 'diffie-hellman-group1-sha1'],
            'ciphers': ['aes256-ctr'],
            'digests': ['hmac-sha2-256'],
            'key_types': ['ssh-ed25519'],
        }
        weak = self.client._find_weak_algorithms(algorithms)
        self.assertIn('kex', weak)
        self.assertEqual(len(weak['kex']), 1)
        self.assertIn('diffie-hellman-group1-sha1', weak['kex'][0])

    def test_find_weak_ciphers(self):
        """Test detection of weak ciphers."""
        algorithms = {
            'ciphers': ['aes256-ctr', 'arcfour', '3des-cbc'],
        }
        weak = self.client._find_weak_algorithms(algorithms)
        self.assertIn('ciphers', weak)
        self.assertEqual(len(weak['ciphers']), 2)

    def test_find_weak_macs(self):
        """Test detection of weak MAC algorithms."""
        algorithms = {
            'digests': ['hmac-sha2-256', 'hmac-md5', 'hmac-sha1'],
        }
        weak = self.client._find_weak_algorithms(algorithms)
        self.assertIn('digests', weak)
        self.assertEqual(len(weak['digests']), 2)

    def test_no_weak_algorithms(self):
        """Test when no weak algorithms are present."""
        algorithms = {
            'kex': ['curve25519-sha256'],
            'ciphers': ['aes256-gcm@openssh.com'],
            'digests': ['hmac-sha2-256'],
            'key_types': ['ssh-ed25519'],
        }
        weak = self.client._find_weak_algorithms(algorithms)
        self.assertEqual(len(weak), 0)

    def test_empty_algorithms(self):
        """Test with empty algorithm dict."""
        weak = self.client._find_weak_algorithms({})
        self.assertEqual(len(weak), 0)


class TestPasswordListBuilding(unittest.TestCase):
    """Test cases for password list building with try_empty and user_as_pass."""

    def test_normal_passwords(self):
        """Test normal password list without extras."""
        client = SSHAuditClient()
        pw_list = client._build_password_list(["pass1", "pass2"], "admin")
        self.assertEqual(pw_list, ["pass1", "pass2"])

    def test_try_empty(self):
        """Test that empty password is prepended."""
        client = SSHAuditClient(try_empty=True)
        pw_list = client._build_password_list(["pass1"], "admin")
        self.assertEqual(pw_list[0], "")
        self.assertEqual(len(pw_list), 2)

    def test_try_empty_already_present(self):
        """Test that empty password is not duplicated."""
        client = SSHAuditClient(try_empty=True)
        pw_list = client._build_password_list(["", "pass1"], "admin")
        self.assertEqual(pw_list.count(""), 1)

    def test_user_as_pass(self):
        """Test that username is prepended as password."""
        client = SSHAuditClient(user_as_pass=True)
        pw_list = client._build_password_list(["pass1"], "admin")
        self.assertEqual(pw_list[0], "admin")
        self.assertEqual(len(pw_list), 2)

    def test_user_as_pass_already_present(self):
        """Test that username is not duplicated in password list."""
        client = SSHAuditClient(user_as_pass=True)
        pw_list = client._build_password_list(["admin", "pass1"], "admin")
        self.assertEqual(pw_list.count("admin"), 1)

    def test_both_try_empty_and_user_as_pass(self):
        """Test both flags together."""
        client = SSHAuditClient(try_empty=True, user_as_pass=True)
        pw_list = client._build_password_list(["pass1"], "admin")
        self.assertIn("", pw_list)
        self.assertIn("admin", pw_list)
        self.assertIn("pass1", pw_list)


class TestStopOnSuccess(unittest.TestCase):
    """Test cases for stop-on-success functionality."""

    def test_should_skip_after_success(self):
        """Test that attempts are skipped after success for a host:port."""
        client = SSHAuditClient(stop_on_success=True)
        client._successful_hosts.add("192.168.1.1:22")
        result = client._should_skip("192.168.1.1", 22, "root")
        self.assertEqual(result, "stop_on_success")

    def test_should_not_skip_different_host(self):
        """Test that different host:port is not skipped."""
        client = SSHAuditClient(stop_on_success=True)
        client._successful_hosts.add("192.168.1.1:22")
        result = client._should_skip("192.168.1.2", 22, "root")
        self.assertIsNone(result)

    def test_should_not_skip_when_disabled(self):
        """Test that nothing is skipped when stop-on-success is disabled."""
        client = SSHAuditClient(stop_on_success=False)
        client._successful_hosts.add("192.168.1.1:22")
        result = client._should_skip("192.168.1.1", 22, "root")
        self.assertIsNone(result)


class TestLockoutProtection(unittest.TestCase):
    """Test cases for account lockout protection."""

    def test_should_skip_after_max_attempts(self):
        """Test that attempts are skipped after max failures."""
        client = SSHAuditClient(max_attempts_per_user=3)
        client._failure_counts["192.168.1.1:22:root"] = 3
        result = client._should_skip("192.168.1.1", 22, "root")
        self.assertEqual(result, "lockout_protection")

    def test_should_not_skip_under_max(self):
        """Test that attempts continue under max failures."""
        client = SSHAuditClient(max_attempts_per_user=3)
        client._failure_counts["192.168.1.1:22:root"] = 2
        result = client._should_skip("192.168.1.1", 22, "root")
        self.assertIsNone(result)

    def test_should_not_skip_different_user(self):
        """Test that different user is not affected by lockout."""
        client = SSHAuditClient(max_attempts_per_user=3)
        client._failure_counts["192.168.1.1:22:root"] = 5
        result = client._should_skip("192.168.1.1", 22, "admin")
        self.assertIsNone(result)

    def test_should_not_skip_when_disabled(self):
        """Test that nothing is skipped when lockout protection is disabled."""
        client = SSHAuditClient(max_attempts_per_user=0)
        client._failure_counts["192.168.1.1:22:root"] = 100
        result = client._should_skip("192.168.1.1", 22, "root")
        self.assertIsNone(result)


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

        # Mock transport for host key and algorithm info
        mock_transport = MagicMock()
        mock_key = MagicMock()
        mock_key.get_name.return_value = "ssh-ed25519"
        mock_key.asbytes.return_value = b"fake_key_bytes"
        mock_key.get_bits.return_value = 256
        mock_transport.get_remote_server_key.return_value = mock_key

        mock_sec_opts = MagicMock()
        mock_sec_opts.kex = ["curve25519-sha256"]
        mock_sec_opts.ciphers = ["aes256-gcm@openssh.com"]
        mock_sec_opts.digests = ["hmac-sha2-256"]
        mock_sec_opts.key_types = ["ssh-ed25519"]
        mock_transport.get_security_options.return_value = mock_sec_opts

        mock_client.get_transport.return_value = mock_transport

        # Mock channel for initial output
        mock_channel = MagicMock()
        mock_channel.recv_ready.side_effect = [True, False]
        mock_channel.recv.return_value = b"Welcome to the server\n"
        mock_client.invoke_shell.return_value = mock_channel

        with patch.object(self.client, '_get_ssh_banner', return_value="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"):
            result = self.client._try_login("192.168.1.1", 22, "admin", "password")

        self.assertTrue(result.success)
        self.assertEqual(result.host, "192.168.1.1")
        self.assertEqual(result.username, "admin")
        self.assertEqual(result.banner, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        self.assertEqual(result.host_key_type, "ssh-ed25519")
        self.assertIn("SHA256:", result.host_key_fingerprint)
        self.assertEqual(result.os_info, "Ubuntu Linux")
        self.assertEqual(result.os_family, "Linux")

    @patch('sshcheck.paramiko.SSHClient')
    def test_successful_login_with_command(self, mock_ssh_class):
        """Test successful SSH login with command execution."""
        self.client.command = "id"
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.return_value = None

        mock_transport = MagicMock()
        mock_key = MagicMock()
        mock_key.get_name.return_value = "ssh-ed25519"
        mock_key.asbytes.return_value = b"fake_key_bytes"
        mock_key.get_bits.return_value = 256
        mock_transport.get_remote_server_key.return_value = mock_key
        mock_sec_opts = MagicMock()
        mock_sec_opts.kex = []
        mock_sec_opts.ciphers = []
        mock_sec_opts.digests = []
        mock_sec_opts.key_types = []
        mock_transport.get_security_options.return_value = mock_sec_opts
        mock_client.get_transport.return_value = mock_transport

        # Mock exec_command
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"uid=0(root) gid=0(root)\n"
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        with patch.object(self.client, '_get_ssh_banner', return_value=""):
            result = self.client._try_login("192.168.1.1", 22, "root", "pass")

        self.assertTrue(result.success)
        self.assertIn("uid=0(root)", result.command_output)

    @patch('sshcheck.paramiko.SSHClient')
    def test_authentication_failure(self, mock_ssh_class):
        """Test authentication failure."""
        import paramiko
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        # Mock authentication failure
        mock_client.connect.side_effect = paramiko.AuthenticationException("Auth failed")

        with patch.object(self.client, '_get_ssh_banner', return_value=""):
            result = self.client._try_login("192.168.1.1", 22, "admin", "wrongpass")

        self.assertFalse(result.success)
        self.assertIn("Authentication failed", result.error_message)
        self.assertEqual(self.client.stats.authentication_errors, 1)

    @patch('sshcheck.paramiko.SSHClient')
    def test_authentication_failure_tracks_lockout(self, mock_ssh_class):
        """Test that auth failure increments lockout counter."""
        import paramiko
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = paramiko.AuthenticationException("Auth failed")

        with patch.object(self.client, '_get_ssh_banner', return_value=""):
            self.client._try_login("192.168.1.1", 22, "root", "wrongpass")

        self.assertEqual(self.client._failure_counts["192.168.1.1:22:root"], 1)

    @patch('sshcheck.paramiko.SSHClient')
    def test_connection_timeout(self, mock_ssh_class):
        """Test connection timeout."""
        import socket
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        # Mock timeout
        mock_client.connect.side_effect = socket.timeout()

        with patch.object(self.client, '_get_ssh_banner', return_value=""):
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
            result = self.client._try_login("192.168.1.1", 22, "admin", "password")

        self.assertFalse(result.success)
        self.assertIn("Connection refused", result.error_message)


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
                banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
                host_key_type="ssh-ed25519",
                host_key_fingerprint="SHA256:ab:cd",
                host_key_bits=256,
                os_info="Ubuntu Linux",
                os_family="Linux",
                ssh_version="OpenSSH_8.9p1 Ubuntu-3",
                severity="high",
                severity_reasons=["Login successful for user 'admin'"],
            ),
            ScanResult(
                host="192.168.1.2",
                port=22,
                username="root",
                password="toor",
                success=False,
                timestamp="2026-01-01T12:00:01",
                error_message="Auth failed",
                severity="info",
                severity_reasons=["No significant findings"],
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
        # Check new fields in JSON
        self.assertEqual(data["results"][0]["host_key_type"], "ssh-ed25519")
        self.assertEqual(data["results"][0]["os_info"], "Ubuntu Linux")
        self.assertEqual(data["results"][0]["severity"], "high")

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
        # Check new columns exist
        self.assertIn("host_key_type", rows[0])
        self.assertIn("os_info", rows[0])
        self.assertIn("severity", rows[0])

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
        self.assertIn("Severity: HIGH", content)
        self.assertIn("Ubuntu Linux", content)

    def test_save_xml_output(self):
        """Test saving results in XML format."""
        import xml.etree.ElementTree as ET
        output_file = os.path.join(self.temp_dir, "results.xml")
        self.client.output_file = output_file
        self.client.output_format = "xml"
        self.client._save_results()

        tree = ET.parse(output_file)
        root = tree.getroot()
        self.assertEqual(root.tag, "sshcheck_scan")
        self.assertEqual(root.get("version"), __version__)

        results = root.find("results")
        self.assertEqual(len(results.findall("result")), 2)

        first_result = results.findall("result")[0]
        self.assertEqual(first_result.find("host").text, "192.168.1.1")
        self.assertEqual(first_result.find("host_key_type").text, "ssh-ed25519")
        self.assertEqual(first_result.find("os_info").text, "Ubuntu Linux")
        self.assertEqual(first_result.find("severity").text, "high")

    def test_save_html_output(self):
        """Test saving results in HTML format."""
        output_file = os.path.join(self.temp_dir, "results.html")
        self.client.output_file = output_file
        self.client.output_format = "html"
        self.client._save_results()

        with open(output_file, 'r') as f:
            content = f.read()

        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("SSH Security Audit Report", content)
        self.assertIn("192.168.1.1", content)
        self.assertIn("Ubuntu Linux", content)
        self.assertIn("ssh-ed25519", content)
        self.assertIn("high", content.lower())


class TestCheckpointResume(unittest.TestCase):
    """Test cases for checkpoint/resume functionality."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_save_checkpoint(self):
        """Test saving checkpoint data."""
        checkpoint_file = os.path.join(self.temp_dir, "checkpoint.json")
        client = SSHAuditClient(checkpoint_file=checkpoint_file)
        client.results = [
            ScanResult(
                host="192.168.1.1", port=22, username="root",
                password="pass", success=False,
                timestamp="2026-01-01T12:00:00",
                error_message="Auth failed"
            )
        ]
        client.stats.total_attempts = 1
        client.stats.failed_logins = 1

        completed = [("192.168.1.1", 22, "root", "pass")]
        client._save_checkpoint(completed)

        self.assertTrue(os.path.exists(checkpoint_file))
        with open(checkpoint_file, 'r') as f:
            data = json.load(f)
        self.assertEqual(len(data["completed"]), 1)
        self.assertEqual(len(data["results"]), 1)
        self.assertEqual(data["stats"]["total_attempts"], 1)

    def test_load_checkpoint(self):
        """Test loading checkpoint data."""
        checkpoint_file = os.path.join(self.temp_dir, "checkpoint.json")
        data = {
            "version": __version__,
            "timestamp": "2026-01-01T12:00:00",
            "completed": [["192.168.1.1", 22, "root", "pass"]],
            "results": [],
            "stats": {"total_attempts": 1, "failed_logins": 1}
        }
        with open(checkpoint_file, 'w') as f:
            json.dump(data, f)

        client = SSHAuditClient(checkpoint_file=checkpoint_file)
        loaded = client._load_checkpoint()
        self.assertIsNotNone(loaded)
        self.assertEqual(len(loaded["completed"]), 1)

    def test_load_nonexistent_checkpoint(self):
        """Test loading non-existent checkpoint returns None."""
        client = SSHAuditClient(
            checkpoint_file=os.path.join(self.temp_dir, "missing.json")
        )
        loaded = client._load_checkpoint()
        self.assertIsNone(loaded)

    def test_load_no_checkpoint_file(self):
        """Test loading when no checkpoint file is set."""
        client = SSHAuditClient()
        loaded = client._load_checkpoint()
        self.assertIsNone(loaded)


class TestConfigFile(unittest.TestCase):
    """Test cases for configuration file support."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_load_json_config(self):
        """Test loading JSON config file."""
        config_file = os.path.join(self.temp_dir, "config.json")
        config = {
            "targets": ["192.168.1.1"],
            "users": ["root"],
            "passwords": ["pass"],
            "threads": 5,
            "timeout": 15,
            "try_empty": True,
        }
        with open(config_file, 'w') as f:
            json.dump(config, f)

        loaded = load_config_file(config_file)
        self.assertEqual(loaded["targets"], ["192.168.1.1"])
        self.assertEqual(loaded["threads"], 5)
        self.assertTrue(loaded["try_empty"])

    def test_apply_config_to_args(self):
        """Test applying config values to argparse namespace."""
        import argparse
        args = argparse.Namespace(
            targets=None, target_file=None, users=None, user_file=None,
            passwords=None, password_file=None, ports=None, port_file=None,
            output=None, format='text', verbose=False, quiet=False,
            threads=1, timeout=10, try_empty=False, user_as_pass=False,
            stop_on_success=False, max_attempts_per_user=0, command=None,
            checkpoint=None
        )
        config = {
            "targets": ["192.168.1.0/24"],
            "users": ["root", "admin"],
            "passwords": ["pass1", "pass2"],
            "threads": 10,
            "try_empty": True,
        }
        apply_config(args, config)
        self.assertEqual(args.targets, ["192.168.1.0/24"])
        self.assertEqual(args.users, ["root", "admin"])
        self.assertEqual(args.threads, 10)
        self.assertTrue(args.try_empty)

    def test_cli_overrides_config(self):
        """Test that CLI arguments override config file."""
        import argparse
        args = argparse.Namespace(
            targets=["10.0.0.1"], target_file=None, users=["testuser"],
            user_file=None, passwords=["testpass"], password_file=None,
            ports=None, port_file=None, output=None, format='text',
            verbose=False, quiet=False, threads=1, timeout=10,
            try_empty=False, user_as_pass=False, stop_on_success=False,
            max_attempts_per_user=0, command=None, checkpoint=None
        )
        config = {
            "targets": ["192.168.1.0/24"],
            "users": ["root"],
            "threads": 10,
        }
        apply_config(args, config)
        # CLI values should be preserved
        self.assertEqual(args.targets, ["10.0.0.1"])
        self.assertEqual(args.users, ["testuser"])

    def test_config_string_to_list(self):
        """Test that single string values are converted to lists."""
        import argparse
        args = argparse.Namespace(
            targets=None, target_file=None, users=None, user_file=None,
            passwords=None, password_file=None, ports=None, port_file=None,
            output=None, format='text', verbose=False, quiet=False,
            threads=1, timeout=10, try_empty=False, user_as_pass=False,
            stop_on_success=False, max_attempts_per_user=0, command=None,
            checkpoint=None
        )
        config = {"targets": "192.168.1.1"}
        apply_config(args, config)
        self.assertEqual(args.targets, ["192.168.1.1"])


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

    def test_xml_format(self):
        """Test parsing XML output format."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '-f', 'xml']):
            args = parse_arguments()
        self.assertEqual(args.format, 'xml')

    def test_html_format(self):
        """Test parsing HTML output format."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '-f', 'html']):
            args = parse_arguments()
        self.assertEqual(args.format, 'html')

    def test_verbose_flag(self):
        """Test parsing verbose flag."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '-v']):
            args = parse_arguments()
        self.assertTrue(args.verbose)

    def test_try_empty_flag(self):
        """Test parsing --try-empty flag."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--try-empty']):
            args = parse_arguments()
        self.assertTrue(args.try_empty)

    def test_user_as_pass_flag(self):
        """Test parsing --user-as-pass flag."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--user-as-pass']):
            args = parse_arguments()
        self.assertTrue(args.user_as_pass)

    def test_stop_on_success_flag(self):
        """Test parsing --stop-on-success flag."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--stop-on-success']):
            args = parse_arguments()
        self.assertTrue(args.stop_on_success)

    def test_max_attempts_per_user(self):
        """Test parsing --max-attempts-per-user."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--max-attempts-per-user', '3']):
            args = parse_arguments()
        self.assertEqual(args.max_attempts_per_user, 3)

    def test_command_option(self):
        """Test parsing -c/--command option."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '-c', 'id; uname -a']):
            args = parse_arguments()
        self.assertEqual(args.command, 'id; uname -a')

    def test_checkpoint_option(self):
        """Test parsing --checkpoint option."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--checkpoint', 'scan.checkpoint']):
            args = parse_arguments()
        self.assertEqual(args.checkpoint, 'scan.checkpoint')

    def test_resume_option(self):
        """Test parsing --resume option."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--resume', 'scan.checkpoint']):
            args = parse_arguments()
        self.assertEqual(args.resume, 'scan.checkpoint')

    def test_config_option(self):
        """Test parsing --config option."""
        with patch('sys.argv', ['sshcheck', '--config', 'scan.yaml',
                                '-t', '192.168.1.1', '-u', 'root', '-p', 'pass']):
            args = parse_arguments()
        self.assertEqual(args.config, 'scan.yaml')

    def test_default_values(self):
        """Test default argument values."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root', '-p', 'pass']):
            args = parse_arguments()
        self.assertEqual(args.timeout, 10)
        self.assertEqual(args.threads, 1)
        self.assertEqual(args.format, 'text')
        self.assertFalse(args.verbose)
        self.assertFalse(args.try_empty)
        self.assertFalse(args.user_as_pass)
        self.assertFalse(args.stop_on_success)
        self.assertEqual(args.max_attempts_per_user, 0)
        self.assertIsNone(args.command)
        self.assertIsNone(args.config)
        self.assertIsNone(args.ports)


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
    def test_scan_with_try_empty(self, mock_ssh_class):
        """Test scan with --try-empty adds empty password attempts."""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Connection failed")

        client = SSHAuditClient(try_empty=True)

        with patch.object(client, '_get_ssh_banner', return_value=""):
            with patch('sys.stdout', new_callable=StringIO):
                results = client.scan(
                    ["192.168.1.1"],
                    ["root"],
                    ["password"],
                    [22]
                )

        # 1 host * 1 user * 2 passwords (empty + "password") = 2 attempts
        self.assertEqual(len(results), 2)
        passwords_tried = {r.password for r in results}
        self.assertIn("", passwords_tried)
        self.assertIn("password", passwords_tried)

    @patch('sshcheck.paramiko.SSHClient')
    def test_scan_with_user_as_pass(self, mock_ssh_class):
        """Test scan with --user-as-pass adds username as password."""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Connection failed")

        client = SSHAuditClient(user_as_pass=True)

        with patch.object(client, '_get_ssh_banner', return_value=""):
            with patch('sys.stdout', new_callable=StringIO):
                results = client.scan(
                    ["192.168.1.1"],
                    ["admin"],
                    ["password"],
                    [22]
                )

        # 1 host * 1 user * 2 passwords ("admin" + "password") = 2 attempts
        self.assertEqual(len(results), 2)
        passwords_tried = {r.password for r in results}
        self.assertIn("admin", passwords_tried)
        self.assertIn("password", passwords_tried)

    @patch('sshcheck.paramiko.SSHClient')
    def test_scan_only_try_empty_no_passwords(self, mock_ssh_class):
        """Test scan with only --try-empty and no explicit passwords."""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Connection failed")

        client = SSHAuditClient(try_empty=True)

        with patch.object(client, '_get_ssh_banner', return_value=""):
            with patch('sys.stdout', new_callable=StringIO):
                results = client.scan(
                    ["192.168.1.1"],
                    ["root"],
                    [],  # No explicit passwords
                    [22]
                )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].password, "")

    @patch('sshcheck.paramiko.SSHClient')
    def test_scan_with_checkpoint(self, mock_ssh_class):
        """Test scan with checkpoint saving."""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Connection failed")

        checkpoint_file = os.path.join(self.temp_dir, "scan.checkpoint")
        client = SSHAuditClient(checkpoint_file=checkpoint_file)

        with patch.object(client, '_get_ssh_banner', return_value=""):
            with patch('sys.stdout', new_callable=StringIO):
                results = client.scan(
                    ["192.168.1.1"],
                    ["root"],
                    ["pass"],
                    [22]
                )

        # Checkpoint should be saved
        self.assertTrue(os.path.exists(checkpoint_file))


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
        """Test scanning with empty users."""
        with patch('sys.stdout', new_callable=StringIO):
            with patch('sys.stderr', new_callable=StringIO):
                results = self.client.scan(["192.168.1.1"], [], ["pass"], [22])
        self.assertEqual(len(results), 0)

    def test_empty_passwords(self):
        """Test scanning with empty passwords."""
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

    def test_quiet_mode_suppresses_progress(self):
        """Test that quiet mode suppresses progress output."""
        client = SSHAuditClient(quiet=True)
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="pass", success=False, timestamp="2026-01-01T12:00:00"
        )
        # Should not raise or print anything
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            client._print_progress(result, 1, 10)
        self.assertEqual(mock_out.getvalue(), "")


class TestSprayMode(unittest.TestCase):
    """Test cases for credential spray mode."""

    @patch('sshcheck.paramiko.SSHClient')
    def test_spray_mode_order(self, mock_ssh_class):
        """Test that spray mode tries one password across all users/hosts first."""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Connection failed")

        client = SSHAuditClient(spray_mode=True)

        with patch.object(client, '_get_ssh_banner', return_value=""):
            with patch('sys.stdout', new_callable=StringIO):
                results = client.scan(
                    ["192.168.1.1", "192.168.1.2"],
                    ["root", "admin"],
                    ["pass1", "pass2"],
                    [22]
                )

        # Should have 2 hosts * 2 users * 2 passwords = 8 attempts
        self.assertEqual(len(results), 8)

        # In spray mode, first 4 attempts should all use the same password
        # (user_as_pass adds 'root' and 'admin' as first passwords for each user)
        # Without user_as_pass, first 4 should be pass1
        first_four_passwords = [r.password for r in results[:4]]
        # In spray mode the first password round goes across all hosts/users
        # All attempts in a round should have the same password
        self.assertEqual(len(set(first_four_passwords)), 1)

    @patch('sshcheck.paramiko.SSHClient')
    def test_spray_mode_disabled_by_default(self, mock_ssh_class):
        """Test that spray mode is disabled by default."""
        client = SSHAuditClient()
        self.assertFalse(client.spray_mode)

    @patch('sshcheck.paramiko.SSHClient')
    def test_spray_vs_normal_mode_same_count(self, mock_ssh_class):
        """Test that spray and normal mode produce same number of attempts."""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Failed")

        # Normal mode
        normal_client = SSHAuditClient()
        with patch.object(normal_client, '_get_ssh_banner', return_value=""):
            with patch('sys.stdout', new_callable=StringIO):
                normal_results = normal_client.scan(
                    ["192.168.1.1"], ["root", "admin"], ["pass1", "pass2"], [22]
                )

        # Spray mode
        spray_client = SSHAuditClient(spray_mode=True)
        with patch.object(spray_client, '_get_ssh_banner', return_value=""):
            with patch('sys.stdout', new_callable=StringIO):
                spray_results = spray_client.scan(
                    ["192.168.1.1"], ["root", "admin"], ["pass1", "pass2"], [22]
                )

        self.assertEqual(len(normal_results), len(spray_results))

    def test_spray_mode_argument_parsing(self):
        """Test parsing --spray flag."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--spray']):
            args = parse_arguments()
        self.assertTrue(args.spray)

    def test_spray_mode_default_false(self):
        """Test --spray defaults to False."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root', '-p', 'pass']):
            args = parse_arguments()
        self.assertFalse(args.spray)


class TestTargetExclusion(unittest.TestCase):
    """Test cases for target exclusion functionality."""

    def test_exclude_single_host(self):
        """Test excluding a single host."""
        client = SSHAuditClient(exclude_hosts=["192.168.1.5"])
        self.assertTrue(client._is_excluded("192.168.1.5"))
        self.assertFalse(client._is_excluded("192.168.1.6"))

    def test_exclude_cidr_range(self):
        """Test excluding a CIDR range."""
        client = SSHAuditClient(exclude_hosts=["192.168.1.0/30"])
        self.assertTrue(client._is_excluded("192.168.1.1"))
        self.assertTrue(client._is_excluded("192.168.1.2"))
        self.assertFalse(client._is_excluded("192.168.1.5"))

    def test_exclude_ip_range(self):
        """Test excluding an IP range."""
        client = SSHAuditClient(exclude_hosts=["192.168.1.1-3"])
        self.assertTrue(client._is_excluded("192.168.1.1"))
        self.assertTrue(client._is_excluded("192.168.1.2"))
        self.assertTrue(client._is_excluded("192.168.1.3"))
        self.assertFalse(client._is_excluded("192.168.1.4"))

    def test_exclude_multiple_hosts(self):
        """Test excluding multiple individual hosts."""
        client = SSHAuditClient(exclude_hosts=["192.168.1.1", "192.168.1.5", "10.0.0.1"])
        self.assertTrue(client._is_excluded("192.168.1.1"))
        self.assertTrue(client._is_excluded("192.168.1.5"))
        self.assertTrue(client._is_excluded("10.0.0.1"))
        self.assertFalse(client._is_excluded("192.168.1.2"))

    def test_no_exclusions(self):
        """Test with no exclusions configured."""
        client = SSHAuditClient()
        self.assertFalse(client._is_excluded("192.168.1.1"))

    @patch('sshcheck.paramiko.SSHClient')
    def test_excluded_hosts_not_scanned(self, mock_ssh_class):
        """Test that excluded hosts are actually skipped during scan."""
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Failed")

        client = SSHAuditClient(exclude_hosts=["192.168.1.2"])

        with patch.object(client, '_get_ssh_banner', return_value=""):
            with patch('sys.stdout', new_callable=StringIO):
                results = client.scan(
                    ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
                    ["root"], ["pass"], [22]
                )

        # Only 2 hosts should be scanned (1.2 excluded)
        scanned_hosts = {r.host for r in results}
        self.assertNotIn("192.168.1.2", scanned_hosts)
        self.assertIn("192.168.1.1", scanned_hosts)
        self.assertIn("192.168.1.3", scanned_hosts)
        self.assertEqual(len(results), 2)

    def test_exclude_argument_parsing(self):
        """Test parsing --exclude arguments."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.0/24', '-u', 'root',
                                '-p', 'pass', '--exclude', '192.168.1.1',
                                '--exclude', '192.168.1.254']):
            args = parse_arguments()
        self.assertEqual(args.exclude_hosts, ['192.168.1.1', '192.168.1.254'])

    def test_exclude_file_argument_parsing(self):
        """Test parsing --exclude-file argument."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.0/24', '-u', 'root',
                                '-p', 'pass', '--exclude-file', 'exclude.txt']):
            args = parse_arguments()
        self.assertEqual(args.exclude_file, 'exclude.txt')


class TestHoneypotDetection(unittest.TestCase):
    """Test cases for honeypot detection."""

    def setUp(self):
        self.client = SSHAuditClient(detect_honeypot=True)

    def test_known_honeypot_banner(self):
        """Test detection of known Cowrie honeypot banner."""
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="root", success=True,
            timestamp="2026-01-01T12:00:00",
            banner="SSH-2.0-libssh-0.6.0"
        )
        score, reasons = self.client._detect_honeypot_indicators(result)
        self.assertGreater(score, 0.3)
        self.assertTrue(any("honeypot banner" in r.lower() for r in reasons))

    def test_suspicious_banner_pattern(self):
        """Test detection of suspicious banner pattern."""
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="root", success=True,
            timestamp="2026-01-01T12:00:00",
            banner="SSH-2.0-libssh-0.5.3"
        )
        score, reasons = self.client._detect_honeypot_indicators(result)
        self.assertGreater(score, 0.0)

    def test_suspicious_output_pattern(self):
        """Test detection of known honeypot output."""
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="root", success=True,
            timestamp="2026-01-01T12:00:00",
            banner="SSH-2.0-OpenSSH_8.0",
            initial_output="root@svr04:~# "
        )
        score, reasons = self.client._detect_honeypot_indicators(result)
        self.assertGreater(score, 0.0)
        self.assertTrue(any("output pattern" in r.lower() for r in reasons))

    def test_root_trivial_password(self):
        """Test honeypot score increase for root with trivial password."""
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="", success=True,
            timestamp="2026-01-01T12:00:00",
            banner="SSH-2.0-OpenSSH_8.0"
        )
        score, reasons = self.client._detect_honeypot_indicators(result)
        self.assertGreater(score, 0.0)
        self.assertTrue(any("trivial password" in r.lower() for r in reasons))

    def test_no_honeypot_indicators(self):
        """Test normal host with no honeypot indicators."""
        result = ScanResult(
            host="192.168.1.1", port=22, username="admin",
            password="s3cur3P@ss!", success=True,
            timestamp="2026-01-01T12:00:00",
            banner="SSH-2.0-OpenSSH_9.0p1 Ubuntu-1",
            connection_time=0.5
        )
        score, reasons = self.client._detect_honeypot_indicators(result)
        self.assertEqual(score, 0.0)
        self.assertEqual(len(reasons), 0)

    def test_failed_login_no_honeypot_check(self):
        """Test that failed logins get minimal honeypot score."""
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="wrong", success=False,
            timestamp="2026-01-01T12:00:00",
            banner="SSH-2.0-OpenSSH_9.0"
        )
        score, reasons = self.client._detect_honeypot_indicators(result)
        # Failed login should not trigger root+trivial password check
        self.assertEqual(score, 0.0)

    def test_high_honeypot_score_multiple_indicators(self):
        """Test high score when multiple indicators present."""
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="root", success=True,
            timestamp="2026-01-01T12:00:00",
            banner="SSH-2.0-libssh-0.6.0",
            initial_output="root@svr04:~# ",
            connection_time=0.01
        )
        score, reasons = self.client._detect_honeypot_indicators(result)
        self.assertGreaterEqual(score, 0.7)
        self.assertGreater(len(reasons), 2)

    def test_honeypot_score_capped_at_one(self):
        """Test that honeypot score is capped at 1.0."""
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="", success=True,
            timestamp="2026-01-01T12:00:00",
            banner="SSH-2.0-libssh-0.6.0",
            initial_output="root@svr04:~# uid=0(root) gid=0(root) groups=0(root)",
            connection_time=0.01
        )
        score, reasons = self.client._detect_honeypot_indicators(result)
        self.assertLessEqual(score, 1.0)

    def test_detect_honeypot_argument_parsing(self):
        """Test parsing --detect-honeypot flag."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--detect-honeypot']):
            args = parse_arguments()
        self.assertTrue(args.detect_honeypot)


class TestNmapXMLImport(unittest.TestCase):
    """Test cases for Nmap XML import functionality."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_import_basic_nmap_xml(self):
        """Test importing a basic Nmap XML with SSH hosts."""
        nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.2"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        filepath = os.path.join(self.temp_dir, "scan.xml")
        with open(filepath, 'w') as f:
            f.write(nmap_xml)

        targets = SSHAuditClient.import_nmap_xml(filepath)
        self.assertEqual(len(targets), 2)
        self.assertIn("192.168.1.1:22", targets)
        self.assertIn("192.168.1.2:22", targets)

    def test_import_nmap_nonstandard_ssh_port(self):
        """Test importing Nmap XML with SSH on non-standard port."""
        nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="2222">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        filepath = os.path.join(self.temp_dir, "scan.xml")
        with open(filepath, 'w') as f:
            f.write(nmap_xml)

        targets = SSHAuditClient.import_nmap_xml(filepath)
        self.assertEqual(len(targets), 1)
        self.assertIn("10.0.0.1:2222", targets)

    def test_import_nmap_no_ssh_hosts(self):
        """Test importing Nmap XML with no SSH hosts."""
        nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        filepath = os.path.join(self.temp_dir, "scan.xml")
        with open(filepath, 'w') as f:
            f.write(nmap_xml)

        targets = SSHAuditClient.import_nmap_xml(filepath)
        self.assertEqual(len(targets), 0)

    def test_import_nmap_closed_ssh_port(self):
        """Test that closed SSH ports are not imported."""
        nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        filepath = os.path.join(self.temp_dir, "scan.xml")
        with open(filepath, 'w') as f:
            f.write(nmap_xml)

        targets = SSHAuditClient.import_nmap_xml(filepath)
        self.assertEqual(len(targets), 0)

    def test_import_nmap_down_host(self):
        """Test that down hosts are not imported."""
        nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="down"/>
    <address addr="192.168.1.1"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        filepath = os.path.join(self.temp_dir, "scan.xml")
        with open(filepath, 'w') as f:
            f.write(nmap_xml)

        targets = SSHAuditClient.import_nmap_xml(filepath)
        self.assertEqual(len(targets), 0)

    def test_import_nmap_file_not_found(self):
        """Test error on non-existent Nmap file."""
        with self.assertRaises(FileNotFoundError):
            SSHAuditClient.import_nmap_xml("/nonexistent/scan.xml")

    def test_import_nmap_invalid_xml(self):
        """Test error on invalid XML."""
        filepath = os.path.join(self.temp_dir, "bad.xml")
        with open(filepath, 'w') as f:
            f.write("not valid xml <><>")

        with self.assertRaises(ValueError):
            SSHAuditClient.import_nmap_xml(filepath)

    def test_import_nmap_common_port_without_service(self):
        """Test that port 22 is detected even without service info."""
        nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        filepath = os.path.join(self.temp_dir, "scan.xml")
        with open(filepath, 'w') as f:
            f.write(nmap_xml)

        targets = SSHAuditClient.import_nmap_xml(filepath)
        self.assertEqual(len(targets), 1)
        self.assertIn("192.168.1.1:22", targets)

    def test_import_nmap_argument_parsing(self):
        """Test parsing --import-nmap argument."""
        with patch('sys.argv', ['sshcheck', '--import-nmap', 'scan.xml',
                                '-u', 'root', '-p', 'pass']):
            args = parse_arguments()
        self.assertEqual(args.import_nmap, 'scan.xml')


class TestBaselineComparison(unittest.TestCase):
    """Test cases for baseline comparison functionality."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_baseline(self, results):
        """Helper to create a baseline file."""
        filepath = os.path.join(self.temp_dir, "baseline.json")
        data = {
            "scan_info": {"version": __version__},
            "results": results
        }
        with open(filepath, 'w') as f:
            json.dump(data, f)
        return filepath

    def test_no_changes(self):
        """Test baseline comparison with no changes."""
        baseline = self._create_baseline([
            {"host": "192.168.1.1", "port": 22, "username": "root",
             "password": "pass", "success": True,
             "host_key_fingerprint": "SHA256:abc", "host_key_type": "ssh-ed25519",
             "ssh_version": "OpenSSH_9.0"}
        ])
        current = [ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="pass", success=True,
            timestamp="2026-01-01T12:00:00",
            host_key_fingerprint="SHA256:abc", host_key_type="ssh-ed25519",
            ssh_version="OpenSSH_9.0"
        )]
        diff = SSHAuditClient.compare_baseline(current, baseline)
        self.assertEqual(diff['summary']['new_hosts_count'], 0)
        self.assertEqual(diff['summary']['removed_hosts_count'], 0)
        self.assertEqual(diff['summary']['new_credentials_count'], 0)
        self.assertEqual(diff['summary']['host_key_changes_count'], 0)

    def test_new_host_detected(self):
        """Test detecting a new host."""
        baseline = self._create_baseline([
            {"host": "192.168.1.1", "port": 22, "username": "root",
             "password": "pass", "success": False}
        ])
        current = [
            ScanResult(host="192.168.1.1", port=22, username="root",
                       password="pass", success=False, timestamp="2026-01-01T12:00:00"),
            ScanResult(host="192.168.1.2", port=22, username="root",
                       password="pass", success=False, timestamp="2026-01-01T12:00:01"),
        ]
        diff = SSHAuditClient.compare_baseline(current, baseline)
        self.assertEqual(diff['summary']['new_hosts_count'], 1)
        self.assertEqual(diff['new_hosts'][0]['host'], "192.168.1.2")

    def test_removed_host_detected(self):
        """Test detecting a removed host."""
        baseline = self._create_baseline([
            {"host": "192.168.1.1", "port": 22, "username": "root",
             "password": "pass", "success": False},
            {"host": "192.168.1.2", "port": 22, "username": "root",
             "password": "pass", "success": False},
        ])
        current = [
            ScanResult(host="192.168.1.1", port=22, username="root",
                       password="pass", success=False, timestamp="2026-01-01T12:00:00"),
        ]
        diff = SSHAuditClient.compare_baseline(current, baseline)
        self.assertEqual(diff['summary']['removed_hosts_count'], 1)
        self.assertEqual(diff['removed_hosts'][0]['host'], "192.168.1.2")

    def test_new_credential_detected(self):
        """Test detecting new valid credentials."""
        baseline = self._create_baseline([
            {"host": "192.168.1.1", "port": 22, "username": "root",
             "password": "pass", "success": False}
        ])
        current = [
            ScanResult(host="192.168.1.1", port=22, username="root",
                       password="pass", success=True, timestamp="2026-01-01T12:00:00"),
        ]
        diff = SSHAuditClient.compare_baseline(current, baseline)
        self.assertEqual(diff['summary']['new_credentials_count'], 1)

    def test_lost_credential_detected(self):
        """Test detecting credentials that stopped working."""
        baseline = self._create_baseline([
            {"host": "192.168.1.1", "port": 22, "username": "root",
             "password": "pass", "success": True}
        ])
        current = [
            ScanResult(host="192.168.1.1", port=22, username="root",
                       password="pass", success=False, timestamp="2026-01-01T12:00:00"),
        ]
        diff = SSHAuditClient.compare_baseline(current, baseline)
        self.assertEqual(diff['summary']['lost_credentials_count'], 1)

    def test_host_key_change_detected(self):
        """Test detecting host key changes."""
        baseline = self._create_baseline([
            {"host": "192.168.1.1", "port": 22, "username": "root",
             "password": "pass", "success": True,
             "host_key_fingerprint": "SHA256:old_key",
             "host_key_type": "ssh-ed25519"}
        ])
        current = [
            ScanResult(host="192.168.1.1", port=22, username="root",
                       password="pass", success=True,
                       timestamp="2026-01-01T12:00:00",
                       host_key_fingerprint="SHA256:new_key",
                       host_key_type="ssh-ed25519"),
        ]
        diff = SSHAuditClient.compare_baseline(current, baseline)
        self.assertEqual(diff['summary']['host_key_changes_count'], 1)
        self.assertEqual(diff['host_key_changes'][0]['previous_fingerprint'], "SHA256:old_key")
        self.assertEqual(diff['host_key_changes'][0]['current_fingerprint'], "SHA256:new_key")

    def test_ssh_version_change_detected(self):
        """Test detecting SSH version changes."""
        baseline = self._create_baseline([
            {"host": "192.168.1.1", "port": 22, "username": "root",
             "password": "pass", "success": False,
             "ssh_version": "OpenSSH_7.9"}
        ])
        current = [
            ScanResult(host="192.168.1.1", port=22, username="root",
                       password="pass", success=False,
                       timestamp="2026-01-01T12:00:00",
                       ssh_version="OpenSSH_9.0"),
        ]
        diff = SSHAuditClient.compare_baseline(current, baseline)
        self.assertEqual(diff['summary']['ssh_version_changes_count'], 1)
        self.assertEqual(diff['ssh_version_changes'][0]['previous_version'], "OpenSSH_7.9")
        self.assertEqual(diff['ssh_version_changes'][0]['current_version'], "OpenSSH_9.0")

    def test_baseline_file_not_found(self):
        """Test error on non-existent baseline file."""
        current = [ScanResult(host="192.168.1.1", port=22, username="root",
                              password="pass", success=False, timestamp="now")]
        with self.assertRaises(FileNotFoundError):
            SSHAuditClient.compare_baseline(current, "/nonexistent/baseline.json")

    def test_baseline_invalid_json(self):
        """Test error on invalid JSON baseline."""
        filepath = os.path.join(self.temp_dir, "bad.json")
        with open(filepath, 'w') as f:
            f.write("not json{{}}")

        current = [ScanResult(host="192.168.1.1", port=22, username="root",
                              password="pass", success=False, timestamp="now")]
        with self.assertRaises(ValueError):
            SSHAuditClient.compare_baseline(current, filepath)

    def test_baseline_argument_parsing(self):
        """Test parsing --baseline argument."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--baseline', 'prev_scan.json']):
            args = parse_arguments()
        self.assertEqual(args.baseline, 'prev_scan.json')


class TestHostKeyContinuity(unittest.TestCase):
    """Test cases for host key continuity checking."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_load_json_known_hosts(self):
        """Test loading known hosts from JSON format."""
        filepath = os.path.join(self.temp_dir, "known_hosts.json")
        data = {
            "192.168.1.1:22": {
                "type": "ssh-ed25519",
                "fingerprint": "SHA256:abc123"
            },
            "10.0.0.1:2222": {
                "type": "ssh-rsa",
                "fingerprint": "SHA256:def456"
            }
        }
        with open(filepath, 'w') as f:
            json.dump(data, f)

        client = SSHAuditClient(known_hosts_file=filepath)
        self.assertEqual(len(client._known_host_keys), 2)
        self.assertEqual(client._known_host_keys["192.168.1.1:22"][1], "SHA256:abc123")
        self.assertEqual(client._known_host_keys["10.0.0.1:2222"][0], "ssh-rsa")

    def test_load_openssh_known_hosts(self):
        """Test loading known hosts from OpenSSH format."""
        import base64
        # Create a fake key and compute its expected fingerprint
        fake_key_bytes = b"fake_ssh_key_data_for_testing_1234"
        key_b64 = base64.b64encode(fake_key_bytes).decode()
        expected_fp = hashlib.sha256(fake_key_bytes).hexdigest()
        expected_fp_formatted = ':'.join(
            expected_fp[i:i+2] for i in range(0, len(expected_fp), 2)
        )

        filepath = os.path.join(self.temp_dir, "known_hosts")
        with open(filepath, 'w') as f:
            f.write(f"# Comment line\n")
            f.write(f"192.168.1.1 ssh-ed25519 {key_b64}\n")
            f.write(f"10.0.0.1 ssh-rsa {key_b64}\n")

        client = SSHAuditClient(known_hosts_file=filepath)
        self.assertGreater(len(client._known_host_keys), 0)
        # Check that host was loaded with default port 22
        self.assertIn("192.168.1.1:22", client._known_host_keys)

    def test_host_key_no_change(self):
        """Test host key continuity check when key hasn't changed."""
        filepath = os.path.join(self.temp_dir, "known_hosts.json")
        data = {
            "192.168.1.1:22": {
                "type": "ssh-ed25519",
                "fingerprint": "SHA256:abc123"
            }
        }
        with open(filepath, 'w') as f:
            json.dump(data, f)

        client = SSHAuditClient(known_hosts_file=filepath)
        changed, prev = client._check_host_key_continuity(
            "192.168.1.1", 22, "ssh-ed25519", "SHA256:abc123"
        )
        self.assertFalse(changed)
        self.assertEqual(prev, "")

    def test_host_key_changed(self):
        """Test host key continuity check when key HAS changed (MITM)."""
        filepath = os.path.join(self.temp_dir, "known_hosts.json")
        data = {
            "192.168.1.1:22": {
                "type": "ssh-ed25519",
                "fingerprint": "SHA256:old_fingerprint"
            }
        }
        with open(filepath, 'w') as f:
            json.dump(data, f)

        client = SSHAuditClient(known_hosts_file=filepath)
        changed, prev = client._check_host_key_continuity(
            "192.168.1.1", 22, "ssh-ed25519", "SHA256:new_fingerprint"
        )
        self.assertTrue(changed)
        self.assertEqual(prev, "SHA256:old_fingerprint")

    def test_host_key_unknown_host(self):
        """Test host key check for unknown host (not in known_hosts)."""
        filepath = os.path.join(self.temp_dir, "known_hosts.json")
        data = {
            "192.168.1.1:22": {
                "type": "ssh-ed25519",
                "fingerprint": "SHA256:abc123"
            }
        }
        with open(filepath, 'w') as f:
            json.dump(data, f)

        client = SSHAuditClient(known_hosts_file=filepath)
        changed, prev = client._check_host_key_continuity(
            "10.0.0.1", 22, "ssh-ed25519", "SHA256:xyz789"
        )
        self.assertFalse(changed)

    def test_save_known_hosts(self):
        """Test saving discovered host keys."""
        filepath = os.path.join(self.temp_dir, "known_hosts.json")
        client = SSHAuditClient(known_hosts_file=filepath)
        client.results = [
            ScanResult(
                host="192.168.1.1", port=22, username="root",
                password="pass", success=True,
                timestamp="2026-01-01T12:00:00",
                host_key_type="ssh-ed25519",
                host_key_fingerprint="SHA256:abc123",
                host_key_bits=256
            ),
            ScanResult(
                host="10.0.0.1", port=2222, username="admin",
                password="pass", success=True,
                timestamp="2026-01-01T12:00:01",
                host_key_type="ssh-rsa",
                host_key_fingerprint="SHA256:def456",
                host_key_bits=4096
            ),
        ]
        client._save_known_hosts(filepath)

        with open(filepath, 'r') as f:
            saved = json.load(f)

        self.assertIn("192.168.1.1:22", saved)
        self.assertIn("10.0.0.1:2222", saved)
        self.assertEqual(saved["192.168.1.1:22"]["type"], "ssh-ed25519")
        self.assertEqual(saved["10.0.0.1:2222"]["fingerprint"], "SHA256:def456")

    def test_severity_critical_on_key_change(self):
        """Test that host key change triggers CRITICAL severity."""
        client = SSHAuditClient()
        result = ScanResult(
            host="192.168.1.1", port=22, username="user",
            password="pass", success=False,
            timestamp="2026-01-01T12:00:00",
            host_key_changed=True,
            host_key_previous="SHA256:old_key"
        )
        severity, reasons = client._assess_severity(result)
        self.assertEqual(severity, "critical")
        self.assertTrue(any("MITM" in r for r in reasons))

    def test_nonexistent_known_hosts_file(self):
        """Test graceful handling of non-existent known hosts file."""
        client = SSHAuditClient(known_hosts_file="/nonexistent/file.json")
        self.assertEqual(len(client._known_host_keys), 0)

    def test_known_hosts_argument_parsing(self):
        """Test parsing --known-hosts argument."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root',
                                '-p', 'pass', '--known-hosts', 'hosts.json']):
            args = parse_arguments()
        self.assertEqual(args.known_hosts, 'hosts.json')


class TestScanResultNewFields(unittest.TestCase):
    """Test cases for new ScanResult fields (honeypot, host key change)."""

    def test_scan_result_honeypot_fields(self):
        """Test ScanResult honeypot fields."""
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="root", success=True,
            timestamp="2026-01-01T12:00:00",
            honeypot_score=0.7,
            honeypot_reasons=["Known honeypot banner"]
        )
        self.assertEqual(result.honeypot_score, 0.7)
        self.assertEqual(len(result.honeypot_reasons), 1)

    def test_scan_result_host_key_change_fields(self):
        """Test ScanResult host key change fields."""
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="pass", success=True,
            timestamp="2026-01-01T12:00:00",
            host_key_changed=True,
            host_key_previous="SHA256:old"
        )
        self.assertTrue(result.host_key_changed)
        self.assertEqual(result.host_key_previous, "SHA256:old")

    def test_scan_result_to_dict_new_fields(self):
        """Test to_dict includes new fields."""
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="pass", success=True,
            timestamp="2026-01-01T12:00:00",
            honeypot_score=0.5,
            host_key_changed=True
        )
        d = result.to_dict()
        self.assertIn('honeypot_score', d)
        self.assertIn('honeypot_reasons', d)
        self.assertIn('host_key_changed', d)
        self.assertIn('host_key_previous', d)
        self.assertEqual(d['honeypot_score'], 0.5)
        self.assertTrue(d['host_key_changed'])
        # None honeypot_reasons should be converted to empty list
        self.assertEqual(d['honeypot_reasons'], [])

    def test_scan_result_defaults(self):
        """Test default values for new fields."""
        result = ScanResult(
            host="192.168.1.1", port=22, username="root",
            password="pass", success=False,
            timestamp="2026-01-01T12:00:00"
        )
        self.assertEqual(result.honeypot_score, 0.0)
        self.assertIsNone(result.honeypot_reasons)
        self.assertFalse(result.host_key_changed)
        self.assertEqual(result.host_key_previous, "")


class TestNewArgumentDefaults(unittest.TestCase):
    """Test default values for new CLI arguments."""

    def test_all_new_defaults(self):
        """Test all new argument defaults."""
        with patch('sys.argv', ['sshcheck', '-t', '192.168.1.1', '-u', 'root', '-p', 'pass']):
            args = parse_arguments()
        self.assertFalse(args.spray)
        self.assertIsNone(args.exclude_hosts)
        self.assertIsNone(args.exclude_file)
        self.assertFalse(args.detect_honeypot)
        self.assertIsNone(args.known_hosts)
        self.assertIsNone(args.baseline)
        self.assertIsNone(args.import_nmap)


class TestConfigNewOptions(unittest.TestCase):
    """Test configuration file support for new options."""

    def test_apply_config_spray(self):
        """Test applying spray mode from config."""
        import argparse
        args = argparse.Namespace(
            targets=None, target_file=None, users=None, user_file=None,
            passwords=None, password_file=None, ports=None, port_file=None,
            output=None, format='text', verbose=False, quiet=False,
            threads=1, timeout=10, try_empty=False, user_as_pass=False,
            stop_on_success=False, max_attempts_per_user=0, command=None,
            checkpoint=None, spray=False, exclude_hosts=None,
            detect_honeypot=False, known_hosts=None, baseline=None,
            import_nmap=None
        )
        config = {
            "spray": True,
            "detect_honeypot": True,
            "known_hosts": "hosts.json",
            "baseline": "prev_scan.json",
        }
        apply_config(args, config)
        self.assertTrue(args.spray)
        self.assertTrue(args.detect_honeypot)
        self.assertEqual(args.known_hosts, "hosts.json")
        self.assertEqual(args.baseline, "prev_scan.json")


class TestBaselineDiffPrinting(unittest.TestCase):
    """Test baseline diff printing."""

    def test_print_no_changes(self):
        """Test printing diff with no changes."""
        client = SSHAuditClient()
        diff = {
            'new_hosts': [], 'removed_hosts': [],
            'new_credentials': [], 'lost_credentials': [],
            'host_key_changes': [], 'ssh_version_changes': [],
            'summary': {
                'new_hosts_count': 0, 'removed_hosts_count': 0,
                'new_credentials_count': 0, 'lost_credentials_count': 0,
                'host_key_changes_count': 0, 'ssh_version_changes_count': 0,
            }
        }
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            client._print_baseline_diff(diff)
        self.assertIn("No changes", mock_out.getvalue())

    def test_print_with_changes(self):
        """Test printing diff with various changes."""
        client = SSHAuditClient()
        diff = {
            'new_hosts': [{'host': '10.0.0.5', 'port': 22}],
            'removed_hosts': [{'host': '10.0.0.3', 'port': 22}],
            'new_credentials': [
                {'host': '10.0.0.1', 'port': 22, 'username': 'root', 'password': 'pass'}
            ],
            'lost_credentials': [],
            'host_key_changes': [{
                'host': '10.0.0.1', 'port': 22,
                'previous_type': 'ssh-rsa', 'previous_fingerprint': 'SHA256:old',
                'current_type': 'ssh-ed25519', 'current_fingerprint': 'SHA256:new'
            }],
            'ssh_version_changes': [{
                'host': '10.0.0.1', 'port': 22,
                'previous_version': 'OpenSSH_7.0', 'current_version': 'OpenSSH_9.0'
            }],
            'summary': {
                'new_hosts_count': 1, 'removed_hosts_count': 1,
                'new_credentials_count': 1, 'lost_credentials_count': 0,
                'host_key_changes_count': 1, 'ssh_version_changes_count': 1,
            }
        }
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            client._print_baseline_diff(diff)
        output = mock_out.getvalue()
        self.assertIn("NEW HOSTS", output)
        self.assertIn("REMOVED HOSTS", output)
        self.assertIn("NEW CREDENTIALS", output)
        self.assertIn("HOST KEY CHANGES", output)
        self.assertIn("SSH VERSION CHANGES", output)

    def test_quiet_mode_suppresses_diff(self):
        """Test that quiet mode suppresses diff output."""
        client = SSHAuditClient(quiet=True)
        diff = {
            'new_hosts': [{'host': '10.0.0.5', 'port': 22}],
            'removed_hosts': [], 'new_credentials': [],
            'lost_credentials': [], 'host_key_changes': [],
            'ssh_version_changes': [],
            'summary': {
                'new_hosts_count': 1, 'removed_hosts_count': 0,
                'new_credentials_count': 0, 'lost_credentials_count': 0,
                'host_key_changes_count': 0, 'ssh_version_changes_count': 0,
            }
        }
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            client._print_baseline_diff(diff)
        self.assertEqual(mock_out.getvalue(), "")


class TestPasswordStrengthScoring(unittest.TestCase):
    """Test cases for password strength scoring."""

    def test_empty_password(self):
        """Test scoring an empty password."""
        score, label = SSHAuditClient.score_password_strength("")
        self.assertEqual(score, 0.0)
        self.assertEqual(label, "empty")

    def test_common_password(self):
        """Test that common passwords get a low score."""
        score, label = SSHAuditClient.score_password_strength("password")
        self.assertLess(score, 30)
        self.assertIn(label, ("very_weak", "weak"))

    def test_common_password_123456(self):
        """Test scoring of '123456'."""
        score, label = SSHAuditClient.score_password_strength("123456")
        self.assertLess(score, 30)

    def test_strong_password(self):
        """Test a strong password gets a high score."""
        score, label = SSHAuditClient.score_password_strength("T#h1s!Is@Str0ng_P4ss")
        self.assertGreater(score, 60)
        self.assertIn(label, ("strong", "very_strong"))

    def test_very_short_password(self):
        """Test very short passwords get low scores."""
        score, label = SSHAuditClient.score_password_strength("ab")
        self.assertLess(score, 30)

    def test_username_as_password_penalty(self):
        """Test penalty when password matches username."""
        # Use a non-common password to avoid common password penalty masking the difference
        score_without, _ = SSHAuditClient.score_password_strength("jsmith2024")
        score_with, _ = SSHAuditClient.score_password_strength("jsmith2024", username="jsmith2024")
        self.assertLess(score_with, score_without)

    def test_username_in_password_penalty(self):
        """Test penalty when username is contained in password."""
        score_without, _ = SSHAuditClient.score_password_strength("admin123")
        score_with, _ = SSHAuditClient.score_password_strength("admin123", username="admin")
        self.assertLess(score_with, score_without)

    def test_character_diversity(self):
        """Test that character diversity increases score."""
        # All lowercase
        score_low, _ = SSHAuditClient.score_password_strength("abcdefghij")
        # Mixed: lower + upper + digits + special
        score_high, _ = SSHAuditClient.score_password_strength("aB3$efghij")
        self.assertGreater(score_high, score_low)

    def test_sequential_characters_penalty(self):
        """Test penalty for sequential characters."""
        score_seq, _ = SSHAuditClient.score_password_strength("abcdefghij")
        score_non, _ = SSHAuditClient.score_password_strength("axbzeyghwj")
        self.assertLess(score_seq, score_non)

    def test_repeated_characters_penalty(self):
        """Test penalty for repeated characters."""
        score_rep, _ = SSHAuditClient.score_password_strength("aaabbbccc")
        score_non, _ = SSHAuditClient.score_password_strength("axbyczdwe")
        self.assertLess(score_rep, score_non)

    def test_long_complex_password(self):
        """Test a long complex password gets very strong."""
        score, label = SSHAuditClient.score_password_strength(
            "K9$mL2#xPq4!vN7&jR5@wT8"
        )
        self.assertGreater(score, 70)
        self.assertIn(label, ("strong", "very_strong"))

    def test_score_bounded(self):
        """Test that score is always between 0 and 100."""
        test_passwords = ["", "a", "password", "P@$$w0rd!2024LongOne"]
        for pw in test_passwords:
            score, _ = SSHAuditClient.score_password_strength(pw)
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 100.0)

    def test_label_values(self):
        """Test that labels are from the expected set."""
        valid_labels = {"empty", "very_weak", "weak", "moderate", "strong", "very_strong"}
        test_passwords = [
            "", "a", "123456", "password1", "Str0ng!Pass",
            "K9$mL2#xPq4!vN7&jR5@wT8"
        ]
        for pw in test_passwords:
            _, label = SSHAuditClient.score_password_strength(pw)
            self.assertIn(label, valid_labels)

    def test_score_password_in_scan_result(self):
        """Test that password strength is added to scan results."""
        client = SSHAuditClient(score_passwords=True)
        result = ScanResult(
            host="10.0.0.1", port=22, username="admin",
            password="password123", success=True,
            timestamp="2026-01-01T12:00:00"
        )
        # Simulate the scoring that happens in _try_login
        pw_score, pw_label = SSHAuditClient.score_password_strength(
            result.password, result.username
        )
        result.password_strength_score = pw_score
        result.password_strength_label = pw_label
        self.assertGreater(result.password_strength_score, 0)
        self.assertIn(result.password_strength_label, {"very_weak", "weak", "moderate", "strong", "very_strong"})

    def test_common_passwords_set(self):
        """Test that COMMON_PASSWORDS contains expected entries."""
        self.assertIn("password", COMMON_PASSWORDS)
        self.assertIn("123456", COMMON_PASSWORDS)
        self.assertIn("admin", COMMON_PASSWORDS)
        self.assertIn("root", COMMON_PASSWORDS)


class TestSourceIPBinding(unittest.TestCase):
    """Test cases for source IP binding."""

    def test_source_ip_init(self):
        """Test that source_ip is stored in client."""
        client = SSHAuditClient(source_ip="192.168.1.100")
        self.assertEqual(client.source_ip, "192.168.1.100")

    def test_source_ip_default_none(self):
        """Test that source_ip defaults to None."""
        client = SSHAuditClient()
        self.assertIsNone(client.source_ip)

    def test_source_ip_argument_parsing(self):
        """Test --source-ip argument parsing."""
        with patch('sys.argv', ['sshcheck', '-t', '10.0.0.1', '-u', 'root',
                                '-p', 'pass', '--source-ip', '192.168.1.5']):
            args = parse_arguments()
            self.assertEqual(args.source_ip, '192.168.1.5')

    def test_source_ip_config(self):
        """Test source_ip from config file."""
        import argparse
        args = argparse.Namespace(
            targets=None, target_file=None, users=None, user_file=None,
            passwords=None, password_file=None, ports=None, port_file=None,
            output=None, format='text', verbose=False, quiet=False,
            threads=1, timeout=10, try_empty=False, user_as_pass=False,
            stop_on_success=False, max_attempts_per_user=0, command=None,
            checkpoint=None, spray=False, exclude_hosts=None,
            detect_honeypot=False, known_hosts=None, baseline=None,
            import_nmap=None, source_ip=None, jitter=0.0,
            score_passwords=False, diff_mode=False, scan_ports=False,
            discovery_ports=None,
        )
        config = {'source_ip': '10.0.0.5'}
        apply_config(args, config)
        self.assertEqual(args.source_ip, '10.0.0.5')

    @patch('socket.socket')
    def test_banner_with_source_ip(self, mock_socket_cls):
        """Test that _get_ssh_banner binds to source IP."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9"

        client = SSHAuditClient(source_ip="192.168.1.100")
        banner = client._get_ssh_banner("10.0.0.1", 22)

        mock_sock.bind.assert_called_once_with(("192.168.1.100", 0))
        self.assertEqual(banner, "SSH-2.0-OpenSSH_8.9")

    @patch('socket.socket')
    def test_banner_without_source_ip(self, mock_socket_cls):
        """Test that _get_ssh_banner does not bind without source IP."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9"

        client = SSHAuditClient()
        banner = client._get_ssh_banner("10.0.0.1", 22)

        mock_sock.bind.assert_not_called()


class TestJitter(unittest.TestCase):
    """Test cases for jitter/randomization."""

    def test_jitter_init(self):
        """Test that jitter is stored in client."""
        client = SSHAuditClient(jitter=2.5)
        self.assertEqual(client.jitter, 2.5)

    def test_jitter_default_zero(self):
        """Test that jitter defaults to 0."""
        client = SSHAuditClient()
        self.assertEqual(client.jitter, 0.0)

    def test_jitter_argument_parsing(self):
        """Test --jitter argument parsing."""
        with patch('sys.argv', ['sshcheck', '-t', '10.0.0.1', '-u', 'root',
                                '-p', 'pass', '--jitter', '1.5']):
            args = parse_arguments()
            self.assertEqual(args.jitter, 1.5)

    def test_jitter_argument_default(self):
        """Test --jitter default is 0."""
        with patch('sys.argv', ['sshcheck', '-t', '10.0.0.1', '-u', 'root',
                                '-p', 'pass']):
            args = parse_arguments()
            self.assertEqual(args.jitter, 0.0)

    def test_jitter_config(self):
        """Test jitter from config file."""
        import argparse
        args = argparse.Namespace(
            targets=None, target_file=None, users=None, user_file=None,
            passwords=None, password_file=None, ports=None, port_file=None,
            output=None, format='text', verbose=False, quiet=False,
            threads=1, timeout=10, try_empty=False, user_as_pass=False,
            stop_on_success=False, max_attempts_per_user=0, command=None,
            checkpoint=None, spray=False, exclude_hosts=None,
            detect_honeypot=False, known_hosts=None, baseline=None,
            import_nmap=None, source_ip=None, jitter=0.0,
            score_passwords=False, diff_mode=False, scan_ports=False,
            discovery_ports=None,
        )
        config = {'jitter': 3.0}
        apply_config(args, config)
        self.assertEqual(args.jitter, 3.0)

    @patch('time.sleep')
    @patch('random.uniform')
    def test_jitter_delay_applied(self, mock_uniform, mock_sleep):
        """Test that jitter delay is applied between scan attempts."""
        mock_uniform.return_value = 0.5
        client = SSHAuditClient(jitter=2.0, quiet=True)

        # Mock _try_login to return quickly
        mock_result = ScanResult(
            host="10.0.0.1", port=22, username="root",
            password="pass", success=False,
            timestamp="2026-01-01T12:00:00",
            error_message="Auth failed"
        )
        mock_result.severity = "info"
        mock_result.severity_reasons = ["No findings"]

        with patch.object(client, '_try_login', return_value=mock_result):
            client.scan(
                targets=["10.0.0.1"],
                usernames=["root"],
                passwords=["pass1", "pass2"],
                ports=[22]
            )
        # Jitter sleep should have been called at least once (between attempts)
        self.assertTrue(mock_sleep.called)


class TestServiceDiscovery(unittest.TestCase):
    """Test cases for Nmap-style service discovery."""

    @patch('socket.socket')
    def test_discover_ssh_ports_found(self, mock_socket_cls):
        """Test discovering an SSH port."""
        # Create separate mock sockets for each port attempt
        mock_sock_ssh = MagicMock()
        mock_sock_ssh.connect_ex.return_value = 0
        mock_sock_ssh.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1"

        mock_sock_http = MagicMock()
        mock_sock_http.connect_ex.return_value = 0
        mock_sock_http.recv.return_value = b"HTTP/1.1 200 OK\r\n"

        mock_socket_cls.side_effect = [mock_sock_ssh, mock_sock_http]

        found = SSHAuditClient.discover_ssh_ports("10.0.0.1", ports=[22, 80])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][0], 22)
        self.assertIn("SSH-2.0", found[0][1])

    @patch('socket.socket')
    def test_discover_ssh_ports_not_found(self, mock_socket_cls):
        """Test when no SSH ports are found."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1  # Connection refused

        found = SSHAuditClient.discover_ssh_ports("10.0.0.1", ports=[22, 80])
        self.assertEqual(len(found), 0)

    @patch('socket.socket')
    def test_discover_ssh_ports_non_ssh_service(self, mock_socket_cls):
        """Test that non-SSH services are filtered out."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n"

        found = SSHAuditClient.discover_ssh_ports("10.0.0.1", ports=[80])
        self.assertEqual(len(found), 0)

    @patch('socket.socket')
    def test_discover_ssh_ports_with_source_ip(self, mock_socket_cls):
        """Test service discovery with source IP binding."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9"

        found = SSHAuditClient.discover_ssh_ports(
            "10.0.0.1", ports=[22], source_ip="192.168.1.5"
        )
        mock_sock.bind.assert_called_with(("192.168.1.5", 0))
        self.assertEqual(len(found), 1)

    @patch('socket.socket')
    def test_discover_ssh_default_ports(self, mock_socket_cls):
        """Test that default ports include common SSH ports."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1  # All closed

        SSHAuditClient.discover_ssh_ports("10.0.0.1")
        # Should have tried all COMMON_SSH_PORTS
        self.assertEqual(mock_sock.connect_ex.call_count, len(COMMON_SSH_PORTS))

    @patch('socket.socket')
    def test_discover_ssh_timeout_handling(self, mock_socket_cls):
        """Test that connection timeouts are handled gracefully."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        import socket
        mock_sock.connect_ex.side_effect = socket.timeout("timed out")

        # Should not raise
        found = SSHAuditClient.discover_ssh_ports("10.0.0.1", ports=[22])
        self.assertEqual(len(found), 0)

    def test_scan_ports_argument_parsing(self):
        """Test --scan-ports argument parsing."""
        with patch('sys.argv', ['sshcheck', '-t', '10.0.0.1', '-u', 'root',
                                '-p', 'pass', '--scan-ports']):
            args = parse_arguments()
            self.assertTrue(args.scan_ports)

    def test_discovery_ports_argument_parsing(self):
        """Test --discovery-ports argument parsing."""
        with patch('sys.argv', ['sshcheck', '-t', '10.0.0.1', '-u', 'root',
                                '-p', 'pass', '--scan-ports',
                                '--discovery-ports', '22,2222,8022']):
            args = parse_arguments()
            self.assertEqual(args.discovery_ports, '22,2222,8022')

    def test_common_ssh_ports_list(self):
        """Test that COMMON_SSH_PORTS contains expected ports."""
        self.assertIn(22, COMMON_SSH_PORTS)
        self.assertIn(2222, COMMON_SSH_PORTS)
        self.assertIn(22222, COMMON_SSH_PORTS)
        self.assertIn(8022, COMMON_SSH_PORTS)


class TestDiffMode(unittest.TestCase):
    """Test cases for differential/delta output."""

    def test_diff_mode_init(self):
        """Test that diff_mode is stored in client."""
        client = SSHAuditClient(diff_mode=True)
        self.assertTrue(client.diff_mode)

    def test_diff_mode_default_false(self):
        """Test that diff_mode defaults to False."""
        client = SSHAuditClient()
        self.assertFalse(client.diff_mode)

    def test_diff_argument_parsing(self):
        """Test --diff argument parsing."""
        with patch('sys.argv', ['sshcheck', '-t', '10.0.0.1', '-u', 'root',
                                '-p', 'pass', '--diff', '--baseline', 'prev.json']):
            args = parse_arguments()
            self.assertTrue(args.diff_mode)

    def test_save_diff_json(self):
        """Test saving diff output as JSON."""
        client = SSHAuditClient(diff_mode=True)
        diff = {
            'new_hosts': [{'host': '10.0.0.5', 'port': 22}],
            'removed_hosts': [],
            'new_credentials': [
                {'host': '10.0.0.1', 'port': 22, 'username': 'root', 'password': 'toor'}
            ],
            'lost_credentials': [],
            'host_key_changes': [],
            'ssh_version_changes': [],
            'summary': {
                'new_hosts_count': 1, 'removed_hosts_count': 0,
                'new_credentials_count': 1, 'lost_credentials_count': 0,
                'host_key_changes_count': 0, 'ssh_version_changes_count': 0,
            }
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_diff_output(diff, Path(tmp_path))
            with open(tmp_path, 'r') as f:
                saved = json.load(f)
            self.assertEqual(saved['changes']['new_hosts'][0]['host'], '10.0.0.5')
            self.assertEqual(saved['changes']['new_credentials'][0]['username'], 'root')
            self.assertIn('scan_info', saved)
            self.assertEqual(saved['scan_info']['mode'], 'differential')
        finally:
            os.unlink(tmp_path)

    def test_save_diff_csv(self):
        """Test saving diff output as CSV."""
        client = SSHAuditClient(diff_mode=True)
        diff = {
            'new_hosts': [{'host': '10.0.0.5', 'port': 22}],
            'removed_hosts': [{'host': '10.0.0.3', 'port': 22}],
            'new_credentials': [],
            'lost_credentials': [],
            'host_key_changes': [],
            'ssh_version_changes': [],
            'summary': {
                'new_hosts_count': 1, 'removed_hosts_count': 1,
                'new_credentials_count': 0, 'lost_credentials_count': 0,
                'host_key_changes_count': 0, 'ssh_version_changes_count': 0,
            }
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_diff_output(diff, Path(tmp_path))
            with open(tmp_path, 'r') as f:
                content = f.read()
            self.assertIn('new_host', content)
            self.assertIn('removed_host', content)
            self.assertIn('10.0.0.5', content)
            self.assertIn('10.0.0.3', content)
        finally:
            os.unlink(tmp_path)

    def test_save_diff_text(self):
        """Test saving diff output as text."""
        client = SSHAuditClient(diff_mode=True)
        diff = {
            'new_hosts': [{'host': '10.0.0.5', 'port': 22}],
            'removed_hosts': [],
            'new_credentials': [
                {'host': '10.0.0.1', 'port': 22, 'username': 'admin', 'password': 'pass'}
            ],
            'lost_credentials': [],
            'host_key_changes': [],
            'ssh_version_changes': [
                {'host': '10.0.0.1', 'port': 22,
                 'previous_version': 'OpenSSH_7.9', 'current_version': 'OpenSSH_8.9'}
            ],
            'summary': {
                'new_hosts_count': 1, 'removed_hosts_count': 0,
                'new_credentials_count': 1, 'lost_credentials_count': 0,
                'host_key_changes_count': 0, 'ssh_version_changes_count': 1,
            }
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_diff_output(diff, Path(tmp_path))
            with open(tmp_path, 'r') as f:
                content = f.read()
            self.assertIn('NEW HOSTS', content)
            self.assertIn('10.0.0.5', content)
            self.assertIn('NEW CREDENTIALS', content)
            self.assertIn('SSH VERSION CHANGES', content)
            self.assertIn('Differential', content)
        finally:
            os.unlink(tmp_path)

    def test_save_diff_no_changes(self):
        """Test saving diff output with no changes."""
        client = SSHAuditClient(diff_mode=True)
        diff = {
            'new_hosts': [], 'removed_hosts': [],
            'new_credentials': [], 'lost_credentials': [],
            'host_key_changes': [], 'ssh_version_changes': [],
            'summary': {
                'new_hosts_count': 0, 'removed_hosts_count': 0,
                'new_credentials_count': 0, 'lost_credentials_count': 0,
                'host_key_changes_count': 0, 'ssh_version_changes_count': 0,
            }
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_diff_output(diff, Path(tmp_path))
            with open(tmp_path, 'r') as f:
                content = f.read()
            self.assertIn('No changes detected', content)
        finally:
            os.unlink(tmp_path)

    def test_diff_config(self):
        """Test diff_mode from config file."""
        import argparse
        args = argparse.Namespace(
            targets=None, target_file=None, users=None, user_file=None,
            passwords=None, password_file=None, ports=None, port_file=None,
            output=None, format='text', verbose=False, quiet=False,
            threads=1, timeout=10, try_empty=False, user_as_pass=False,
            stop_on_success=False, max_attempts_per_user=0, command=None,
            checkpoint=None, spray=False, exclude_hosts=None,
            detect_honeypot=False, known_hosts=None, baseline=None,
            import_nmap=None, source_ip=None, jitter=0.0,
            score_passwords=False, diff_mode=False, scan_ports=False,
            discovery_ports=None,
        )
        config = {'diff_mode': True}
        apply_config(args, config)
        self.assertTrue(args.diff_mode)


class TestPDFReport(unittest.TestCase):
    """Test cases for PDF report generation."""

    def test_pdf_format_argument(self):
        """Test --format pdf argument parsing."""
        with patch('sys.argv', ['sshcheck', '-t', '10.0.0.1', '-u', 'root',
                                '-p', 'pass', '-f', 'pdf', '-o', 'report.pdf']):
            args = parse_arguments()
            self.assertEqual(args.format, 'pdf')

    def test_save_pdf_creates_file(self):
        """Test that _save_pdf creates a valid PDF file."""
        client = SSHAuditClient()
        client.stats.start_time = None
        client.stats.end_time = None
        client.results = []

        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_pdf(Path(tmp_path))
            self.assertTrue(os.path.exists(tmp_path))
            with open(tmp_path, 'rb') as f:
                content = f.read()
            # Verify it starts with PDF header
            self.assertTrue(content.startswith(b'%PDF-1.4'))
            # Verify it ends with %%EOF
            self.assertTrue(content.rstrip().endswith(b'%%EOF'))
        finally:
            os.unlink(tmp_path)

    def test_save_pdf_with_results(self):
        """Test PDF generation with scan results."""
        from datetime import datetime
        client = SSHAuditClient()
        client.stats.start_time = datetime(2026, 1, 1, 12, 0, 0)
        client.stats.end_time = datetime(2026, 1, 1, 12, 5, 0)
        client.stats.total_attempts = 5
        client.stats.successful_logins = 2
        client.stats.failed_logins = 3
        client.results = [
            ScanResult(
                host="10.0.0.1", port=22, username="root",
                password="toor", success=True,
                timestamp="2026-01-01T12:00:00",
                banner="SSH-2.0-OpenSSH_8.9",
                severity="critical",
                severity_reasons=["Root login with password"],
                os_info="Ubuntu Linux",
                os_family="Linux",
                ssh_version="OpenSSH_8.9",
                host_key_type="ssh-ed25519",
                host_key_fingerprint="SHA256:abc123",
                host_key_bits=256,
            ),
            ScanResult(
                host="10.0.0.1", port=22, username="admin",
                password="wrong", success=False,
                timestamp="2026-01-01T12:01:00",
                error_message="Auth failed",
                severity="info",
            ),
        ]

        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_pdf(Path(tmp_path))
            self.assertTrue(os.path.exists(tmp_path))
            with open(tmp_path, 'rb') as f:
                content = f.read()
            self.assertTrue(content.startswith(b'%PDF-1.4'))
            # Should contain page objects
            self.assertIn(b'/Type /Page', content)
            self.assertIn(b'/Type /Catalog', content)
        finally:
            os.unlink(tmp_path)

    def test_save_pdf_special_characters(self):
        """Test PDF generation with special characters in data."""
        client = SSHAuditClient()
        client.stats.start_time = None
        client.stats.end_time = None
        client.results = [
            ScanResult(
                host="10.0.0.1", port=22, username="root",
                password="p@ss(word)", success=True,
                timestamp="2026-01-01T12:00:00",
                severity="high",
                severity_reasons=["Login successful"],
                banner="SSH-2.0-OpenSSH_8.9 (test)",
            ),
        ]

        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_pdf(Path(tmp_path))
            with open(tmp_path, 'rb') as f:
                content = f.read()
            self.assertTrue(content.startswith(b'%PDF-1.4'))
        finally:
            os.unlink(tmp_path)

    def test_save_pdf_many_results(self):
        """Test PDF generation with many results (multi-page)."""
        client = SSHAuditClient()
        client.stats.start_time = None
        client.stats.end_time = None
        client.results = [
            ScanResult(
                host=f"10.0.0.{i}", port=22, username="root",
                password=f"pass{i}", success=(i % 3 == 0),
                timestamp="2026-01-01T12:00:00",
                severity="info",
            )
            for i in range(100)
        ]

        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_pdf(Path(tmp_path))
            with open(tmp_path, 'rb') as f:
                content = f.read()
            self.assertTrue(content.startswith(b'%PDF-1.4'))
            # Should have multiple pages
            page_count = content.count(b'/Type /Page')
            self.assertGreater(page_count, 1)
        finally:
            os.unlink(tmp_path)


class TestScanResultNewFieldsV4(unittest.TestCase):
    """Test new ScanResult fields for v4.0."""

    def test_password_strength_defaults(self):
        """Test default values for password strength fields."""
        result = ScanResult(
            host="10.0.0.1", port=22, username="root",
            password="pass", success=True,
            timestamp="2026-01-01T12:00:00"
        )
        self.assertEqual(result.password_strength_score, 0.0)
        self.assertEqual(result.password_strength_label, "")

    def test_password_strength_to_dict(self):
        """Test that password strength fields appear in to_dict."""
        result = ScanResult(
            host="10.0.0.1", port=22, username="root",
            password="pass", success=True,
            timestamp="2026-01-01T12:00:00",
            password_strength_score=45.5,
            password_strength_label="moderate",
        )
        d = result.to_dict()
        self.assertEqual(d['password_strength_score'], 45.5)
        self.assertEqual(d['password_strength_label'], 'moderate')


class TestNewArgumentDefaultsV4(unittest.TestCase):
    """Test argument defaults for v4 features."""

    def test_all_new_defaults(self):
        """Test default values for all new v4 arguments."""
        with patch('sys.argv', ['sshcheck', '-t', '10.0.0.1',
                                '-u', 'root', '-p', 'pass']):
            args = parse_arguments()
            self.assertIsNone(args.source_ip)
            self.assertEqual(args.jitter, 0.0)
            self.assertFalse(args.score_passwords)
            self.assertFalse(args.diff_mode)
            self.assertFalse(args.scan_ports)
            self.assertIsNone(args.discovery_ports)

    def test_pdf_format_in_choices(self):
        """Test that pdf is a valid format choice."""
        with patch('sys.argv', ['sshcheck', '-t', '10.0.0.1',
                                '-u', 'root', '-p', 'pass',
                                '-f', 'pdf']):
            args = parse_arguments()
            self.assertEqual(args.format, 'pdf')


class TestConfigNewOptionsV4(unittest.TestCase):
    """Test config file support for v4 options."""

    def test_apply_config_all_v4_options(self):
        """Test applying all v4 config options."""
        import argparse
        args = argparse.Namespace(
            targets=None, target_file=None, users=None, user_file=None,
            passwords=None, password_file=None, ports=None, port_file=None,
            output=None, format='text', verbose=False, quiet=False,
            threads=1, timeout=10, try_empty=False, user_as_pass=False,
            stop_on_success=False, max_attempts_per_user=0, command=None,
            checkpoint=None, spray=False, exclude_hosts=None,
            detect_honeypot=False, known_hosts=None, baseline=None,
            import_nmap=None, source_ip=None, jitter=0.0,
            score_passwords=False, diff_mode=False, scan_ports=False,
            discovery_ports=None,
        )
        config = {
            'source_ip': '192.168.1.100',
            'jitter': 1.5,
            'score_passwords': True,
            'diff_mode': True,
            'scan_ports': True,
            'discovery_ports': '22,2222',
        }
        apply_config(args, config)
        self.assertEqual(args.source_ip, '192.168.1.100')
        self.assertEqual(args.jitter, 1.5)
        self.assertTrue(args.score_passwords)
        self.assertTrue(args.diff_mode)
        self.assertTrue(args.scan_ports)
        self.assertEqual(args.discovery_ports, '22,2222')


class TestVersionUpdate(unittest.TestCase):
    """Test version update."""

    def test_version_is_4(self):
        """Test that version is 4.0.0."""
        self.assertEqual(__version__, "4.0.0")


class TestPasswordStrengthInProgress(unittest.TestCase):
    """Test password strength display in progress output."""

    def test_progress_shows_password_strength(self):
        """Test that password strength is shown in progress output."""
        client = SSHAuditClient(score_passwords=True)
        result = ScanResult(
            host="10.0.0.1", port=22, username="root",
            password="weak", success=True,
            timestamp="2026-01-01T12:00:00",
            severity="critical",
            severity_reasons=["Root login"],
            password_strength_score=15.0,
            password_strength_label="very_weak",
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            client._print_progress(result, 1, 1)
        output = mock_out.getvalue()
        self.assertIn("VERY_WEAK", output)
        self.assertIn("Password Strength", output)

    def test_progress_no_password_strength_when_not_scoring(self):
        """Test that password strength is not shown when scoring disabled."""
        client = SSHAuditClient(score_passwords=False)
        result = ScanResult(
            host="10.0.0.1", port=22, username="root",
            password="weak", success=True,
            timestamp="2026-01-01T12:00:00",
            severity="critical",
            severity_reasons=["Root login"],
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            client._print_progress(result, 1, 1)
        output = mock_out.getvalue()
        self.assertNotIn("Password Strength", output)


class TestSaveResultsPDF(unittest.TestCase):
    """Test _save_results routing to PDF."""

    def test_save_results_routes_to_pdf(self):
        """Test that format=pdf routes to _save_pdf."""
        from datetime import datetime
        client = SSHAuditClient(
            output_format='pdf',
            output_file='/tmp/test_sshcheck_pdf_route.pdf'
        )
        client.stats.start_time = datetime(2026, 1, 1)
        client.stats.end_time = datetime(2026, 1, 1)
        client.results = []

        with patch.object(client, '_save_pdf') as mock_pdf:
            client._save_results()
            mock_pdf.assert_called_once()

        # Cleanup
        try:
            os.unlink('/tmp/test_sshcheck_pdf_route.pdf')
        except FileNotFoundError:
            pass


class TestOutputFormatCompleteness(unittest.TestCase):
    """Test that all output formats include all ScanResult fields."""

    def _make_client_with_full_result(self):
        """Create a client with a result that has all fields populated."""
        from datetime import datetime
        client = SSHAuditClient(score_passwords=True, detect_honeypot=True)
        client.stats.start_time = datetime(2026, 1, 1, 12, 0, 0)
        client.stats.end_time = datetime(2026, 1, 1, 12, 5, 0)
        client.stats.total_attempts = 1
        client.stats.successful_logins = 1
        client.results = [
            ScanResult(
                host="10.0.0.1", port=22, username="root",
                password="toor", success=True,
                timestamp="2026-01-01T12:00:00",
                banner="SSH-2.0-OpenSSH_8.9",
                severity="critical",
                severity_reasons=["Root login with password"],
                host_key_type="ssh-ed25519",
                host_key_fingerprint="SHA256:abc123",
                host_key_bits=256,
                os_info="Ubuntu", os_family="Linux",
                ssh_version="OpenSSH_8.9",
                honeypot_score=0.7,
                honeypot_reasons=["Known Cowrie banner"],
                host_key_changed=True,
                host_key_previous="SHA256:old_key",
                password_strength_score=15.0,
                password_strength_label="very_weak",
            ),
        ]
        return client

    def test_text_output_includes_honeypot(self):
        """Test that text output includes honeypot data."""
        client = self._make_client_with_full_result()
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_text(Path(tmp_path))
            with open(tmp_path, 'r') as f:
                content = f.read()
            self.assertIn('Honeypot score: 0.7', content)
            self.assertIn('Known Cowrie banner', content)
        finally:
            os.unlink(tmp_path)

    def test_text_output_includes_mitm(self):
        """Test that text output includes MITM/host key change data."""
        client = self._make_client_with_full_result()
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_text(Path(tmp_path))
            with open(tmp_path, 'r') as f:
                content = f.read()
            self.assertIn('HOST KEY CHANGED', content)
            self.assertIn('SHA256:old_key', content)
        finally:
            os.unlink(tmp_path)

    def test_text_output_includes_password_strength(self):
        """Test that text output includes password strength data."""
        client = self._make_client_with_full_result()
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_text(Path(tmp_path))
            with open(tmp_path, 'r') as f:
                content = f.read()
            self.assertIn('Password Strength:', content)
            self.assertIn('VERY_WEAK', content)
            self.assertIn('15/100', content)
        finally:
            os.unlink(tmp_path)

    def test_csv_output_includes_all_fields(self):
        """Test that CSV output includes all ScanResult fields."""
        client = self._make_client_with_full_result()
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_csv(Path(tmp_path))
            with open(tmp_path, 'r') as f:
                content = f.read()
            # Check header has new fields
            self.assertIn('honeypot_score', content)
            self.assertIn('honeypot_reasons', content)
            self.assertIn('host_key_changed', content)
            self.assertIn('host_key_previous', content)
            self.assertIn('password_strength_score', content)
            self.assertIn('password_strength_label', content)
            self.assertIn('host_key_bits', content)
            self.assertIn('os_family', content)
            self.assertIn('severity_reasons', content)
            # Check data values are present
            self.assertIn('Known Cowrie banner', content)
            self.assertIn('very_weak', content)
            self.assertIn('SHA256:old_key', content)
        finally:
            os.unlink(tmp_path)

    def test_xml_output_includes_honeypot(self):
        """Test that XML output includes honeypot data."""
        client = self._make_client_with_full_result()
        with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_xml(Path(tmp_path))
            with open(tmp_path, 'r') as f:
                content = f.read()
            self.assertIn('<honeypot_score>0.7</honeypot_score>', content)
            self.assertIn('Known Cowrie banner', content)
            self.assertIn('<host_key_changed>true</host_key_changed>', content)
            self.assertIn('<host_key_previous>SHA256:old_key</host_key_previous>', content)
            self.assertIn('<password_strength_score>15.0</password_strength_score>', content)
            self.assertIn('<password_strength_label>very_weak</password_strength_label>', content)
        finally:
            os.unlink(tmp_path)

    def test_html_output_includes_honeypot(self):
        """Test that HTML output includes honeypot data."""
        client = self._make_client_with_full_result()
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_html(Path(tmp_path))
            with open(tmp_path, 'r') as f:
                content = f.read()
            self.assertIn('honeypot', content.lower())
            self.assertIn('0.7', content)
        finally:
            os.unlink(tmp_path)

    def test_html_output_includes_mitm(self):
        """Test that HTML output includes MITM detection."""
        client = self._make_client_with_full_result()
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_html(Path(tmp_path))
            with open(tmp_path, 'r') as f:
                content = f.read()
            self.assertIn('HOST KEY CHANGED', content)
            self.assertIn('SHA256:old_key', content)
        finally:
            os.unlink(tmp_path)

    def test_html_output_includes_password_strength(self):
        """Test that HTML output includes password strength."""
        client = self._make_client_with_full_result()
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            tmp_path = f.name
        try:
            client._save_html(Path(tmp_path))
            with open(tmp_path, 'r') as f:
                content = f.read()
            self.assertIn('Password Strength', content)
            self.assertIn('VERY_WEAK', content)
        finally:
            os.unlink(tmp_path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
