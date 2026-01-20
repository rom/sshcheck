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

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sshcheck import (
    SSHAuditClient,
    ScanResult,
    ScanStatistics,
    parse_arguments,
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

        # Mock channel for initial output
        mock_channel = MagicMock()
        mock_channel.recv_ready.side_effect = [True, False]
        mock_channel.recv.return_value = b"Welcome to the server\n"
        mock_client.invoke_shell.return_value = mock_channel

        with patch.object(self.client, '_get_ssh_banner', return_value="SSH-2.0-OpenSSH"):
            result = self.client._try_login("192.168.1.1", 22, "admin", "password")

        self.assertTrue(result.success)
        self.assertEqual(result.host, "192.168.1.1")
        self.assertEqual(result.username, "admin")
        self.assertEqual(result.banner, "SSH-2.0-OpenSSH")

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
                banner="SSH-2.0-OpenSSH"
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
