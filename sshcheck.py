#!/usr/bin/env python3
"""
sshcheck - SSH Security Audit Client

A security audit tool for testing SSH login capabilities across multiple hosts.
Designed for authorized penetration testing and security assessments.

Author: Robert Malmgren, with help of Claude code
License: MIT
"""

import argparse
import ipaddress
import json
import logging
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Tuple, Generator

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko is not installed.", file=sys.stderr)
    print("Please install it using: pip install paramiko", file=sys.stderr)
    sys.exit(1)


# Version information
__version__ = "1.0.0"
__program_name__ = "sshcheck"


@dataclass
class ScanResult:
    """Data class to store scan results for a single attempt."""
    host: str
    port: int
    username: str
    password: str
    success: bool
    timestamp: str
    initial_output: str = ""
    error_message: str = ""
    banner: str = ""
    connection_time: float = 0.0

    def to_dict(self) -> dict:
        """Convert result to dictionary."""
        return asdict(self)


@dataclass
class ScanStatistics:
    """Statistics for the scan session."""
    total_attempts: int = 0
    successful_logins: int = 0
    failed_logins: int = 0
    connection_errors: int = 0
    timeout_errors: int = 0
    authentication_errors: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def get_duration(self) -> float:
        """Get scan duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


class SSHAuditClient:
    """SSH Security Audit Client for testing login capabilities."""

    def __init__(
        self,
        timeout: int = 10,
        verbose: bool = False,
        threads: int = 1,
        output_file: Optional[str] = None,
        output_format: str = "text"
    ):
        """
        Initialize the SSH Audit Client.

        Args:
            timeout: Connection timeout in seconds
            verbose: Enable verbose output
            threads: Number of concurrent threads
            output_file: Path to output file for results
            output_format: Output format ('text', 'json', 'csv')
        """
        self.timeout = timeout
        self.verbose = verbose
        self.threads = threads
        self.output_file = output_file
        self.output_format = output_format
        self.results: List[ScanResult] = []
        self.stats = ScanStatistics()
        self._setup_logging()

        # Suppress paramiko logging unless verbose
        if not verbose:
            logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    def _setup_logging(self):
        """Configure logging based on verbosity level."""
        level = logging.DEBUG if self.verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        self.logger = logging.getLogger(__name__)

    def _parse_targets(self, targets: List[str]) -> Generator[str, None, None]:
        """
        Parse target specifications and yield individual IP addresses.

        Args:
            targets: List of IP addresses or CIDR ranges

        Yields:
            Individual IP addresses as strings
        """
        for target in targets:
            target = target.strip()
            if not target or target.startswith('#'):
                continue

            try:
                # Try parsing as a network (CIDR notation)
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    for ip in network.hosts():
                        yield str(ip)
                # Try parsing as IP range (e.g., 192.168.1.1-254)
                elif '-' in target and not target.count('-') > 1:
                    parts = target.rsplit('.', 1)
                    if len(parts) == 2 and '-' in parts[1]:
                        base = parts[0]
                        range_part = parts[1]
                        start, end = range_part.split('-')
                        for i in range(int(start), int(end) + 1):
                            yield f"{base}.{i}"
                    else:
                        # Single IP with hyphen in hostname (unlikely but handle)
                        yield target
                else:
                    # Single IP address or hostname
                    ipaddress.ip_address(target)  # Validate if IP
                    yield target
            except ValueError:
                # Could be a hostname
                yield target

    def _read_file_lines(self, filepath: str, description: str) -> List[str]:
        """
        Read lines from a file, handling errors gracefully.

        Args:
            filepath: Path to the file
            description: Description of file type for error messages

        Returns:
            List of non-empty, non-comment lines
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(
                f"ERROR: {description} file not found: {filepath}\n"
                f"Please ensure the file exists and the path is correct."
            )

        if not path.is_file():
            raise ValueError(
                f"ERROR: {description} path is not a file: {filepath}\n"
                f"Please provide a valid file path."
            )

        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                lines = []
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        lines.append(line)
                return lines
        except PermissionError:
            raise PermissionError(
                f"ERROR: Permission denied reading {description} file: {filepath}\n"
                f"Please check file permissions."
            )
        except IOError as e:
            raise IOError(
                f"ERROR: Failed to read {description} file: {filepath}\n"
                f"IO Error: {e}"
            )

    def _get_ssh_banner(self, host: str, port: int) -> str:
        """
        Retrieve SSH banner from target host.

        Args:
            host: Target hostname or IP
            port: Target port

        Returns:
            SSH banner string or empty string on failure
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
            sock.close()
            return banner
        except Exception:
            return ""

    def _try_login(
        self,
        host: str,
        port: int,
        username: str,
        password: str
    ) -> ScanResult:
        """
        Attempt SSH login to a target host.

        Args:
            host: Target hostname or IP
            port: Target port
            username: SSH username
            password: SSH password

        Returns:
            ScanResult object with attempt details
        """
        timestamp = datetime.now().isoformat()
        start_time = time.time()
        result = ScanResult(
            host=host,
            port=port,
            username=username,
            password=password,
            success=False,
            timestamp=timestamp
        )

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Get banner before full connection
            result.banner = self._get_ssh_banner(host, port)

            # Attempt connection
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=self.timeout
            )

            result.connection_time = time.time() - start_time
            result.success = True

            # Try to get initial shell output
            try:
                channel = client.invoke_shell()
                channel.settimeout(3)  # Short timeout for initial output
                time.sleep(1)  # Wait for initial output

                output_buffer = b""
                while channel.recv_ready():
                    output_buffer += channel.recv(4096)
                    time.sleep(0.1)

                result.initial_output = output_buffer.decode('utf-8', errors='replace')
                channel.close()
            except Exception as e:
                # Even if we can't get shell output, login was successful
                if self.verbose:
                    self.logger.debug(f"Could not get shell output: {e}")

            self.stats.successful_logins += 1

        except paramiko.AuthenticationException as e:
            result.error_message = f"Authentication failed: {str(e)}"
            self.stats.authentication_errors += 1
            self.stats.failed_logins += 1

        except paramiko.SSHException as e:
            result.error_message = f"SSH error: {str(e)}"
            self.stats.connection_errors += 1
            self.stats.failed_logins += 1

        except socket.timeout:
            result.error_message = (
                f"Connection timed out after {self.timeout} seconds. "
                f"The host may be unreachable or the SSH service is not responding."
            )
            self.stats.timeout_errors += 1
            self.stats.failed_logins += 1

        except socket.error as e:
            error_messages = {
                111: "Connection refused - SSH service may not be running on the target",
                113: "No route to host - Network path to target is unavailable",
                101: "Network is unreachable - Check network configuration",
                110: "Connection timed out - Host may be down or firewalled",
            }
            errno_val = getattr(e, 'errno', None)
            detail = error_messages.get(errno_val, str(e))
            result.error_message = f"Socket error: {detail}"
            self.stats.connection_errors += 1
            self.stats.failed_logins += 1

        except Exception as e:
            result.error_message = f"Unexpected error: {type(e).__name__}: {str(e)}"
            self.stats.connection_errors += 1
            self.stats.failed_logins += 1

        finally:
            try:
                client.close()
            except Exception:
                pass

        result.connection_time = time.time() - start_time
        self.stats.total_attempts += 1

        return result

    def _print_progress(self, result: ScanResult, current: int, total: int):
        """
        Print scan progress to stdout.

        Args:
            result: The scan result to display
            current: Current attempt number
            total: Total number of attempts
        """
        percentage = (current / total) * 100 if total > 0 else 0
        status = "[SUCCESS]" if result.success else "[FAILED]"
        color_start = "\033[92m" if result.success else "\033[91m"
        color_end = "\033[0m"

        print(
            f"[{current}/{total}] ({percentage:5.1f}%) "
            f"{color_start}{status}{color_end} "
            f"{result.host}:{result.port} "
            f"user={result.username}"
        )

        if result.success and result.initial_output:
            # Show first line of output
            first_line = result.initial_output.split('\n')[0][:60]
            if first_line:
                print(f"    Output: {first_line}...")

        if self.verbose and result.error_message:
            print(f"    Error: {result.error_message}")

    def scan(
        self,
        targets: List[str],
        usernames: List[str],
        passwords: List[str],
        ports: List[int]
    ) -> List[ScanResult]:
        """
        Perform SSH audit scan on specified targets.

        Args:
            targets: List of target hosts/networks
            usernames: List of usernames to try
            passwords: List of passwords to try
            ports: List of ports to try

        Returns:
            List of ScanResult objects
        """
        self.stats = ScanStatistics()
        self.stats.start_time = datetime.now()
        self.results = []

        # Build list of all hosts
        hosts = list(set(self._parse_targets(targets)))

        if not hosts:
            print("ERROR: No valid target hosts specified.", file=sys.stderr)
            print("Please provide valid IP addresses, hostnames, or CIDR ranges.", file=sys.stderr)
            return []

        if not usernames:
            print("ERROR: No usernames specified.", file=sys.stderr)
            print("Please provide at least one username using -u or -U options.", file=sys.stderr)
            return []

        if not passwords:
            print("ERROR: No passwords specified.", file=sys.stderr)
            print("Please provide at least one password using -p or -P options.", file=sys.stderr)
            return []

        if not ports:
            ports = [22]

        # Calculate total combinations
        total = len(hosts) * len(usernames) * len(passwords) * len(ports)

        print(f"\n{'='*60}")
        print(f"SSH Security Audit - {__program_name__} v{__version__}")
        print(f"{'='*60}")
        print(f"Targets: {len(hosts)} host(s)")
        print(f"Usernames: {len(usernames)}")
        print(f"Passwords: {len(passwords)}")
        print(f"Ports: {ports}")
        print(f"Total combinations: {total}")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        print(f"{'='*60}\n")

        # Build work items
        work_items = []
        for host in hosts:
            for port in ports:
                for username in usernames:
                    for password in passwords:
                        work_items.append((host, port, username, password))

        current = 0

        if self.threads > 1:
            # Multi-threaded execution
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._try_login, h, p, u, pw): (h, p, u, pw)
                    for h, p, u, pw in work_items
                }

                for future in as_completed(futures):
                    current += 1
                    try:
                        result = future.result()
                        self.results.append(result)
                        self._print_progress(result, current, total)
                    except Exception as e:
                        h, p, u, pw = futures[future]
                        print(f"ERROR: Unexpected exception for {h}:{p}: {e}", file=sys.stderr)
        else:
            # Single-threaded execution
            for host, port, username, password in work_items:
                current += 1
                result = self._try_login(host, port, username, password)
                self.results.append(result)
                self._print_progress(result, current, total)

        self.stats.end_time = datetime.now()

        # Print summary
        self._print_summary()

        # Save results if output file specified
        if self.output_file:
            self._save_results()

        return self.results

    def _print_summary(self):
        """Print scan summary statistics."""
        print(f"\n{'='*60}")
        print("SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Total attempts:        {self.stats.total_attempts}")
        print(f"Successful logins:     {self.stats.successful_logins}")
        print(f"Failed logins:         {self.stats.failed_logins}")
        print(f"  - Auth failures:     {self.stats.authentication_errors}")
        print(f"  - Connection errors: {self.stats.connection_errors}")
        print(f"  - Timeouts:          {self.stats.timeout_errors}")
        print(f"Duration:              {self.stats.get_duration():.2f} seconds")
        print(f"{'='*60}")

        # List successful logins
        successful = [r for r in self.results if r.success]
        if successful:
            print("\nSUCCESSFUL LOGINS:")
            print("-" * 40)
            for r in successful:
                print(f"  {r.host}:{r.port} - {r.username}:{r.password}")
                if r.banner:
                    print(f"    Banner: {r.banner}")
                if r.initial_output:
                    # Show truncated output
                    output_preview = r.initial_output[:200].replace('\n', ' ')
                    print(f"    Output: {output_preview}...")
            print()

    def _save_results(self):
        """Save scan results to output file."""
        try:
            path = Path(self.output_file)

            # Create parent directories if needed
            path.parent.mkdir(parents=True, exist_ok=True)

            if self.output_format == "json":
                self._save_json(path)
            elif self.output_format == "csv":
                self._save_csv(path)
            else:
                self._save_text(path)

            print(f"Results saved to: {self.output_file}")

        except PermissionError:
            print(
                f"ERROR: Permission denied writing to: {self.output_file}\n"
                f"Please check directory permissions or choose a different location.",
                file=sys.stderr
            )
        except IOError as e:
            print(
                f"ERROR: Failed to write results to: {self.output_file}\n"
                f"IO Error: {e}",
                file=sys.stderr
            )

    def _save_json(self, path: Path):
        """Save results in JSON format."""
        data = {
            "scan_info": {
                "program": __program_name__,
                "version": __version__,
                "start_time": self.stats.start_time.isoformat() if self.stats.start_time else None,
                "end_time": self.stats.end_time.isoformat() if self.stats.end_time else None,
                "duration_seconds": self.stats.get_duration()
            },
            "statistics": {
                "total_attempts": self.stats.total_attempts,
                "successful_logins": self.stats.successful_logins,
                "failed_logins": self.stats.failed_logins,
                "authentication_errors": self.stats.authentication_errors,
                "connection_errors": self.stats.connection_errors,
                "timeout_errors": self.stats.timeout_errors
            },
            "results": [r.to_dict() for r in self.results]
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _save_csv(self, path: Path):
        """Save results in CSV format."""
        import csv
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'host', 'port', 'username', 'password', 'success',
                'timestamp', 'banner', 'initial_output', 'error_message',
                'connection_time'
            ])
            for r in self.results:
                writer.writerow([
                    r.host, r.port, r.username, r.password, r.success,
                    r.timestamp, r.banner, r.initial_output, r.error_message,
                    r.connection_time
                ])

    def _save_text(self, path: Path):
        """Save results in text format."""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"SSH Security Audit Results\n")
            f.write(f"Generated by {__program_name__} v{__version__}\n")
            f.write(f"{'='*60}\n\n")

            f.write(f"Scan Statistics:\n")
            f.write(f"  Total attempts: {self.stats.total_attempts}\n")
            f.write(f"  Successful: {self.stats.successful_logins}\n")
            f.write(f"  Failed: {self.stats.failed_logins}\n")
            f.write(f"  Duration: {self.stats.get_duration():.2f}s\n\n")

            f.write(f"{'='*60}\n")
            f.write("SUCCESSFUL LOGINS\n")
            f.write(f"{'='*60}\n\n")

            successful = [r for r in self.results if r.success]
            if successful:
                for r in successful:
                    f.write(f"Host: {r.host}:{r.port}\n")
                    f.write(f"Username: {r.username}\n")
                    f.write(f"Password: {r.password}\n")
                    f.write(f"Timestamp: {r.timestamp}\n")
                    if r.banner:
                        f.write(f"Banner: {r.banner}\n")
                    if r.initial_output:
                        f.write(f"Initial Output:\n{r.initial_output}\n")
                    f.write(f"{'-'*40}\n\n")
            else:
                f.write("No successful logins.\n\n")

            f.write(f"{'='*60}\n")
            f.write("ALL RESULTS\n")
            f.write(f"{'='*60}\n\n")

            for r in self.results:
                status = "SUCCESS" if r.success else "FAILED"
                f.write(f"[{status}] {r.host}:{r.port} {r.username}\n")
                if r.error_message:
                    f.write(f"  Error: {r.error_message}\n")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog=__program_name__,
        description=(
            "SSH Security Audit Client - Test SSH login capabilities across multiple hosts.\n"
            "Designed for authorized penetration testing and security assessments."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1 -u admin -p password123
      Scan single host with single credentials

  %(prog)s -t 192.168.1.0/24 -u root -p admin123
      Scan entire subnet

  %(prog)s -T targets.txt -U users.txt -P passwords.txt -o results.json -f json
      Scan hosts from file using credential lists, output to JSON

  %(prog)s -t 10.0.0.1-254 -u admin -p password -n 10 --timeout 5
      Scan IP range with 10 threads and 5 second timeout

  %(prog)s -t server.example.com -u root -p secret --port 2222
      Scan non-standard SSH port

Report bugs to: https://github.com/rom/sshcheck/issues
        """
    )

    # Target specification
    target_group = parser.add_argument_group('Target Specification')
    target_group.add_argument(
        '-t', '--target',
        action='append',
        dest='targets',
        metavar='HOST',
        help=(
            'Target host(s) to scan. Can be: single IP (192.168.1.1), '
            'CIDR range (192.168.1.0/24), IP range (192.168.1.1-254), '
            'or hostname. Can be specified multiple times.'
        )
    )
    target_group.add_argument(
        '-T', '--target-file',
        metavar='FILE',
        help=(
            'File containing target hosts (one per line). '
            'Supports IP addresses, CIDR ranges, and hostnames. '
            'Lines starting with # are treated as comments.'
        )
    )

    # Username specification
    user_group = parser.add_argument_group('Username Specification')
    user_group.add_argument(
        '-u', '--user',
        action='append',
        dest='users',
        metavar='USER',
        help='Username(s) to try. Can be specified multiple times.'
    )
    user_group.add_argument(
        '-U', '--user-file',
        metavar='FILE',
        help=(
            'File containing usernames (one per line). '
            'Lines starting with # are treated as comments.'
        )
    )

    # Password specification
    pass_group = parser.add_argument_group('Password Specification')
    pass_group.add_argument(
        '-p', '--password',
        action='append',
        dest='passwords',
        metavar='PASS',
        help='Password(s) to try. Can be specified multiple times.'
    )
    pass_group.add_argument(
        '-P', '--password-file',
        metavar='FILE',
        help=(
            'File containing passwords (one per line). '
            'Lines starting with # are treated as comments.'
        )
    )

    # Port specification
    port_group = parser.add_argument_group('Port Specification')
    port_group.add_argument(
        '--port',
        action='append',
        dest='ports',
        type=int,
        metavar='PORT',
        help='SSH port(s) to try. Default is 22. Can be specified multiple times.'
    )
    port_group.add_argument(
        '--port-file',
        metavar='FILE',
        help=(
            'File containing ports (one per line). '
            'Lines starting with # are treated as comments.'
        )
    )

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Save results to specified file.'
    )
    output_group.add_argument(
        '-f', '--format',
        choices=['text', 'json', 'csv'],
        default='text',
        help='Output format: text, json, or csv. Default: text'
    )
    output_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output with detailed error messages.'
    )
    output_group.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress progress output, only show summary.'
    )

    # Performance options
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument(
        '-n', '--threads',
        type=int,
        default=1,
        metavar='NUM',
        help='Number of concurrent threads. Default: 1 (sequential).'
    )
    perf_group.add_argument(
        '--timeout',
        type=int,
        default=10,
        metavar='SECONDS',
        help='Connection timeout in seconds. Default: 10'
    )

    # Other options
    parser.add_argument(
        '-V', '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )

    return parser.parse_args()


def main():
    """Main entry point for the SSH audit client."""
    args = parse_arguments()

    # Collect targets
    targets = []
    if args.targets:
        targets.extend(args.targets)
    if args.target_file:
        try:
            client = SSHAuditClient()  # Temporary instance for file reading
            targets.extend(client._read_file_lines(args.target_file, "target"))
        except (FileNotFoundError, PermissionError, IOError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    if not targets:
        print(
            "ERROR: No targets specified.\n"
            "Please provide targets using -t/--target or -T/--target-file options.\n"
            "Use --help for usage information.",
            file=sys.stderr
        )
        sys.exit(1)

    # Collect usernames
    users = []
    if args.users:
        users.extend(args.users)
    if args.user_file:
        try:
            client = SSHAuditClient()
            users.extend(client._read_file_lines(args.user_file, "username"))
        except (FileNotFoundError, PermissionError, IOError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    if not users:
        print(
            "ERROR: No usernames specified.\n"
            "Please provide usernames using -u/--user or -U/--user-file options.\n"
            "Use --help for usage information.",
            file=sys.stderr
        )
        sys.exit(1)

    # Collect passwords
    passwords = []
    if args.passwords:
        passwords.extend(args.passwords)
    if args.password_file:
        try:
            client = SSHAuditClient()
            passwords.extend(client._read_file_lines(args.password_file, "password"))
        except (FileNotFoundError, PermissionError, IOError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    if not passwords:
        print(
            "ERROR: No passwords specified.\n"
            "Please provide passwords using -p/--password or -P/--password-file options.\n"
            "Use --help for usage information.",
            file=sys.stderr
        )
        sys.exit(1)

    # Collect ports
    ports = []
    if args.ports:
        ports.extend(args.ports)
    if args.port_file:
        try:
            client = SSHAuditClient()
            port_lines = client._read_file_lines(args.port_file, "port")
            for line in port_lines:
                try:
                    port = int(line.strip())
                    if 1 <= port <= 65535:
                        ports.append(port)
                    else:
                        print(
                            f"WARNING: Invalid port number {port} (must be 1-65535), skipping.",
                            file=sys.stderr
                        )
                except ValueError:
                    print(
                        f"WARNING: Invalid port value '{line}', skipping.",
                        file=sys.stderr
                    )
        except (FileNotFoundError, PermissionError, IOError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    if not ports:
        ports = [22]  # Default SSH port

    # Validate thread count
    if args.threads < 1:
        print(
            "ERROR: Thread count must be at least 1.\n"
            f"Provided value: {args.threads}",
            file=sys.stderr
        )
        sys.exit(1)

    if args.threads > 100:
        print(
            "WARNING: High thread count ({}) may cause connection issues.\n"
            "Consider using 10-50 threads for optimal performance.".format(args.threads),
            file=sys.stderr
        )

    # Validate timeout
    if args.timeout < 1:
        print(
            "ERROR: Timeout must be at least 1 second.\n"
            f"Provided value: {args.timeout}",
            file=sys.stderr
        )
        sys.exit(1)

    # Create and run audit client
    client = SSHAuditClient(
        timeout=args.timeout,
        verbose=args.verbose,
        threads=args.threads,
        output_file=args.output,
        output_format=args.format
    )

    try:
        results = client.scan(targets, users, passwords, ports)

        # Exit with appropriate code
        successful = [r for r in results if r.success]
        if successful:
            sys.exit(0)  # Found at least one successful login
        else:
            sys.exit(1)  # No successful logins

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\nERROR: Unexpected error occurred: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
