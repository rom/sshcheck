#!/usr/bin/env python3
"""
sshcheck - SSH Security Audit Client

A security audit tool for testing SSH login capabilities across multiple hosts.
Designed for authorized penetration testing and security assessments.

Author: Robert Malmgren, with help of Claude code
License: MIT
"""

import argparse
import csv
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Tuple, Generator, Dict

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko is not installed.", file=sys.stderr)
    print("Please install it using: pip install paramiko", file=sys.stderr)
    sys.exit(1)

# Optional dependency: PySocks for SOCKS proxy support
try:
    import socks as pysocks
    HAS_PYSOCKS = True
except ImportError:
    HAS_PYSOCKS = False


# Version information
__version__ = "2.0.0"
__program_name__ = "sshcheck"


# ============================================================================
# SSH Vulnerability Database
# ============================================================================

# Known CVEs mapped to SSH software version patterns
SSH_VULNERABILITIES = {
    "OpenSSH": [
        {
            "cve": "CVE-2024-6387",
            "name": "regreSSHion",
            "severity": "HIGH",
            "affected": "OpenSSH 8.5p1 - 9.7p1 (except 9.6p2+)",
            "description": "Race condition in signal handler allows unauthenticated remote code execution",
            "check": lambda v: _version_in_range(v, (8, 5), (9, 7)) and not _version_gte(v, (9, 6, 2))
        },
        {
            "cve": "CVE-2023-51385",
            "name": "OS command injection via ssh and ssh-keygen",
            "severity": "MEDIUM",
            "affected": "OpenSSH < 9.6",
            "description": "OS command injection via expansion tokens in certain conditions",
            "check": lambda v: _version_lt(v, (9, 6))
        },
        {
            "cve": "CVE-2023-48795",
            "name": "Terrapin Attack",
            "severity": "MEDIUM",
            "affected": "OpenSSH < 9.6",
            "description": "Prefix truncation attack on Binary Packet Protocol (BPP) with ChaCha20-Poly1305 or CBC with Encrypt-then-MAC",
            "check": lambda v: _version_lt(v, (9, 6))
        },
        {
            "cve": "CVE-2023-38408",
            "name": "Remote code execution via ssh-agent forwarding",
            "severity": "HIGH",
            "affected": "OpenSSH < 9.3p2",
            "description": "Remote code execution via PKCS#11 providers in forwarded ssh-agent",
            "check": lambda v: _version_lt(v, (9, 3, 2))
        },
        {
            "cve": "CVE-2021-41617",
            "name": "Privilege escalation via AuthorizedKeysCommand/AuthorizedPrincipalsCommand",
            "severity": "HIGH",
            "affected": "OpenSSH 6.2 - 8.7",
            "description": "sshd allows privilege escalation because supplemental groups are not initialized as expected",
            "check": lambda v: _version_in_range(v, (6, 2), (8, 7))
        },
        {
            "cve": "CVE-2020-15778",
            "name": "Command injection via scp",
            "severity": "HIGH",
            "affected": "OpenSSH < 9.0",
            "description": "Command injection via backtick characters in scp target filenames",
            "check": lambda v: _version_lt(v, (9, 0))
        },
        {
            "cve": "CVE-2019-6111",
            "name": "SCP client spoofing via object name",
            "severity": "MEDIUM",
            "affected": "OpenSSH < 8.0",
            "description": "SCP client allows server to write arbitrary files via modified object names",
            "check": lambda v: _version_lt(v, (8, 0))
        },
        {
            "cve": "CVE-2018-15473",
            "name": "Username enumeration",
            "severity": "MEDIUM",
            "affected": "OpenSSH < 7.8",
            "description": "User enumeration via malformed authentication requests",
            "check": lambda v: _version_lt(v, (7, 8))
        },
        {
            "cve": "CVE-2016-20012",
            "name": "Username enumeration via auth timing",
            "severity": "LOW",
            "affected": "OpenSSH < 8.8",
            "description": "Allows remote attackers to enumerate valid usernames via timing differences",
            "check": lambda v: _version_lt(v, (8, 8))
        },
    ],
    "Dropbear": [
        {
            "cve": "CVE-2023-48795",
            "name": "Terrapin Attack",
            "severity": "MEDIUM",
            "affected": "Dropbear < 2022.83+",
            "description": "Prefix truncation attack on Binary Packet Protocol",
            "check": lambda v: _version_lt(v, (2022, 83))
        },
        {
            "cve": "CVE-2021-36369",
            "name": "Trivial authentication bypass",
            "severity": "HIGH",
            "affected": "Dropbear < 2022.82",
            "description": "Allows trivial authentication when no login credentials are configured",
            "check": lambda v: _version_lt(v, (2022, 82))
        },
    ],
    "libssh": [
        {
            "cve": "CVE-2023-48795",
            "name": "Terrapin Attack",
            "severity": "MEDIUM",
            "affected": "libssh < 0.10.6 / 0.9.8",
            "description": "Prefix truncation attack on Binary Packet Protocol",
            "check": lambda v: _version_lt(v, (0, 10, 6))
        },
        {
            "cve": "CVE-2023-6004",
            "name": "ProxyCommand/ProxyJump command injection",
            "severity": "LOW",
            "affected": "libssh < 0.10.6 / 0.9.8",
            "description": "Command injection via hostname with ProxyCommand/ProxyJump",
            "check": lambda v: _version_lt(v, (0, 10, 6))
        },
    ],
}


# ============================================================================
# Weak Algorithm Definitions
# ============================================================================

WEAK_KEX_ALGORITHMS = {
    "diffie-hellman-group1-sha1": "Uses 1024-bit DH group, vulnerable to Logjam attack",
    "diffie-hellman-group-exchange-sha1": "Uses SHA-1 which is deprecated",
    "diffie-hellman-group14-sha1": "Uses SHA-1 which is deprecated",
    "ecdh-sha2-nistp256": "NIST curve with potential backdoor concerns",
    "kexguess2@matt.ucc.asn.au": "Non-standard, potentially insecure KEX guess extension",
}

WEAK_CIPHERS = {
    "3des-cbc": "Triple DES is slow and has 64-bit block size, vulnerable to Sweet32",
    "blowfish-cbc": "Legacy cipher, 64-bit block size, vulnerable to Sweet32",
    "cast128-cbc": "Legacy cipher, 64-bit block size",
    "arcfour": "RC4 is broken, multiple known biases",
    "arcfour128": "RC4 is broken, multiple known biases",
    "arcfour256": "RC4 is broken, multiple known biases",
    "aes128-cbc": "CBC mode vulnerable to padding oracle attacks (CVE-2008-5161)",
    "aes192-cbc": "CBC mode vulnerable to padding oracle attacks (CVE-2008-5161)",
    "aes256-cbc": "CBC mode vulnerable to padding oracle attacks (CVE-2008-5161)",
    "rijndael-cbc@lysator.liu.se": "CBC mode, renamed AES-256-CBC",
}

WEAK_MACS = {
    "hmac-md5": "MD5 is cryptographically broken",
    "hmac-md5-96": "MD5 is cryptographically broken, truncated to 96 bits",
    "hmac-sha1": "SHA-1 is deprecated",
    "hmac-sha1-96": "SHA-1 is deprecated, truncated to 96 bits",
    "umac-64@openssh.com": "64-bit UMAC, short tag length",
    "hmac-ripemd160": "RIPEMD-160 no longer considered secure",
    "hmac-ripemd160@openssh.com": "RIPEMD-160 no longer considered secure",
}

WEAK_HOST_KEY_TYPES = {
    "ssh-dss": "DSA keys limited to 1024 bits, insufficient security",
    "ssh-rsa": "Uses SHA-1 signatures, deprecated in OpenSSH 8.8+",
    "ecdsa-sha2-nistp256": "NIST curve with potential backdoor concerns",
}


# ============================================================================
# OS/Software Fingerprinting Database
# ============================================================================

SSH_FINGERPRINTS = [
    # (regex_pattern, software, os_guess)
    (r"SSH-2\.0-OpenSSH_(\S+)\s+Ubuntu", "OpenSSH", "Ubuntu Linux"),
    (r"SSH-2\.0-OpenSSH_(\S+)\s+Debian", "OpenSSH", "Debian Linux"),
    (r"SSH-2\.0-OpenSSH_(\S+)\s+FreeBSD", "OpenSSH", "FreeBSD"),
    (r"SSH-2\.0-OpenSSH.*fc\d+", "OpenSSH", "Fedora Linux"),
    (r"SSH-2\.0-OpenSSH.*el\d+", "OpenSSH", "RHEL/CentOS Linux"),
    (r"SSH-2\.0-OpenSSH_for_Windows", "OpenSSH", "Windows"),
    (r"SSH-2\.0-OpenSSH_(\S+)", "OpenSSH", "Unknown (likely Linux/Unix)"),
    (r"SSH-2\.0-dropbear_(\S+)", "Dropbear", "Embedded/Linux"),
    (r"SSH-2\.0-dropbear", "Dropbear", "Embedded/Linux"),
    (r"SSH-2\.0-libssh[_-](\S+)", "libssh", "Unknown"),
    (r"SSH-2\.0-libssh", "libssh", "Unknown"),
    (r"SSH-2\.0-ROSSSH", "RouterOS SSH", "MikroTik RouterOS"),
    (r"SSH-2\.0-Cisco", "Cisco SSH", "Cisco IOS/IOS-XE"),
    (r"SSH-1\.99-Cisco", "Cisco SSH", "Cisco IOS (legacy)"),
    (r"SSH-2\.0-Serv-U", "Serv-U", "Windows (Serv-U FTP)"),
    (r"SSH-2\.0-HUAWEI", "Huawei SSH", "Huawei VRP"),
    (r"SSH-2\.0-xxxxxxx", "Unknown (obfuscated)", "Unknown (banner obfuscated)"),
    (r"SSH-2\.0-paramiko_(\S+)", "Paramiko", "Python application"),
    (r"SSH-2\.0-Go", "Go SSH", "Go application"),
    (r"SSH-2\.0-AsyncSSH_(\S+)", "AsyncSSH", "Python application"),
    (r"SSH-1\.", "SSHv1", "Legacy (SSHv1 - INSECURE)"),
]


# ============================================================================
# Version Comparison Helpers
# ============================================================================

def _parse_version(version_str: str) -> tuple:
    """Parse a version string into a tuple of integers."""
    # Remove common suffixes like 'p1', 'p2' etc.
    match = re.match(r'(\d+(?:\.\d+)*(?:p\d+)?)', version_str)
    if not match:
        return (0,)
    ver = match.group(1)
    # Handle 'p' as a version component (e.g., 8.9p1 -> (8, 9, 1))
    parts = re.split(r'[.p]', ver)
    return tuple(int(x) for x in parts if x.isdigit())


def _version_lt(version: str, target: tuple) -> bool:
    """Check if version is less than target."""
    v = _parse_version(version)
    return v < target


def _version_gte(version: str, target: tuple) -> bool:
    """Check if version is greater than or equal to target."""
    v = _parse_version(version)
    return v >= target


def _version_in_range(version: str, low: tuple, high: tuple) -> bool:
    """Check if version is in range [low, high] inclusive."""
    v = _parse_version(version)
    return low <= v <= high


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class HostKeyInfo:
    """Information about a host's SSH key."""
    key_type: str = ""
    key_bits: int = 0
    fingerprint_sha256: str = ""
    fingerprint_md5: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AlgorithmInfo:
    """Information about SSH algorithms supported by a host."""
    kex_algorithms: List[str] = field(default_factory=list)
    ciphers: List[str] = field(default_factory=list)
    macs: List[str] = field(default_factory=list)
    host_key_types: List[str] = field(default_factory=list)
    weak_kex: List[dict] = field(default_factory=list)
    weak_ciphers: List[dict] = field(default_factory=list)
    weak_macs: List[dict] = field(default_factory=list)
    weak_host_keys: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FingerprintInfo:
    """OS/software fingerprint information from SSH banner."""
    software: str = ""
    software_version: str = ""
    os_guess: str = ""
    raw_banner: str = ""
    protocol_version: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VulnerabilityInfo:
    """Known vulnerability information."""
    cve: str = ""
    name: str = ""
    severity: str = ""
    affected: str = ""
    description: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


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
    auth_method: str = "password"
    key_file: str = ""
    host_key_info: Optional[HostKeyInfo] = None
    algorithm_info: Optional[AlgorithmInfo] = None
    fingerprint_info: Optional[FingerprintInfo] = None
    vulnerabilities: List[VulnerabilityInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert result to dictionary."""
        d = {
            'host': self.host,
            'port': self.port,
            'username': self.username,
            'password': self.password if self.auth_method == 'password' else '',
            'success': self.success,
            'timestamp': self.timestamp,
            'initial_output': self.initial_output,
            'error_message': self.error_message,
            'banner': self.banner,
            'connection_time': self.connection_time,
            'auth_method': self.auth_method,
            'key_file': self.key_file,
        }
        if self.host_key_info:
            d['host_key_info'] = self.host_key_info.to_dict()
        if self.algorithm_info:
            d['algorithm_info'] = self.algorithm_info.to_dict()
        if self.fingerprint_info:
            d['fingerprint_info'] = self.fingerprint_info.to_dict()
        if self.vulnerabilities:
            d['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        return d


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


# ============================================================================
# Color Support
# ============================================================================

class ColorOutput:
    """Manages colored terminal output with toggle support."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled and sys.stdout.isatty()

    def green(self, text: str) -> str:
        return f"\033[92m{text}\033[0m" if self.enabled else text

    def red(self, text: str) -> str:
        return f"\033[91m{text}\033[0m" if self.enabled else text

    def yellow(self, text: str) -> str:
        return f"\033[93m{text}\033[0m" if self.enabled else text

    def cyan(self, text: str) -> str:
        return f"\033[96m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return f"\033[1m{text}\033[0m" if self.enabled else text

    def dim(self, text: str) -> str:
        return f"\033[2m{text}\033[0m" if self.enabled else text


# ============================================================================
# Progress Bar
# ============================================================================

class ProgressBar:
    """Terminal progress bar with ETA calculation."""

    def __init__(self, total: int, color: ColorOutput, width: int = 30):
        self.total = total
        self.color = color
        self.width = width
        self.start_time = time.time()
        self._last_line_length = 0

    def _format_time(self, seconds: float) -> str:
        """Format seconds into human-readable time."""
        if seconds < 0 or seconds > 86400 * 7:
            return "--:--"
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        if hours > 0:
            return f"{hours}:{minutes:02d}:{secs:02d}"
        return f"{minutes}:{secs:02d}"

    def update(self, current: int, status_text: str = ""):
        """Update progress bar display."""
        if self.total <= 0:
            return

        percentage = (current / self.total) * 100
        filled = int(self.width * current / self.total)
        bar = "█" * filled + "░" * (self.width - filled)

        # Calculate ETA
        elapsed = time.time() - self.start_time
        if current > 0:
            rate = elapsed / current
            remaining = rate * (self.total - current)
            eta_str = self._format_time(remaining)
        else:
            eta_str = "--:--"

        elapsed_str = self._format_time(elapsed)

        line = (
            f"\r{self.color.cyan('Progress')} |{bar}| "
            f"{percentage:5.1f}% "
            f"[{current}/{self.total}] "
            f"Elapsed: {elapsed_str} ETA: {eta_str}"
        )
        if status_text:
            line += f"  {status_text}"

        # Clear any remaining characters from previous line
        padding = max(0, self._last_line_length - len(line))
        sys.stdout.write(line + " " * padding)
        sys.stdout.flush()
        self._last_line_length = len(line)

    def finish(self):
        """Complete the progress bar."""
        elapsed = time.time() - self.start_time
        elapsed_str = self._format_time(elapsed)
        bar = "█" * self.width
        line = (
            f"\r{self.color.cyan('Progress')} |{bar}| "
            f"100.0% "
            f"[{self.total}/{self.total}] "
            f"Elapsed: {elapsed_str} Done!"
        )
        padding = max(0, self._last_line_length - len(line))
        sys.stdout.write(line + " " * padding + "\n")
        sys.stdout.flush()


# ============================================================================
# Main SSH Audit Client
# ============================================================================

class SSHAuditClient:
    """SSH Security Audit Client for testing login capabilities."""

    def __init__(
        self,
        timeout: int = 10,
        verbose: bool = False,
        threads: int = 1,
        output_file: Optional[str] = None,
        output_format: str = "text",
        color: bool = True,
        proxy: Optional[str] = None,
        quiet: bool = False
    ):
        """
        Initialize the SSH Audit Client.

        Args:
            timeout: Connection timeout in seconds
            verbose: Enable verbose output
            threads: Number of concurrent threads
            output_file: Path to output file for results
            output_format: Output format ('text', 'json', 'csv')
            color: Enable colored output
            proxy: Proxy URL (socks5://host:port or http://host:port)
            quiet: Suppress progress output
        """
        self.timeout = timeout
        self.verbose = verbose
        self.threads = threads
        self.output_file = output_file
        self.output_format = output_format
        self.quiet = quiet
        self.results: List[ScanResult] = []
        self.stats = ScanStatistics()
        self.color = ColorOutput(enabled=color)
        self.proxy = proxy
        self._proxy_type = None
        self._proxy_host = None
        self._proxy_port = None
        self._setup_logging()
        self._parse_proxy()

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

    def _parse_proxy(self):
        """Parse proxy URL into components."""
        if not self.proxy:
            return

        proxy = self.proxy.strip()

        # Parse proxy type
        if proxy.startswith("socks5://") or proxy.startswith("socks5h://"):
            self._proxy_type = "socks5"
            proxy = proxy.split("://", 1)[1]
        elif proxy.startswith("socks4://"):
            self._proxy_type = "socks4"
            proxy = proxy.split("://", 1)[1]
        elif proxy.startswith("http://"):
            self._proxy_type = "http"
            proxy = proxy.split("://", 1)[1]
        elif proxy.startswith("https://"):
            self._proxy_type = "http"
            proxy = proxy.split("://", 1)[1]
        else:
            # Default to SOCKS5 if no scheme specified
            self._proxy_type = "socks5"

        # Parse host and port
        if ":" in proxy:
            host, port_str = proxy.rsplit(":", 1)
            try:
                self._proxy_port = int(port_str)
            except ValueError:
                raise ValueError(f"Invalid proxy port: {port_str}")
            self._proxy_host = host
        else:
            self._proxy_host = proxy
            self._proxy_port = 1080 if self._proxy_type in ("socks4", "socks5") else 8080

    def _create_proxy_socket(self, dest_host: str, dest_port: int) -> socket.socket:
        """
        Create a socket connection through the configured proxy.

        Args:
            dest_host: Destination hostname or IP
            dest_port: Destination port

        Returns:
            Connected socket through the proxy
        """
        if self._proxy_type in ("socks4", "socks5"):
            if not HAS_PYSOCKS:
                raise ImportError(
                    "PySocks is required for SOCKS proxy support.\n"
                    "Install with: pip install pysocks"
                )
            proxy_type_map = {
                "socks4": pysocks.SOCKS4,
                "socks5": pysocks.SOCKS5,
            }
            sock = pysocks.socksocket()
            sock.set_proxy(
                proxy_type_map[self._proxy_type],
                self._proxy_host,
                self._proxy_port
            )
            sock.settimeout(self.timeout)
            sock.connect((dest_host, dest_port))
            return sock

        elif self._proxy_type == "http":
            # HTTP CONNECT proxy
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self._proxy_host, self._proxy_port))

            # Send CONNECT request
            connect_req = (
                f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\n"
                f"Host: {dest_host}:{dest_port}\r\n"
                f"\r\n"
            )
            sock.sendall(connect_req.encode())

            # Read response
            response = b""
            while b"\r\n\r\n" not in response:
                data = sock.recv(4096)
                if not data:
                    raise ConnectionError("HTTP proxy closed connection during CONNECT")
                response += data

            status_line = response.split(b"\r\n")[0].decode("utf-8", errors="replace")
            if "200" not in status_line:
                raise ConnectionError(f"HTTP proxy CONNECT failed: {status_line}")

            return sock

        raise ValueError(f"Unsupported proxy type: {self._proxy_type}")

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

    def _parse_combo_file(self, filepath: str) -> List[Tuple[str, str]]:
        """
        Parse a credential combo file with user:password format.

        Supports formats:
            user:password
            user:pass:word  (password containing colons - split on first colon only)

        Args:
            filepath: Path to the combo file

        Returns:
            List of (username, password) tuples
        """
        lines = self._read_file_lines(filepath, "combo")
        combos = []
        for line in lines:
            if ':' in line:
                # Split on first colon only (password may contain colons)
                username, password = line.split(':', 1)
                username = username.strip()
                password = password.strip()
                if username:
                    combos.append((username, password))
            else:
                self.logger.warning(f"Skipping invalid combo line (no colon separator): {line}")
        return combos

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
            if self._proxy_type:
                sock = self._create_proxy_socket(host, port)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
            sock.close()
            return banner
        except Exception:
            return ""

    def _fingerprint_banner(self, banner: str) -> FingerprintInfo:
        """
        Analyze SSH banner to identify software and OS.

        Args:
            banner: Raw SSH banner string

        Returns:
            FingerprintInfo with identified software and OS
        """
        info = FingerprintInfo(raw_banner=banner)

        if not banner:
            return info

        # Extract protocol version
        if banner.startswith("SSH-"):
            parts = banner.split("-", 2)
            if len(parts) >= 2:
                info.protocol_version = parts[1]

        # Match against known fingerprints
        for pattern, software, os_guess in SSH_FINGERPRINTS:
            match = re.match(pattern, banner, re.IGNORECASE)
            if match:
                info.software = software
                info.os_guess = os_guess
                # Extract version if captured
                if match.groups():
                    info.software_version = match.group(1)
                break

        # If no match, try a generic extraction
        if not info.software and banner.startswith("SSH-"):
            parts = banner.split("-", 2)
            if len(parts) >= 3:
                info.software = parts[2].split("_")[0] if "_" in parts[2] else parts[2].split()[0]

        return info

    def _check_vulnerabilities(self, fingerprint: FingerprintInfo) -> List[VulnerabilityInfo]:
        """
        Check for known vulnerabilities based on software fingerprint.

        Args:
            fingerprint: Software fingerprint information

        Returns:
            List of matching vulnerabilities
        """
        vulns = []

        if not fingerprint.software or not fingerprint.software_version:
            return vulns

        # Look up vulnerability database for the software
        software_vulns = SSH_VULNERABILITIES.get(fingerprint.software, [])

        for vuln in software_vulns:
            try:
                if vuln["check"](fingerprint.software_version):
                    vulns.append(VulnerabilityInfo(
                        cve=vuln["cve"],
                        name=vuln["name"],
                        severity=vuln["severity"],
                        affected=vuln["affected"],
                        description=vuln["description"]
                    ))
            except Exception:
                # Skip if version check fails
                pass

        return vulns

    def _enumerate_algorithms(self, host: str, port: int) -> AlgorithmInfo:
        """
        Enumerate SSH algorithms supported by the server using paramiko's transport.

        Args:
            host: Target hostname or IP
            port: Target port

        Returns:
            AlgorithmInfo with supported algorithms and weakness analysis
        """
        algo_info = AlgorithmInfo()

        try:
            if self._proxy_type:
                sock = self._create_proxy_socket(host, port)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((host, port))

            transport = paramiko.Transport(sock)
            # Use a SecurityOptions object to discover server algorithms
            try:
                transport.connect()
            except paramiko.SSHException:
                # Connection may fail but we can still get algorithm info
                # from the key exchange phase
                pass

            # Get negotiated/available algorithms from the transport
            sec_opts = transport.get_security_options()

            algo_info.kex_algorithms = list(sec_opts.kex)
            algo_info.ciphers = list(sec_opts.ciphers)
            algo_info.macs = list(sec_opts.digests)
            algo_info.host_key_types = list(sec_opts.key_types)

            transport.close()
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"Algorithm enumeration failed for {host}:{port}: {e}")
            return algo_info

        # Analyze for weaknesses
        for alg in algo_info.kex_algorithms:
            if alg in WEAK_KEX_ALGORITHMS:
                algo_info.weak_kex.append({
                    "algorithm": alg,
                    "reason": WEAK_KEX_ALGORITHMS[alg]
                })

        for cipher in algo_info.ciphers:
            if cipher in WEAK_CIPHERS:
                algo_info.weak_ciphers.append({
                    "algorithm": cipher,
                    "reason": WEAK_CIPHERS[cipher]
                })

        for mac in algo_info.macs:
            if mac in WEAK_MACS:
                algo_info.weak_macs.append({
                    "algorithm": mac,
                    "reason": WEAK_MACS[mac]
                })

        for key_type in algo_info.host_key_types:
            if key_type in WEAK_HOST_KEY_TYPES:
                algo_info.weak_host_keys.append({
                    "algorithm": key_type,
                    "reason": WEAK_HOST_KEY_TYPES[key_type]
                })

        return algo_info

    def _get_host_key_info(self, host: str, port: int) -> HostKeyInfo:
        """
        Collect host key fingerprint information.

        Args:
            host: Target hostname or IP
            port: Target port

        Returns:
            HostKeyInfo with key details and fingerprints
        """
        info = HostKeyInfo()

        try:
            if self._proxy_type:
                sock = self._create_proxy_socket(host, port)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((host, port))

            transport = paramiko.Transport(sock)
            try:
                transport.connect()
            except paramiko.SSHException:
                pass

            key = transport.get_remote_server_key()
            if key:
                info.key_type = key.get_name()
                info.key_bits = key.get_bits()

                # SHA-256 fingerprint
                key_bytes = key.asbytes()
                sha256_digest = hashlib.sha256(key_bytes).digest()
                import base64
                info.fingerprint_sha256 = "SHA256:" + base64.b64encode(sha256_digest).decode('ascii').rstrip('=')

                # MD5 fingerprint
                md5_digest = hashlib.md5(key_bytes).hexdigest()
                info.fingerprint_md5 = "MD5:" + ":".join(
                    md5_digest[i:i+2] for i in range(0, len(md5_digest), 2)
                )

            transport.close()
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"Host key collection failed for {host}:{port}: {e}")

        return info

    def _try_login(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        key_file: Optional[str] = None
    ) -> ScanResult:
        """
        Attempt SSH login to a target host.

        Args:
            host: Target hostname or IP
            port: Target port
            username: SSH username
            password: SSH password (or key passphrase if key_file specified)
            key_file: Optional path to SSH private key file

        Returns:
            ScanResult object with attempt details
        """
        timestamp = datetime.now().isoformat()
        start_time = time.time()
        auth_method = "key" if key_file else "password"
        result = ScanResult(
            host=host,
            port=port,
            username=username,
            password=password if not key_file else "",
            success=False,
            timestamp=timestamp,
            auth_method=auth_method,
            key_file=key_file or ""
        )

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Get banner before full connection
            result.banner = self._get_ssh_banner(host, port)

            # OS/software fingerprinting
            result.fingerprint_info = self._fingerprint_banner(result.banner)

            # Vulnerability checking
            result.vulnerabilities = self._check_vulnerabilities(result.fingerprint_info)

            # Collect host key fingerprint
            result.host_key_info = self._get_host_key_info(host, port)

            # Enumerate algorithms
            result.algorithm_info = self._enumerate_algorithms(host, port)

            # Build connection kwargs
            connect_kwargs = {
                'hostname': host,
                'port': port,
                'username': username,
                'timeout': self.timeout,
                'banner_timeout': self.timeout,
                'allow_agent': False,
                'look_for_keys': False,
            }

            # Create proxy socket if needed
            if self._proxy_type:
                sock = self._create_proxy_socket(host, port)
                connect_kwargs['sock'] = sock

            # Key-based or password authentication
            if key_file:
                # Try loading the key (supports RSA, Ed25519, ECDSA, DSA)
                pkey = self._load_private_key(key_file, password if password else None)
                connect_kwargs['pkey'] = pkey
            else:
                connect_kwargs['password'] = password

            # Attempt connection
            client.connect(**connect_kwargs)

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

    def _load_private_key(
        self,
        key_file: str,
        passphrase: Optional[str] = None
    ) -> paramiko.PKey:
        """
        Load an SSH private key file, auto-detecting the key type.

        Supports RSA, Ed25519, ECDSA, and DSA keys.

        Args:
            key_file: Path to the private key file
            passphrase: Optional passphrase for encrypted keys

        Returns:
            Loaded paramiko key object

        Raises:
            paramiko.SSHException: If key cannot be loaded
        """
        key_path = Path(key_file)
        if not key_path.exists():
            raise FileNotFoundError(f"Key file not found: {key_file}")
        if not key_path.is_file():
            raise ValueError(f"Key path is not a file: {key_file}")

        # Try each key type in order of likelihood
        key_classes = [
            (paramiko.RSAKey, "RSA"),
            (paramiko.Ed25519Key, "Ed25519"),
            (paramiko.ECDSAKey, "ECDSA"),
        ]
        # DSSKey was removed in paramiko 4.0; include if available
        if hasattr(paramiko, 'DSSKey'):
            key_classes.append((paramiko.DSSKey, "DSA"))

        last_error = None
        for key_class, key_name in key_classes:
            try:
                return key_class.from_private_key_file(key_file, password=passphrase)
            except paramiko.PasswordRequiredException:
                raise paramiko.SSHException(
                    f"Key file {key_file} is encrypted but no passphrase provided. "
                    f"Use -p to specify the passphrase."
                )
            except (paramiko.SSHException, ValueError) as e:
                last_error = e
                continue

        raise paramiko.SSHException(
            f"Unable to load key file {key_file}: Unsupported key type or invalid format. "
            f"Last error: {last_error}"
        )

    def _print_progress(self, result: ScanResult, current: int, total: int):
        """
        Print scan progress to stdout.

        Args:
            result: The scan result to display
            current: Current attempt number
            total: Total number of attempts
        """
        status = "[SUCCESS]" if result.success else "[FAILED]"
        if result.success:
            status = self.color.green(status)
        else:
            status = self.color.red(status)

        auth_info = f"key={result.key_file}" if result.auth_method == "key" else f"user={result.username}"

        print(
            f"  {status} "
            f"{result.host}:{result.port} "
            f"{auth_info}"
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
        ports: List[int],
        key_files: Optional[List[str]] = None,
        combo_list: Optional[List[Tuple[str, str]]] = None
    ) -> List[ScanResult]:
        """
        Perform SSH audit scan on specified targets.

        Args:
            targets: List of target hosts/networks
            usernames: List of usernames to try
            passwords: List of passwords to try
            ports: List of ports to try
            key_files: Optional list of SSH private key files
            combo_list: Optional list of (username, password) tuples from combo files

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

        has_password_creds = usernames and passwords
        has_key_creds = key_files and usernames
        has_combo_creds = combo_list

        if not has_password_creds and not has_key_creds and not has_combo_creds:
            print("ERROR: No credentials specified.", file=sys.stderr)
            print("Please provide username/password, key files, or combo file.", file=sys.stderr)
            return []

        if not ports:
            ports = [22]

        # Build work items: (host, port, username, password, key_file)
        work_items = []

        # Password-based work items
        if has_password_creds:
            for host in hosts:
                for port in ports:
                    for username in usernames:
                        for password in passwords:
                            work_items.append((host, port, username, password, None))

        # Key-based work items
        if has_key_creds:
            for host in hosts:
                for port in ports:
                    for username in usernames:
                        for key_file in key_files:
                            # Password here acts as passphrase for encrypted keys
                            work_items.append((host, port, username, "", key_file))

        # Combo file work items
        if has_combo_creds:
            for host in hosts:
                for port in ports:
                    for username, password in combo_list:
                        work_items.append((host, port, username, password, None))

        total = len(work_items)

        print(f"\n{'='*60}")
        print(f"SSH Security Audit - {self.color.bold(f'{__program_name__} v{__version__}')}")
        print(f"{'='*60}")
        print(f"Targets: {len(hosts)} host(s)")
        if has_password_creds:
            print(f"Usernames: {len(usernames)}")
            print(f"Passwords: {len(passwords)}")
        if has_key_creds:
            print(f"Key files: {len(key_files)}")
        if has_combo_creds:
            print(f"Combo entries: {len(combo_list)}")
        print(f"Ports: {ports}")
        print(f"Total combinations: {total}")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        if self._proxy_type:
            print(f"Proxy: {self._proxy_type}://{self._proxy_host}:{self._proxy_port}")
        print(f"{'='*60}\n")

        # Initialize progress bar
        progress_bar = None
        if not self.quiet:
            progress_bar = ProgressBar(total, self.color)

        current = 0

        if self.threads > 1:
            # Multi-threaded execution
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(
                        self._try_login, h, p, u, pw, kf
                    ): (h, p, u, pw, kf)
                    for h, p, u, pw, kf in work_items
                }

                for future in as_completed(futures):
                    current += 1
                    try:
                        result = future.result()
                        self.results.append(result)
                        if not self.quiet:
                            if progress_bar:
                                status = self.color.green("✓") if result.success else self.color.red("✗")
                                progress_bar.update(current, status)
                            self._print_progress(result, current, total)
                    except Exception as e:
                        h, p, u, pw, kf = futures[future]
                        print(f"ERROR: Unexpected exception for {h}:{p}: {e}", file=sys.stderr)
        else:
            # Single-threaded execution
            for host, port, username, password, key_file in work_items:
                current += 1
                result = self._try_login(host, port, username, password, key_file)
                self.results.append(result)
                if not self.quiet:
                    if progress_bar:
                        status = self.color.green("✓") if result.success else self.color.red("✗")
                        progress_bar.update(current, status)
                    self._print_progress(result, current, total)

        if progress_bar and not self.quiet:
            progress_bar.finish()

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
        print(self.color.bold("SCAN SUMMARY"))
        print(f"{'='*60}")
        print(f"Total attempts:        {self.stats.total_attempts}")
        print(f"Successful logins:     {self.color.green(str(self.stats.successful_logins))}")
        print(f"Failed logins:         {self.stats.failed_logins}")
        print(f"  - Auth failures:     {self.stats.authentication_errors}")
        print(f"  - Connection errors: {self.stats.connection_errors}")
        print(f"  - Timeouts:          {self.stats.timeout_errors}")
        print(f"Duration:              {self.stats.get_duration():.2f} seconds")
        print(f"{'='*60}")

        # List successful logins
        successful = [r for r in self.results if r.success]
        if successful:
            print(f"\n{self.color.bold('SUCCESSFUL LOGINS:')}")
            print("-" * 40)
            for r in successful:
                if r.auth_method == "key":
                    print(f"  {self.color.green('✓')} {r.host}:{r.port} - {r.username} (key: {r.key_file})")
                else:
                    print(f"  {self.color.green('✓')} {r.host}:{r.port} - {r.username}:{r.password}")
                if r.banner:
                    print(f"    Banner: {r.banner}")
                if r.initial_output:
                    # Show truncated output
                    output_preview = r.initial_output[:200].replace('\n', ' ')
                    print(f"    Output: {output_preview}...")
            print()

        # Print host key fingerprints
        seen_hosts = set()
        host_key_results = [r for r in self.results if r.host_key_info and r.host_key_info.key_type]
        if host_key_results:
            print(f"{self.color.bold('HOST KEY FINGERPRINTS:')}")
            print("-" * 40)
            for r in host_key_results:
                host_port = f"{r.host}:{r.port}"
                if host_port in seen_hosts:
                    continue
                seen_hosts.add(host_port)
                hk = r.host_key_info
                print(f"  {host_port}")
                print(f"    Type: {hk.key_type} ({hk.key_bits} bits)")
                print(f"    {hk.fingerprint_sha256}")
                print(f"    {hk.fingerprint_md5}")
            print()

        # Print OS/software fingerprints
        seen_hosts = set()
        fp_results = [r for r in self.results if r.fingerprint_info and r.fingerprint_info.software]
        if fp_results:
            print(f"{self.color.bold('SOFTWARE FINGERPRINTS:')}")
            print("-" * 40)
            for r in fp_results:
                host_port = f"{r.host}:{r.port}"
                if host_port in seen_hosts:
                    continue
                seen_hosts.add(host_port)
                fp = r.fingerprint_info
                version_str = f" {fp.software_version}" if fp.software_version else ""
                print(f"  {host_port}: {fp.software}{version_str} (OS: {fp.os_guess})")
            print()

        # Print vulnerability findings
        seen_hosts = set()
        vuln_results = [r for r in self.results if r.vulnerabilities]
        if vuln_results:
            print(f"{self.color.bold(self.color.yellow('POTENTIAL VULNERABILITIES:'))}")
            print("-" * 40)
            for r in vuln_results:
                host_port = f"{r.host}:{r.port}"
                if host_port in seen_hosts:
                    continue
                seen_hosts.add(host_port)
                for v in r.vulnerabilities:
                    severity_color = {
                        "HIGH": self.color.red,
                        "MEDIUM": self.color.yellow,
                        "LOW": self.color.dim,
                    }.get(v.severity, self.color.dim)
                    print(f"  {host_port}: {severity_color(f'[{v.severity}]')} {v.cve} - {v.name}")
                    print(f"    Affected: {v.affected}")
                    print(f"    {v.description}")
            print()

        # Print algorithm weakness findings
        seen_hosts = set()
        algo_results = [
            r for r in self.results
            if r.algorithm_info and (
                r.algorithm_info.weak_kex or r.algorithm_info.weak_ciphers or
                r.algorithm_info.weak_macs or r.algorithm_info.weak_host_keys
            )
        ]
        if algo_results:
            print(f"{self.color.bold(self.color.yellow('WEAK ALGORITHMS DETECTED:'))}")
            print("-" * 40)
            for r in algo_results:
                host_port = f"{r.host}:{r.port}"
                if host_port in seen_hosts:
                    continue
                seen_hosts.add(host_port)
                ai = r.algorithm_info
                print(f"  {host_port}:")
                if ai.weak_kex:
                    for w in ai.weak_kex:
                        print(f"    {self.color.yellow('KEX')}: {w['algorithm']} - {w['reason']}")
                if ai.weak_ciphers:
                    for w in ai.weak_ciphers:
                        print(f"    {self.color.yellow('Cipher')}: {w['algorithm']} - {w['reason']}")
                if ai.weak_macs:
                    for w in ai.weak_macs:
                        print(f"    {self.color.yellow('MAC')}: {w['algorithm']} - {w['reason']}")
                if ai.weak_host_keys:
                    for w in ai.weak_host_keys:
                        print(f"    {self.color.yellow('HostKey')}: {w['algorithm']} - {w['reason']}")
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
                "duration_seconds": self.stats.get_duration(),
                "proxy": f"{self._proxy_type}://{self._proxy_host}:{self._proxy_port}" if self._proxy_type else None
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
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'host', 'port', 'username', 'password', 'auth_method', 'key_file',
                'success', 'timestamp', 'banner', 'initial_output', 'error_message',
                'connection_time', 'software', 'software_version', 'os_guess',
                'host_key_type', 'host_key_bits', 'host_key_sha256',
                'vulnerabilities'
            ])
            for r in self.results:
                vuln_str = "; ".join(
                    f"{v.cve}({v.severity})" for v in r.vulnerabilities
                ) if r.vulnerabilities else ""
                fp = r.fingerprint_info
                hk = r.host_key_info
                writer.writerow([
                    r.host, r.port, r.username,
                    r.password if r.auth_method == "password" else "",
                    r.auth_method, r.key_file,
                    r.success, r.timestamp, r.banner, r.initial_output,
                    r.error_message, r.connection_time,
                    fp.software if fp else "",
                    fp.software_version if fp else "",
                    fp.os_guess if fp else "",
                    hk.key_type if hk else "",
                    hk.key_bits if hk else "",
                    hk.fingerprint_sha256 if hk else "",
                    vuln_str
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
                    if r.auth_method == "key":
                        f.write(f"Auth: key ({r.key_file})\n")
                    else:
                        f.write(f"Password: {r.password}\n")
                    f.write(f"Timestamp: {r.timestamp}\n")
                    if r.banner:
                        f.write(f"Banner: {r.banner}\n")
                    if r.fingerprint_info and r.fingerprint_info.software:
                        fp = r.fingerprint_info
                        f.write(f"Software: {fp.software} {fp.software_version}\n")
                        f.write(f"OS Guess: {fp.os_guess}\n")
                    if r.host_key_info and r.host_key_info.key_type:
                        hk = r.host_key_info
                        f.write(f"Host Key: {hk.key_type} ({hk.key_bits} bits)\n")
                        f.write(f"  {hk.fingerprint_sha256}\n")
                        f.write(f"  {hk.fingerprint_md5}\n")
                    if r.initial_output:
                        f.write(f"Initial Output:\n{r.initial_output}\n")
                    f.write(f"{'-'*40}\n\n")
            else:
                f.write("No successful logins.\n\n")

            # Vulnerability section
            vuln_results = [r for r in self.results if r.vulnerabilities]
            if vuln_results:
                f.write(f"{'='*60}\n")
                f.write("POTENTIAL VULNERABILITIES\n")
                f.write(f"{'='*60}\n\n")
                seen = set()
                for r in vuln_results:
                    hp = f"{r.host}:{r.port}"
                    if hp in seen:
                        continue
                    seen.add(hp)
                    for v in r.vulnerabilities:
                        f.write(f"{hp}: [{v.severity}] {v.cve} - {v.name}\n")
                        f.write(f"  Affected: {v.affected}\n")
                        f.write(f"  {v.description}\n\n")

            # Algorithm weakness section
            algo_results = [
                r for r in self.results
                if r.algorithm_info and (
                    r.algorithm_info.weak_kex or r.algorithm_info.weak_ciphers or
                    r.algorithm_info.weak_macs or r.algorithm_info.weak_host_keys
                )
            ]
            if algo_results:
                f.write(f"{'='*60}\n")
                f.write("WEAK ALGORITHMS\n")
                f.write(f"{'='*60}\n\n")
                seen = set()
                for r in algo_results:
                    hp = f"{r.host}:{r.port}"
                    if hp in seen:
                        continue
                    seen.add(hp)
                    ai = r.algorithm_info
                    f.write(f"{hp}:\n")
                    for w in ai.weak_kex:
                        f.write(f"  KEX: {w['algorithm']} - {w['reason']}\n")
                    for w in ai.weak_ciphers:
                        f.write(f"  Cipher: {w['algorithm']} - {w['reason']}\n")
                    for w in ai.weak_macs:
                        f.write(f"  MAC: {w['algorithm']} - {w['reason']}\n")
                    for w in ai.weak_host_keys:
                        f.write(f"  HostKey: {w['algorithm']} - {w['reason']}\n")
                    f.write("\n")

            f.write(f"{'='*60}\n")
            f.write("ALL RESULTS\n")
            f.write(f"{'='*60}\n\n")

            for r in self.results:
                status = "SUCCESS" if r.success else "FAILED"
                auth = f"key={r.key_file}" if r.auth_method == "key" else r.username
                f.write(f"[{status}] {r.host}:{r.port} {auth}\n")
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

  %(prog)s -t 192.168.1.1 -u admin -k ~/.ssh/id_rsa
      Scan using SSH key authentication

  %(prog)s -t 192.168.1.1 -C combos.txt
      Scan using user:password combo file

  %(prog)s -t 192.168.1.1 -u root -p pass --proxy socks5://127.0.0.1:9050
      Scan through a SOCKS5 proxy (e.g., Tor)

  %(prog)s -t 192.168.1.1 -u root -p pass --no-color
      Scan with color output disabled (for piping/logging)

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

    # Key-based authentication
    key_group = parser.add_argument_group('Key Authentication')
    key_group.add_argument(
        '-k', '--key',
        action='append',
        dest='key_files',
        metavar='FILE',
        help=(
            'SSH private key file(s) for key-based authentication. '
            'Supports RSA, Ed25519, ECDSA, and DSA keys. '
            'Can be specified multiple times. Use -p for key passphrase.'
        )
    )
    key_group.add_argument(
        '-K', '--key-file',
        metavar='FILE',
        help=(
            'File containing paths to SSH private key files (one per line). '
            'Lines starting with # are treated as comments.'
        )
    )

    # Combo file
    combo_group = parser.add_argument_group('Combo File')
    combo_group.add_argument(
        '-C', '--combo-file',
        metavar='FILE',
        help=(
            'File containing username:password combinations (one per line). '
            'Format: username:password. Colons in passwords are supported. '
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
    output_group.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output. Useful for piping output to files or non-terminal use.'
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

    # Proxy options
    proxy_group = parser.add_argument_group('Proxy Options')
    proxy_group.add_argument(
        '--proxy',
        metavar='URL',
        help=(
            'Route connections through a proxy. '
            'Supported formats: socks5://host:port, socks4://host:port, http://host:port. '
            'SOCKS proxy requires PySocks (pip install pysocks).'
        )
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

    # Create a temporary client for file reading
    temp_client = SSHAuditClient()

    # Collect targets
    targets = []
    if args.targets:
        targets.extend(args.targets)
    if args.target_file:
        try:
            targets.extend(temp_client._read_file_lines(args.target_file, "target"))
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
            users.extend(temp_client._read_file_lines(args.user_file, "username"))
        except (FileNotFoundError, PermissionError, IOError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    # Collect passwords
    passwords = []
    if args.passwords:
        passwords.extend(args.passwords)
    if args.password_file:
        try:
            passwords.extend(temp_client._read_file_lines(args.password_file, "password"))
        except (FileNotFoundError, PermissionError, IOError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    # Collect key files
    key_files = []
    if args.key_files:
        key_files.extend(args.key_files)
    if args.key_file:
        try:
            key_files.extend(temp_client._read_file_lines(args.key_file, "key"))
        except (FileNotFoundError, PermissionError, IOError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    # Parse combo file
    combo_list = []
    if args.combo_file:
        try:
            combo_list = temp_client._parse_combo_file(args.combo_file)
        except (FileNotFoundError, PermissionError, IOError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    # Validate: must have at least some credentials
    has_password_creds = users and passwords
    has_key_creds = key_files and users
    has_combo_creds = bool(combo_list)

    if not has_password_creds and not has_key_creds and not has_combo_creds:
        print(
            "ERROR: No valid credentials specified.\n"
            "Please provide at least one of:\n"
            "  - Username (-u) and password (-p) combination\n"
            "  - Username (-u) and key file (-k) combination\n"
            "  - Combo file (-C) with user:password entries\n"
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
            port_lines = temp_client._read_file_lines(args.port_file, "port")
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

    # Validate proxy
    if args.proxy:
        proxy_str = args.proxy.strip()
        if proxy_str.startswith(("socks4://", "socks5://", "socks5h://")) and not HAS_PYSOCKS:
            print(
                "ERROR: PySocks library is required for SOCKS proxy support.\n"
                "Install it with: pip install pysocks",
                file=sys.stderr
            )
            sys.exit(1)

    # Determine color setting
    use_color = not args.no_color

    # Create and run audit client
    client = SSHAuditClient(
        timeout=args.timeout,
        verbose=args.verbose,
        threads=args.threads,
        output_file=args.output,
        output_format=args.format,
        color=use_color,
        proxy=args.proxy,
        quiet=args.quiet
    )

    try:
        results = client.scan(
            targets, users, passwords, ports,
            key_files=key_files if key_files else None,
            combo_list=combo_list if combo_list else None
        )

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
