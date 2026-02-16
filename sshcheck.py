#!/usr/bin/env python3
"""
sshcheck - SSH Security Audit Client

A security audit tool for testing SSH login capabilities across multiple hosts.
Designed for authorized penetration testing and security assessments.

Author: Robert Malmgren, with help of Claude code
License: MIT
"""

import argparse
import base64
import csv
import hashlib
import ipaddress
import json
import logging
import math
import os
import random
import re
import socket
import string
import struct
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from html import escape as html_escape
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Generator

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko is not installed.", file=sys.stderr)
    print("Please install it using: pip install paramiko", file=sys.stderr)
    sys.exit(1)

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# Version information
__version__ = "4.0.0"
__program_name__ = "sshcheck"


class SeverityLevel(Enum):
    """Severity levels for scan findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Known vulnerable OpenSSH versions (CVE-based)
VULNERABLE_VERSIONS = {
    # version_prefix: (severity, description)
    "OpenSSH_3.": (SeverityLevel.CRITICAL, "Ancient OpenSSH, multiple critical CVEs"),
    "OpenSSH_4.": (SeverityLevel.CRITICAL, "Very old OpenSSH, multiple critical CVEs"),
    "OpenSSH_5.": (SeverityLevel.HIGH, "Old OpenSSH with known vulnerabilities"),
    "OpenSSH_6.": (SeverityLevel.HIGH, "Outdated OpenSSH with known vulnerabilities"),
    "OpenSSH_7.0": (SeverityLevel.MEDIUM, "CVE-2016-0777 roaming vulnerability"),
    "OpenSSH_7.1": (SeverityLevel.MEDIUM, "CVE-2016-0777 roaming vulnerability"),
    "OpenSSH_7.2": (SeverityLevel.LOW, "Minor vulnerabilities patched in later versions"),
    "OpenSSH_7.3": (SeverityLevel.LOW, "Minor vulnerabilities patched in later versions"),
    "OpenSSH_7.4": (SeverityLevel.LOW, "Minor vulnerabilities patched in later versions"),
    "OpenSSH_8.": (SeverityLevel.INFO, "Generally secure, check specific patch level"),
}

# Weak SSH algorithms
WEAK_ALGORITHMS = {
    "kex": {
        "diffie-hellman-group1-sha1": "Weak 1024-bit DH group",
        "diffie-hellman-group-exchange-sha1": "SHA-1 based key exchange",
        "ecdh-sha2-nistp256": "NIST curve, potential backdoor concerns",
    },
    "cipher": {
        "arcfour": "RC4 stream cipher, broken",
        "arcfour128": "RC4 stream cipher, broken",
        "arcfour256": "RC4 stream cipher, broken",
        "aes128-cbc": "CBC mode vulnerable to BEAST-like attacks",
        "aes192-cbc": "CBC mode vulnerable to BEAST-like attacks",
        "aes256-cbc": "CBC mode vulnerable to BEAST-like attacks",
        "3des-cbc": "Triple DES, slow and weak",
        "blowfish-cbc": "Blowfish CBC, deprecated",
        "cast128-cbc": "CAST128 CBC, deprecated",
    },
    "mac": {
        "hmac-md5": "MD5 based MAC, weak",
        "hmac-md5-96": "MD5 based MAC, weak",
        "hmac-sha1": "SHA-1 based MAC, deprecated",
        "hmac-sha1-96": "SHA-1 based MAC, deprecated",
    },
    "host_key": {
        "ssh-dss": "DSA 1024-bit key, considered weak",
        "ssh-rsa": "RSA with SHA-1, deprecated in OpenSSH 8.8+",
    },
}

# OS fingerprinting patterns from SSH banners
OS_FINGERPRINTS = [
    # (pattern, os_name, os_family)
    ("Ubuntu", "Ubuntu Linux", "Linux"),
    ("Debian", "Debian Linux", "Linux"),
    ("FreeBSD", "FreeBSD", "BSD"),
    ("CentOS", "CentOS Linux", "Linux"),
    ("Red Hat", "Red Hat Enterprise Linux", "Linux"),
    ("RHEL", "Red Hat Enterprise Linux", "Linux"),
    ("Fedora", "Fedora Linux", "Linux"),
    ("SUSE", "SUSE Linux", "Linux"),
    ("Raspbian", "Raspbian (Raspberry Pi)", "Linux"),
    ("Arch", "Arch Linux", "Linux"),
    ("Gentoo", "Gentoo Linux", "Linux"),
    ("Alpine", "Alpine Linux", "Linux"),
    ("Amazon", "Amazon Linux", "Linux"),
    ("Windows", "Windows", "Windows"),
    ("Cisco", "Cisco IOS", "Network"),
    ("Dropbear", "Dropbear SSH (Embedded/IoT)", "Embedded"),
    ("libssh", "libssh-based server", "Unknown"),
    ("Bitvise", "Bitvise SSH Server (Windows)", "Windows"),
    ("OpenSSH", "OpenSSH (generic)", "Unix"),
]

# Known honeypot signatures
HONEYPOT_SIGNATURES = {
    "banners": [
        "SSH-2.0-libssh-0.6.0",  # Cowrie default
        "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",  # Common Cowrie
        "SSH-2.0-OpenSSH_5.1p1 Debian-5",  # Kippo default
    ],
    "banner_patterns": [
        r"SSH-2\.0-libssh-0\.[56]\.",  # Older libssh versions used by Cowrie
    ],
    "suspicious_outputs": [
        "root@svr04",  # Default Cowrie hostname
        "root@nas3",   # Default Cowrie hostname
        "root@server",  # Generic honeypot
        "uid=0(root) gid=0(root) groups=0(root)",  # Exact default output
    ],
}

# Common passwords for password strength scoring
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123", "welcome",
    "admin", "root", "toor", "changeme", "default", "test", "guest", "oracle",
    "mysql", "sysadmin", "login", "pass", "p@ssw0rd", "p@ssword", "secret",
    "access", "temp", "abcd1234", "alpine", "raspberry", "ubnt", "vagrant",
}

# Common SSH service ports for service discovery
COMMON_SSH_PORTS = [22, 2222, 2200, 22222, 8022, 830, 222, 2022, 2220, 10022]


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
    host_key_type: str = ""
    host_key_fingerprint: str = ""
    host_key_bits: int = 0
    algorithms: Optional[Dict[str, List[str]]] = None
    weak_algorithms: Optional[Dict[str, List[str]]] = None
    os_info: str = ""
    os_family: str = ""
    ssh_version: str = ""
    severity: str = ""
    severity_reasons: Optional[List[str]] = None
    command_output: str = ""
    honeypot_score: float = 0.0
    honeypot_reasons: Optional[List[str]] = None
    host_key_changed: bool = False
    host_key_previous: str = ""
    password_strength_score: float = 0.0
    password_strength_label: str = ""

    def to_dict(self) -> dict:
        """Convert result to dictionary."""
        d = asdict(self)
        # Ensure None values become empty structures for JSON
        if d['algorithms'] is None:
            d['algorithms'] = {}
        if d['weak_algorithms'] is None:
            d['weak_algorithms'] = {}
        if d['severity_reasons'] is None:
            d['severity_reasons'] = []
        if d['honeypot_reasons'] is None:
            d['honeypot_reasons'] = []
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
    skipped_lockout: int = 0
    skipped_stop_on_success: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def get_duration(self) -> float:
        """Get scan duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


@dataclass
class CheckpointData:
    """Data for resume/checkpoint support."""
    completed_items: List[Tuple[str, int, str, str]]  # (host, port, user, pass)
    results: List[dict]
    stats: dict
    timestamp: str


class SSHAuditClient:
    """SSH Security Audit Client for testing login capabilities."""

    def __init__(
        self,
        timeout: int = 10,
        verbose: bool = False,
        quiet: bool = False,
        threads: int = 1,
        output_file: Optional[str] = None,
        output_format: str = "text",
        try_empty: bool = False,
        user_as_pass: bool = False,
        stop_on_success: bool = False,
        max_attempts_per_user: int = 0,
        command: Optional[str] = None,
        checkpoint_file: Optional[str] = None,
        spray_mode: bool = False,
        exclude_hosts: Optional[List[str]] = None,
        detect_honeypot: bool = False,
        known_hosts_file: Optional[str] = None,
        baseline_file: Optional[str] = None,
        source_ip: Optional[str] = None,
        jitter: float = 0.0,
        score_passwords: bool = False,
        diff_mode: bool = False,
    ):
        self.timeout = timeout
        self.verbose = verbose
        self.quiet = quiet
        self.threads = threads
        self.output_file = output_file
        self.output_format = output_format
        self.try_empty = try_empty
        self.user_as_pass = user_as_pass
        self.stop_on_success = stop_on_success
        self.max_attempts_per_user = max_attempts_per_user
        self.command = command
        self.checkpoint_file = checkpoint_file
        self.spray_mode = spray_mode
        self.exclude_hosts = exclude_hosts or []
        self.detect_honeypot = detect_honeypot
        self.known_hosts_file = known_hosts_file
        self.baseline_file = baseline_file
        self.source_ip = source_ip
        self.jitter = jitter
        self.score_passwords = score_passwords
        self.diff_mode = diff_mode
        self.results: List[ScanResult] = []
        self.stats = ScanStatistics()
        self._setup_logging()

        # Track per-host/user failure counts for lockout protection
        self._failure_counts: Dict[str, int] = {}
        # Track hosts with successful logins for stop-on-success
        self._successful_hosts: Set[str] = set()
        # Known host keys for MITM detection
        self._known_host_keys: Dict[str, Tuple[str, str]] = {}  # host:port -> (type, fingerprint)
        # Load known hosts if provided
        if self.known_hosts_file:
            self._load_known_hosts()
        # Excluded host set (expanded from CIDRs, ranges, etc.)
        self._excluded_set: Set[str] = set()
        if self.exclude_hosts:
            self._build_exclusion_set()

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

    def _build_exclusion_set(self):
        """Build the set of excluded hosts from exclusion list."""
        for host in self.exclude_hosts:
            for expanded in self._parse_targets([host]):
                self._excluded_set.add(expanded)

    def _is_excluded(self, host: str) -> bool:
        """Check if a host is in the exclusion set."""
        return host in self._excluded_set

    def _load_known_hosts(self):
        """
        Load known host keys from a file for MITM detection.

        Supports two formats:
        1. OpenSSH known_hosts format: hostname key-type base64-key
        2. sshcheck JSON format: {"host:port": {"type": "...", "fingerprint": "..."}}
        """
        path = Path(self.known_hosts_file)
        if not path.exists():
            if self.verbose:
                self.logger.warning(f"Known hosts file not found: {self.known_hosts_file}")
            return

        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read().strip()

            # Try JSON format first (sshcheck's own format)
            if content.startswith('{'):
                data = json.loads(content)
                for host_port, info in data.items():
                    self._known_host_keys[host_port] = (
                        info.get('type', ''),
                        info.get('fingerprint', '')
                    )
                return

            # Parse OpenSSH known_hosts format
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('@'):
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    hostnames = parts[0]
                    key_type = parts[1]
                    key_b64 = parts[2]
                    # Compute fingerprint from the base64-encoded key
                    try:
                        key_bytes = base64.b64decode(key_b64)
                        fp = hashlib.sha256(key_bytes).hexdigest()
                        fp_formatted = ':'.join(
                            fp[i:i+2] for i in range(0, len(fp), 2)
                        )
                        fingerprint = f"SHA256:{fp_formatted}"
                    except Exception:
                        fingerprint = ""

                    # Handle multiple hostnames (comma-separated)
                    for hostname in hostnames.split(','):
                        hostname = hostname.strip().strip('[]')
                        # Determine port: [host]:port or just host (default 22)
                        if ':' in hostname and not hostname.startswith('['):
                            # Could be IPv6 or host:port
                            host_key = hostname
                        else:
                            # Default to port 22
                            host_key = f"{hostname}:22"
                        self._known_host_keys[host_key] = (key_type, fingerprint)

        except Exception as e:
            if self.verbose:
                self.logger.warning(f"Failed to load known hosts: {e}")

    def _check_host_key_continuity(self, host: str, port: int,
                                    key_type: str, fingerprint: str) -> Tuple[bool, str]:
        """
        Check if a host key has changed compared to known hosts.

        Returns:
            Tuple of (has_changed, previous_fingerprint)
        """
        host_key = f"{host}:{port}"
        if host_key in self._known_host_keys:
            known_type, known_fp = self._known_host_keys[host_key]
            if known_fp and fingerprint and known_fp != fingerprint:
                return (True, known_fp)
        return (False, "")

    def _save_known_hosts(self, filepath: str):
        """
        Save discovered host keys to a JSON file for future comparison.
        """
        host_keys: Dict[str, Dict[str, str]] = {}
        seen = set()
        for result in self.results:
            host_port = f"{result.host}:{result.port}"
            if host_port not in seen and result.host_key_type and result.host_key_fingerprint:
                host_keys[host_port] = {
                    "type": result.host_key_type,
                    "fingerprint": result.host_key_fingerprint,
                    "bits": result.host_key_bits,
                    "last_seen": result.timestamp,
                }
                seen.add(host_port)

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(host_keys, f, indent=2)
        except Exception as e:
            if self.verbose:
                self.logger.warning(f"Failed to save known hosts: {e}")

    def _detect_honeypot_indicators(self, result: ScanResult) -> Tuple[float, List[str]]:
        """
        Analyze a scan result for honeypot indicators.

        Returns:
            Tuple of (honeypot_score 0.0-1.0, list_of_reasons)
        """
        score = 0.0
        reasons: List[str] = []

        # Check banner against known honeypot signatures
        if result.banner:
            for sig_banner in HONEYPOT_SIGNATURES["banners"]:
                if result.banner == sig_banner:
                    score += 0.4
                    reasons.append(f"Known honeypot banner: {result.banner}")
                    break

            for pattern in HONEYPOT_SIGNATURES["banner_patterns"]:
                if re.search(pattern, result.banner):
                    score += 0.3
                    reasons.append(f"Suspicious banner pattern match")
                    break

        # Check initial output for honeypot signatures
        if result.initial_output:
            for sig_output in HONEYPOT_SIGNATURES["suspicious_outputs"]:
                if sig_output in result.initial_output:
                    score += 0.2
                    reasons.append(f"Known honeypot output pattern: {sig_output}")
                    break

        # Extremely fast connection time is suspicious (< 0.05s on a non-local host)
        if result.connection_time > 0 and result.connection_time < 0.05 and result.success:
            score += 0.1
            reasons.append(f"Suspiciously fast connection ({result.connection_time:.3f}s)")

        # Accepting root with common/empty passwords is a red flag
        if result.success and result.username == "root":
            if result.password in ("", "root", "toor", "password", "123456"):
                score += 0.2
                reasons.append(f"Root login with trivial password '{result.password}'")

        # Cap score at 1.0
        score = min(score, 1.0)

        return (score, reasons)

    @staticmethod
    def score_password_strength(password: str, username: str = "") -> Tuple[float, str]:
        """
        Score the strength of a password on a 0-100 scale.

        Evaluates length, character diversity, common patterns,
        and username similarity.

        Args:
            password: The password to score
            username: Associated username for similarity check

        Returns:
            Tuple of (score 0-100, label string)
        """
        if not password:
            return (0.0, "empty")

        score = 0.0

        # Length scoring (up to 30 points)
        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 8
        else:
            score += 3

        # Character class diversity (up to 25 points)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

        char_classes = sum([has_lower, has_upper, has_digit, has_special])
        score += char_classes * 6.25  # 6.25 per class = 25 max

        # Entropy estimation (up to 25 points)
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32

        if charset_size > 0:
            entropy = length * math.log2(charset_size)
            # 128 bits = perfect, scale to 25 points
            entropy_score = min(entropy / 128.0 * 25, 25)
            score += entropy_score

        # Penalties (up to -30 points)
        penalties = 0

        # Common password check
        if password.lower() in COMMON_PASSWORDS:
            penalties += 25

        # Username similarity
        if username and password.lower() == username.lower():
            penalties += 20
        elif username and username.lower() in password.lower():
            penalties += 10

        # Sequential characters (abc, 123, etc.)
        sequential_count = 0
        for i in range(len(password) - 2):
            if (ord(password[i]) + 1 == ord(password[i+1]) ==
                    ord(password[i+2]) - 1):
                sequential_count += 1
        if sequential_count > 0:
            penalties += min(sequential_count * 5, 15)

        # Repeated characters (aaa, 111)
        repeat_count = 0
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                repeat_count += 1
        if repeat_count > 0:
            penalties += min(repeat_count * 5, 10)

        # All same character class
        if length > 1 and char_classes == 1:
            penalties += 5

        # Common patterns
        common_patterns = [
            r'^[a-zA-Z]+\d+$',      # word + numbers (password123)
            r'^\d+[a-zA-Z]+$',      # numbers + word (123abc)
            r'^(.)\1+$',             # all same character (aaaa)
            r'^(01|12|23|34|45|56|67|78|89|90)+', # sequential digits
        ]
        for pattern in common_patterns:
            if re.match(pattern, password):
                penalties += 5
                break

        score = max(0, score - penalties)
        score = min(100, score)

        # Label assignment
        if score >= 80:
            label = "very_strong"
        elif score >= 60:
            label = "strong"
        elif score >= 40:
            label = "moderate"
        elif score >= 20:
            label = "weak"
        else:
            label = "very_weak"

        return (round(score, 1), label)

    @staticmethod
    def discover_ssh_ports(
        host: str,
        ports: Optional[List[int]] = None,
        timeout: float = 2.0,
        source_ip: Optional[str] = None,
    ) -> List[Tuple[int, str]]:
        """
        Discover SSH services on a host by TCP connect scanning and
        banner grabbing.

        Args:
            host: Target hostname or IP
            ports: List of ports to check (defaults to COMMON_SSH_PORTS)
            timeout: Connection timeout per port
            source_ip: Source IP to bind to (optional)

        Returns:
            List of (port, banner) tuples for ports running SSH
        """
        if ports is None:
            ports = list(COMMON_SSH_PORTS)

        found: List[Tuple[int, str]] = []

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                if source_ip:
                    sock.bind((source_ip, 0))
                result = sock.connect_ex((host, port))
                if result == 0:
                    # Port is open, try to grab SSH banner
                    try:
                        banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
                        if banner.startswith('SSH-'):
                            found.append((port, banner))
                        else:
                            # Port open but not SSH
                            pass
                    except (socket.timeout, Exception):
                        # Port open but couldn't read banner - might still be SSH
                        found.append((port, ""))
                sock.close()
            except Exception:
                pass

        return found

    @staticmethod
    def import_nmap_xml(filepath: str) -> List[str]:
        """
        Import targets from an Nmap XML output file.

        Extracts hosts that have SSH ports open (22, 2222, or any port
        with service name 'ssh').

        Args:
            filepath: Path to the Nmap XML file

        Returns:
            List of "host:port" strings for hosts with SSH open
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Nmap XML file not found: {filepath}")

        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML in Nmap file: {e}")

        targets = []
        for host_elem in root.findall('.//host'):
            # Get host address
            addr_elem = host_elem.find('address')
            if addr_elem is None:
                continue
            host_addr = addr_elem.get('addr', '')

            # Check if host is up
            status_elem = host_elem.find('status')
            if status_elem is not None and status_elem.get('state') != 'up':
                continue

            # Check ports for SSH
            ports_elem = host_elem.find('ports')
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall('port'):
                port_id = port_elem.get('portid', '')
                protocol = port_elem.get('protocol', 'tcp')

                # Skip non-TCP ports
                if protocol != 'tcp':
                    continue

                # Check if port is open
                state_elem = port_elem.find('state')
                if state_elem is None or state_elem.get('state') != 'open':
                    continue

                # Check if service is SSH
                service_elem = port_elem.find('service')
                is_ssh = False
                if service_elem is not None:
                    service_name = service_elem.get('name', '').lower()
                    if 'ssh' in service_name:
                        is_ssh = True

                # Also accept common SSH ports even without service detection
                if port_id in ('22', '2222', '22222', '8022'):
                    is_ssh = True

                if is_ssh and port_id:
                    targets.append(f"{host_addr}:{port_id}")

        return targets

    @staticmethod
    def compare_baseline(current_results: List['ScanResult'],
                         baseline_path: str) -> Dict[str, Any]:
        """
        Compare current scan results against a baseline (previous scan).

        Args:
            current_results: List of current ScanResult objects
            baseline_path: Path to a JSON baseline file (previous scan output)

        Returns:
            Dictionary with comparison results
        """
        path = Path(baseline_path)
        if not path.exists():
            raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

        try:
            with open(path, 'r', encoding='utf-8') as f:
                baseline_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in baseline file: {e}")

        baseline_results = baseline_data.get('results', [])

        # Build lookup sets for comparison
        def _result_key(r):
            """Create a unique key for a result."""
            if isinstance(r, dict):
                return (r.get('host', ''), r.get('port', 0),
                        r.get('username', ''), r.get('password', ''))
            return (r.host, r.port, r.username, r.password)

        def _host_port_key(r):
            if isinstance(r, dict):
                return (r.get('host', ''), r.get('port', 0))
            return (r.host, r.port)

        # Baseline data
        baseline_successes = {
            _result_key(r) for r in baseline_results
            if (isinstance(r, dict) and r.get('success'))
        }
        baseline_hosts = {
            _host_port_key(r) for r in baseline_results
        }
        baseline_host_keys = {}
        for r in baseline_results:
            if isinstance(r, dict):
                hp = _host_port_key(r)
                if r.get('host_key_fingerprint'):
                    baseline_host_keys[hp] = {
                        'type': r.get('host_key_type', ''),
                        'fingerprint': r.get('host_key_fingerprint', ''),
                    }
        baseline_ssh_versions = {}
        for r in baseline_results:
            if isinstance(r, dict):
                hp = _host_port_key(r)
                if r.get('ssh_version'):
                    baseline_ssh_versions[hp] = r.get('ssh_version', '')

        # Current data
        current_successes = {
            _result_key(r) for r in current_results if r.success
        }
        current_hosts = {
            _host_port_key(r) for r in current_results
        }
        current_host_keys = {}
        for r in current_results:
            hp = _host_port_key(r)
            if r.host_key_fingerprint:
                current_host_keys[hp] = {
                    'type': r.host_key_type,
                    'fingerprint': r.host_key_fingerprint,
                }
        current_ssh_versions = {}
        for r in current_results:
            hp = _host_port_key(r)
            if r.ssh_version:
                current_ssh_versions[hp] = r.ssh_version

        # Compute differences
        new_hosts = current_hosts - baseline_hosts
        removed_hosts = baseline_hosts - current_hosts
        new_credentials = current_successes - baseline_successes
        lost_credentials = baseline_successes - current_successes

        # Host key changes
        host_key_changes = []
        for hp in current_host_keys:
            if hp in baseline_host_keys:
                if (current_host_keys[hp]['fingerprint'] !=
                        baseline_host_keys[hp]['fingerprint']):
                    host_key_changes.append({
                        'host': hp[0],
                        'port': hp[1],
                        'previous_type': baseline_host_keys[hp]['type'],
                        'previous_fingerprint': baseline_host_keys[hp]['fingerprint'],
                        'current_type': current_host_keys[hp]['type'],
                        'current_fingerprint': current_host_keys[hp]['fingerprint'],
                    })

        # SSH version changes
        ssh_version_changes = []
        for hp in current_ssh_versions:
            if hp in baseline_ssh_versions:
                if current_ssh_versions[hp] != baseline_ssh_versions[hp]:
                    ssh_version_changes.append({
                        'host': hp[0],
                        'port': hp[1],
                        'previous_version': baseline_ssh_versions[hp],
                        'current_version': current_ssh_versions[hp],
                    })

        diff = {
            'new_hosts': [{'host': h, 'port': p} for h, p in new_hosts],
            'removed_hosts': [{'host': h, 'port': p} for h, p in removed_hosts],
            'new_credentials': [
                {'host': h, 'port': p, 'username': u, 'password': pw}
                for h, p, u, pw in new_credentials
            ],
            'lost_credentials': [
                {'host': h, 'port': p, 'username': u, 'password': pw}
                for h, p, u, pw in lost_credentials
            ],
            'host_key_changes': host_key_changes,
            'ssh_version_changes': ssh_version_changes,
            'summary': {
                'new_hosts_count': len(new_hosts),
                'removed_hosts_count': len(removed_hosts),
                'new_credentials_count': len(new_credentials),
                'lost_credentials_count': len(lost_credentials),
                'host_key_changes_count': len(host_key_changes),
                'ssh_version_changes_count': len(ssh_version_changes),
            }
        }

        return diff

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
            if self.source_ip:
                sock.bind((self.source_ip, 0))
            sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
            sock.close()
            return banner
        except Exception:
            return ""

    def _fingerprint_os(self, banner: str) -> Tuple[str, str, str]:
        """
        Fingerprint OS and SSH version from banner string.

        Args:
            banner: SSH banner string (e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")

        Returns:
            Tuple of (os_info, os_family, ssh_version)
        """
        if not banner:
            return ("", "", "")

        ssh_version = ""
        # Extract SSH software version
        if banner.startswith("SSH-"):
            parts = banner.split("-", 2)
            if len(parts) >= 3:
                ssh_version = parts[2]

        os_info = ""
        os_family = ""
        for pattern, os_name, family in OS_FINGERPRINTS:
            if pattern.lower() in banner.lower():
                os_info = os_name
                os_family = family
                break

        return (os_info, os_family, ssh_version)

    def _get_host_key_info(self, transport: paramiko.Transport) -> Tuple[str, str, int]:
        """
        Extract host key information from a paramiko transport.

        Args:
            transport: Active paramiko Transport

        Returns:
            Tuple of (key_type, fingerprint_sha256, key_bits)
        """
        try:
            key = transport.get_remote_server_key()
            key_type = key.get_name()
            key_bytes = key.asbytes()
            fingerprint = hashlib.sha256(key_bytes).hexdigest()
            # Format as colon-separated pairs
            fp_formatted = ':'.join(
                fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)
            )
            key_bits = key.get_bits()
            return (key_type, f"SHA256:{fp_formatted}", key_bits)
        except Exception:
            return ("", "", 0)

    def _get_algorithms(self, transport: paramiko.Transport) -> Dict[str, List[str]]:
        """
        Extract negotiated and available algorithms from transport.

        Args:
            transport: Active paramiko Transport

        Returns:
            Dictionary with algorithm categories and their values
        """
        algos: Dict[str, List[str]] = {}
        try:
            sec_opts = transport.get_security_options()
            algos['kex'] = list(sec_opts.kex)
            algos['ciphers'] = list(sec_opts.ciphers)
            algos['digests'] = list(sec_opts.digests)
            algos['key_types'] = list(sec_opts.key_types)
        except Exception:
            pass
        return algos

    def _find_weak_algorithms(self, algorithms: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """
        Identify weak algorithms from the available set.

        Args:
            algorithms: Dictionary of algorithm categories

        Returns:
            Dictionary mapping category to list of "algo: reason" strings
        """
        weak: Dict[str, List[str]] = {}

        mapping = {
            'kex': 'kex',
            'ciphers': 'cipher',
            'digests': 'mac',
            'key_types': 'host_key',
        }

        for algo_key, weak_key in mapping.items():
            if algo_key in algorithms:
                found = []
                for algo in algorithms[algo_key]:
                    if algo in WEAK_ALGORITHMS.get(weak_key, {}):
                        reason = WEAK_ALGORITHMS[weak_key][algo]
                        found.append(f"{algo}: {reason}")
                if found:
                    weak[algo_key] = found

        return weak

    def _assess_severity(self, result: ScanResult) -> Tuple[str, List[str]]:
        """
        Assess severity of a finding based on multiple factors.

        Args:
            result: Completed ScanResult

        Returns:
            Tuple of (severity_level, list_of_reasons)
        """
        severity = SeverityLevel.INFO
        reasons: List[str] = []

        if result.success:
            # Successful login is always at least MEDIUM
            if result.username == "root" or result.username == "administrator":
                severity = SeverityLevel.CRITICAL
                reasons.append(f"Root/admin login successful with password '{result.password}'")
            else:
                severity = SeverityLevel.HIGH
                reasons.append(f"Login successful for user '{result.username}'")

            if result.password == "":
                severity = SeverityLevel.CRITICAL
                reasons.append("Empty/null password accepted")
            elif result.password == result.username:
                if severity != SeverityLevel.CRITICAL:
                    severity = SeverityLevel.CRITICAL
                reasons.append("Username used as password")
            elif result.password in ("password", "123456", "admin", "root", "toor",
                                     "changeme", "default", "test", "guest"):
                if severity != SeverityLevel.CRITICAL:
                    severity = SeverityLevel.CRITICAL
                reasons.append(f"Common default password '{result.password}'")

        # Check for weak host key
        if result.host_key_type == "ssh-dss":
            if severity.value < SeverityLevel.MEDIUM.value or severity == SeverityLevel.INFO:
                severity = max(severity, SeverityLevel.MEDIUM, key=lambda s: _severity_rank(s))
            reasons.append("DSA host key (1024-bit, weak)")
        if result.host_key_type == "ssh-rsa" and result.host_key_bits > 0 and result.host_key_bits < 2048:
            severity = max(severity, SeverityLevel.MEDIUM, key=lambda s: _severity_rank(s))
            reasons.append(f"RSA key too short ({result.host_key_bits} bits)")

        # Check SSH version for known vulnerabilities
        if result.ssh_version:
            for ver_prefix, (ver_sev, ver_desc) in VULNERABLE_VERSIONS.items():
                if ver_prefix in result.ssh_version:
                    severity = max(severity, ver_sev, key=lambda s: _severity_rank(s))
                    reasons.append(f"Vulnerable SSH version: {ver_desc}")
                    break

        # Check for weak algorithms
        if result.weak_algorithms:
            weak_count = sum(len(v) for v in result.weak_algorithms.values())
            if weak_count > 0:
                severity = max(severity, SeverityLevel.LOW, key=lambda s: _severity_rank(s))
                reasons.append(f"{weak_count} weak algorithm(s) supported")

        # Check for host key change (possible MITM)
        if result.host_key_changed:
            severity = max(severity, SeverityLevel.CRITICAL, key=lambda s: _severity_rank(s))
            reasons.append(
                f"HOST KEY CHANGED - possible MITM attack! "
                f"Previous: {result.host_key_previous}"
            )

        if not reasons:
            reasons.append("No significant findings")

        return (severity.value, reasons)

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

            # Fingerprint OS from banner
            os_info, os_family, ssh_version = self._fingerprint_os(result.banner)
            result.os_info = os_info
            result.os_family = os_family
            result.ssh_version = ssh_version

            # Attempt connection (with optional source IP binding)
            connect_kwargs = dict(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=self.timeout,
            )
            if self.source_ip:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.bind((self.source_ip, 0))
                sock.connect((host, port))
                connect_kwargs['sock'] = sock

            client.connect(**connect_kwargs)

            result.connection_time = time.time() - start_time
            result.success = True

            # Collect host key and algorithm info from transport
            transport = client.get_transport()
            if transport:
                key_type, fingerprint, key_bits = self._get_host_key_info(transport)
                result.host_key_type = key_type
                result.host_key_fingerprint = fingerprint
                result.host_key_bits = key_bits

                algorithms = self._get_algorithms(transport)
                result.algorithms = algorithms
                result.weak_algorithms = self._find_weak_algorithms(algorithms)

            # Execute command if specified
            if self.command:
                try:
                    stdin, stdout, stderr = client.exec_command(
                        self.command, timeout=self.timeout
                    )
                    result.command_output = stdout.read().decode(
                        'utf-8', errors='replace'
                    )
                    err_output = stderr.read().decode('utf-8', errors='replace')
                    if err_output:
                        result.command_output += f"\n[stderr]: {err_output}"
                except Exception as e:
                    result.command_output = f"[exec error]: {e}"

            # Try to get initial shell output (only if no command was run)
            if not self.command:
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
            self._successful_hosts.add(f"{host}:{port}")

        except paramiko.AuthenticationException as e:
            result.error_message = f"Authentication failed: {str(e)}"
            self.stats.authentication_errors += 1
            self.stats.failed_logins += 1

            # Track failures for lockout protection
            key = f"{host}:{port}:{username}"
            self._failure_counts[key] = self._failure_counts.get(key, 0) + 1

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

        # Check host key continuity
        if self._known_host_keys and result.host_key_fingerprint:
            changed, prev_fp = self._check_host_key_continuity(
                result.host, result.port,
                result.host_key_type, result.host_key_fingerprint
            )
            if changed:
                result.host_key_changed = True
                result.host_key_previous = prev_fp

        # Assess severity
        severity, reasons = self._assess_severity(result)
        result.severity = severity
        result.severity_reasons = reasons

        # Honeypot detection
        if self.detect_honeypot:
            hp_score, hp_reasons = self._detect_honeypot_indicators(result)
            result.honeypot_score = hp_score
            result.honeypot_reasons = hp_reasons

        # Password strength scoring on successful logins
        if self.score_passwords and result.success:
            pw_score, pw_label = self.score_password_strength(
                result.password, result.username
            )
            result.password_strength_score = pw_score
            result.password_strength_label = pw_label

        return result

    def _should_skip(self, host: str, port: int, username: str) -> Optional[str]:
        """
        Check if this attempt should be skipped.

        Returns:
            Reason string if should skip, None if should proceed.
        """
        # Stop-on-success: skip if this host:port already had a successful login
        if self.stop_on_success and f"{host}:{port}" in self._successful_hosts:
            return "stop_on_success"

        # Lockout protection: skip if max attempts reached for this user on this host
        if self.max_attempts_per_user > 0:
            key = f"{host}:{port}:{username}"
            if self._failure_counts.get(key, 0) >= self.max_attempts_per_user:
                return "lockout_protection"

        return None

    def _print_progress(self, result: ScanResult, current: int, total: int):
        """
        Print scan progress to stdout.

        Args:
            result: The scan result to display
            current: Current attempt number
            total: Total number of attempts
        """
        if self.quiet:
            return

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

        if result.success:
            if result.severity:
                sev_colors = {
                    "critical": "\033[91m",
                    "high": "\033[91m",
                    "medium": "\033[93m",
                    "low": "\033[94m",
                    "info": "\033[90m",
                }
                sc = sev_colors.get(result.severity, "")
                print(f"    Severity: {sc}{result.severity.upper()}{color_end}")

            if result.initial_output:
                first_line = result.initial_output.split('\n')[0][:60]
                if first_line:
                    print(f"    Output: {first_line}...")

            if result.command_output:
                first_line = result.command_output.split('\n')[0][:60]
                if first_line:
                    print(f"    Command: {first_line}...")

            if result.host_key_fingerprint:
                print(f"    Host Key: {result.host_key_type} ({result.host_key_fingerprint})")

            if result.host_key_changed:
                print(f"    \033[91m!!! HOST KEY CHANGED - possible MITM !!!\033[0m")
                print(f"    Previous: {result.host_key_previous}")

            if result.honeypot_score >= 0.5:
                print(f"    \033[93m⚠ Possible honeypot (score: {result.honeypot_score:.1f})\033[0m")
                for hr in (result.honeypot_reasons or []):
                    print(f"      - {hr}")

            if result.password_strength_label:
                strength_colors = {
                    "very_weak": "\033[91m",
                    "weak": "\033[91m",
                    "moderate": "\033[93m",
                    "strong": "\033[92m",
                    "very_strong": "\033[92m",
                }
                sc = strength_colors.get(result.password_strength_label, "")
                print(
                    f"    Password Strength: {sc}"
                    f"{result.password_strength_label.upper()} "
                    f"({result.password_strength_score:.0f}/100){color_end}"
                )

        if self.verbose and result.error_message:
            print(f"    Error: {result.error_message}")

    def _build_password_list(self, passwords: List[str], username: str) -> List[str]:
        """Build the effective password list for a given username."""
        pw_list = list(passwords)
        if self.try_empty and "" not in pw_list:
            pw_list.insert(0, "")
        if self.user_as_pass and username not in pw_list:
            pw_list.insert(0, username)
        return pw_list

    def _save_checkpoint(self, completed_items: List[Tuple[str, int, str, str]]):
        """Save checkpoint data for resume support."""
        if not self.checkpoint_file:
            return
        try:
            data = {
                "version": __version__,
                "timestamp": datetime.now().isoformat(),
                "completed": [list(item) for item in completed_items],
                "results": [r.to_dict() for r in self.results],
                "stats": {
                    "total_attempts": self.stats.total_attempts,
                    "successful_logins": self.stats.successful_logins,
                    "failed_logins": self.stats.failed_logins,
                    "connection_errors": self.stats.connection_errors,
                    "timeout_errors": self.stats.timeout_errors,
                    "authentication_errors": self.stats.authentication_errors,
                    "skipped_lockout": self.stats.skipped_lockout,
                    "skipped_stop_on_success": self.stats.skipped_stop_on_success,
                }
            }
            with open(self.checkpoint_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False)
        except Exception as e:
            if self.verbose:
                self.logger.warning(f"Failed to save checkpoint: {e}")

    def _load_checkpoint(self) -> Optional[Dict]:
        """Load checkpoint data for resume."""
        if not self.checkpoint_file:
            return None
        path = Path(self.checkpoint_file)
        if not path.exists():
            return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            if self.verbose:
                self.logger.warning(f"Failed to load checkpoint: {e}")
            return None

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
        self._failure_counts = {}
        self._successful_hosts = set()

        # Build list of all hosts, applying exclusions
        hosts = []
        for h in set(self._parse_targets(targets)):
            if self._is_excluded(h):
                if not self.quiet:
                    self.logger.debug(f"Excluding host: {h}")
                continue
            hosts.append(h)

        if not hosts:
            print("ERROR: No valid target hosts specified.", file=sys.stderr)
            print("Please provide valid IP addresses, hostnames, or CIDR ranges.", file=sys.stderr)
            return []

        if not usernames:
            print("ERROR: No usernames specified.", file=sys.stderr)
            print("Please provide at least one username using -u or -U options.", file=sys.stderr)
            return []

        if not passwords and not self.try_empty and not self.user_as_pass:
            print("ERROR: No passwords specified.", file=sys.stderr)
            print("Please provide at least one password using -p or -P options.", file=sys.stderr)
            return []

        if not ports:
            ports = [22]

        # Build work items - order depends on spray mode
        work_items = []
        if self.spray_mode:
            # Spray mode: try one password across all users/hosts before next password
            # Build the unique password set across all users
            all_pw_sets = {}
            for username in usernames:
                all_pw_sets[username] = self._build_password_list(passwords, username)

            # Find the maximum password list length
            max_pw_len = max(len(v) for v in all_pw_sets.values()) if all_pw_sets else 0

            for pw_idx in range(max_pw_len):
                for host in hosts:
                    for port in ports:
                        for username in usernames:
                            pw_list = all_pw_sets[username]
                            if pw_idx < len(pw_list):
                                work_items.append((host, port, username, pw_list[pw_idx]))
        else:
            # Normal mode: try all passwords per user per host
            for host in hosts:
                for port in ports:
                    for username in usernames:
                        pw_list = self._build_password_list(passwords, username)
                        for password in pw_list:
                            work_items.append((host, port, username, password))

        total = len(work_items)

        # Load checkpoint if resuming
        completed_set: Set[Tuple[str, int, str, str]] = set()
        checkpoint = self._load_checkpoint()
        if checkpoint:
            for item in checkpoint.get("completed", []):
                completed_set.add((str(item[0]), int(item[1]), str(item[2]), str(item[3])))
            # Restore previous results
            for r_dict in checkpoint.get("results", []):
                self.results.append(ScanResult(**{
                    k: v for k, v in r_dict.items()
                    if k in ScanResult.__dataclass_fields__
                }))
            # Restore stats
            prev_stats = checkpoint.get("stats", {})
            self.stats.total_attempts = prev_stats.get("total_attempts", 0)
            self.stats.successful_logins = prev_stats.get("successful_logins", 0)
            self.stats.failed_logins = prev_stats.get("failed_logins", 0)
            self.stats.connection_errors = prev_stats.get("connection_errors", 0)
            self.stats.timeout_errors = prev_stats.get("timeout_errors", 0)
            self.stats.authentication_errors = prev_stats.get("authentication_errors", 0)
            self.stats.skipped_lockout = prev_stats.get("skipped_lockout", 0)
            self.stats.skipped_stop_on_success = prev_stats.get("skipped_stop_on_success", 0)
            # Rebuild successful hosts set from previous results
            for r in self.results:
                if r.success:
                    self._successful_hosts.add(f"{r.host}:{r.port}")
            if not self.quiet:
                print(f"Resuming from checkpoint: {len(completed_set)} attempts already completed")

        if not self.quiet:
            print(f"\n{'='*60}")
            print(f"SSH Security Audit - {__program_name__} v{__version__}")
            print(f"{'='*60}")
            print(f"Targets: {len(hosts)} host(s)")
            print(f"Usernames: {len(usernames)}")
            print(f"Passwords: {len(passwords)}"
                  f"{' (+empty)' if self.try_empty else ''}"
                  f"{' (+user-as-pass)' if self.user_as_pass else ''}")
            print(f"Ports: {ports}")
            print(f"Total combinations: {total}")
            print(f"Threads: {self.threads}")
            print(f"Timeout: {self.timeout}s")
            if self.stop_on_success:
                print(f"Stop on success: enabled")
            if self.max_attempts_per_user > 0:
                print(f"Max attempts per user: {self.max_attempts_per_user}")
            if self.command:
                print(f"Post-auth command: {self.command}")
            if self.spray_mode:
                print(f"Spray mode: enabled (one password per round)")
            if self._excluded_set:
                print(f"Excluded hosts: {len(self._excluded_set)}")
            if self.detect_honeypot:
                print(f"Honeypot detection: enabled")
            if self._known_host_keys:
                print(f"Known hosts loaded: {len(self._known_host_keys)}")
            if self.baseline_file:
                print(f"Baseline comparison: {self.baseline_file}")
            if self.source_ip:
                print(f"Source IP: {self.source_ip}")
            if self.jitter > 0:
                print(f"Jitter: 0-{self.jitter:.1f}s random delay")
            if self.score_passwords:
                print(f"Password scoring: enabled")
            if self.diff_mode and self.baseline_file:
                print(f"Delta/diff mode: enabled")
            print(f"{'='*60}\n")

        completed_items = list(completed_set)
        current = len(completed_set)

        if self.threads > 1:
            # Multi-threaded execution
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {}
                submit_count = 0
                for h, p, u, pw in work_items:
                    if (h, p, u, pw) in completed_set:
                        continue
                    skip_reason = self._should_skip(h, p, u)
                    if skip_reason:
                        current += 1
                        if skip_reason == "stop_on_success":
                            self.stats.skipped_stop_on_success += 1
                        elif skip_reason == "lockout_protection":
                            self.stats.skipped_lockout += 1
                        continue
                    # Apply jitter delay between task submissions
                    if self.jitter > 0 and submit_count > 0:
                        jitter_delay = random.uniform(0, self.jitter)
                        time.sleep(jitter_delay)
                    future = executor.submit(self._try_login, h, p, u, pw)
                    futures[future] = (h, p, u, pw)
                    submit_count += 1

                for future in as_completed(futures):
                    current += 1
                    try:
                        result = future.result()
                        self.results.append(result)
                        item = futures[future]
                        completed_items.append(item)
                        self._print_progress(result, current, total)
                        # Save checkpoint periodically
                        if self.checkpoint_file and current % 50 == 0:
                            self._save_checkpoint(completed_items)
                    except Exception as e:
                        h, p, u, pw = futures[future]
                        print(f"ERROR: Unexpected exception for {h}:{p}: {e}", file=sys.stderr)
        else:
            # Single-threaded execution
            for host, port, username, password in work_items:
                if (host, port, username, password) in completed_set:
                    continue

                skip_reason = self._should_skip(host, port, username)
                if skip_reason:
                    current += 1
                    if skip_reason == "stop_on_success":
                        self.stats.skipped_stop_on_success += 1
                    elif skip_reason == "lockout_protection":
                        self.stats.skipped_lockout += 1
                    continue

                # Apply jitter delay between attempts
                if self.jitter > 0 and current > len(completed_set):
                    jitter_delay = random.uniform(0, self.jitter)
                    time.sleep(jitter_delay)

                current += 1
                result = self._try_login(host, port, username, password)
                self.results.append(result)
                completed_items.append((host, port, username, password))
                self._print_progress(result, current, total)

                # Save checkpoint periodically
                if self.checkpoint_file and current % 50 == 0:
                    self._save_checkpoint(completed_items)

        self.stats.end_time = datetime.now()

        # Final checkpoint save
        if self.checkpoint_file:
            self._save_checkpoint(completed_items)

        # Print summary
        self._print_summary()

        # Save results if output file specified
        if self.output_file:
            self._save_results()

        # Save discovered host keys for future comparison
        if self.known_hosts_file:
            self._save_known_hosts(self.known_hosts_file)

        # Baseline comparison
        if self.baseline_file:
            try:
                diff = self.compare_baseline(self.results, self.baseline_file)
                self._print_baseline_diff(diff)
                # Save diff output
                if self.output_file:
                    if self.diff_mode:
                        # In diff mode, the main output IS the diff
                        diff_path = Path(self.output_file)
                        self._save_diff_output(diff, diff_path)
                        if not self.quiet:
                            print(f"Differential output saved to: {self.output_file}")
                    else:
                        # Save diff alongside regular output
                        diff_path = str(Path(self.output_file).with_suffix('.diff.json'))
                        with open(diff_path, 'w', encoding='utf-8') as f:
                            json.dump(diff, f, indent=2)
                        if not self.quiet:
                            print(f"Baseline diff saved to: {diff_path}")
            except (FileNotFoundError, ValueError) as e:
                print(f"WARNING: Baseline comparison failed: {e}", file=sys.stderr)

        return self.results

    def _print_summary(self):
        """Print scan summary statistics."""
        if self.quiet:
            # In quiet mode, only show successful logins
            successful = [r for r in self.results if r.success]
            if successful:
                for r in successful:
                    print(f"{r.host}:{r.port} {r.username}:{r.password}")
            return

        print(f"\n{'='*60}")
        print("SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Total attempts:        {self.stats.total_attempts}")
        print(f"Successful logins:     {self.stats.successful_logins}")
        print(f"Failed logins:         {self.stats.failed_logins}")
        print(f"  - Auth failures:     {self.stats.authentication_errors}")
        print(f"  - Connection errors: {self.stats.connection_errors}")
        print(f"  - Timeouts:          {self.stats.timeout_errors}")
        if self.stats.skipped_lockout > 0:
            print(f"Skipped (lockout):     {self.stats.skipped_lockout}")
        if self.stats.skipped_stop_on_success > 0:
            print(f"Skipped (success):     {self.stats.skipped_stop_on_success}")
        print(f"Duration:              {self.stats.get_duration():.2f} seconds")
        print(f"{'='*60}")

        # List successful logins
        successful = [r for r in self.results if r.success]
        if successful:
            print("\nSUCCESSFUL LOGINS:")
            print("-" * 40)
            for r in successful:
                sev_tag = f" [{r.severity.upper()}]" if r.severity else ""
                print(f"  {r.host}:{r.port} - {r.username}:{r.password}{sev_tag}")
                if r.banner:
                    print(f"    Banner: {r.banner}")
                if r.os_info:
                    print(f"    OS: {r.os_info}")
                if r.host_key_type:
                    print(f"    Host Key: {r.host_key_type} {r.host_key_fingerprint}")
                if r.command_output:
                    output_preview = r.command_output[:200].replace('\n', ' ')
                    print(f"    Command Output: {output_preview}")
                elif r.initial_output:
                    output_preview = r.initial_output[:200].replace('\n', ' ')
                    print(f"    Output: {output_preview}...")
                if r.severity_reasons:
                    for reason in r.severity_reasons:
                        print(f"    ! {reason}")
                if r.host_key_changed:
                    print(f"    \033[91m!!! HOST KEY CHANGED !!!\033[0m")
                if r.honeypot_score >= 0.5:
                    print(f"    ⚠ Honeypot score: {r.honeypot_score:.1f}")
                if r.password_strength_label:
                    print(f"    Password Strength: {r.password_strength_label.upper()} ({r.password_strength_score:.0f}/100)")
            print()

    def _print_baseline_diff(self, diff: Dict[str, Any]):
        """Print baseline comparison results."""
        if self.quiet:
            return

        summary = diff.get('summary', {})
        total_changes = sum(summary.values())

        if total_changes == 0:
            print("\nBASELINE COMPARISON: No changes detected.")
            return

        print(f"\n{'='*60}")
        print("BASELINE COMPARISON")
        print(f"{'='*60}")

        if diff['new_hosts']:
            print(f"\n  NEW HOSTS ({len(diff['new_hosts'])}):")
            for h in diff['new_hosts']:
                print(f"    + {h['host']}:{h['port']}")

        if diff['removed_hosts']:
            print(f"\n  REMOVED HOSTS ({len(diff['removed_hosts'])}):")
            for h in diff['removed_hosts']:
                print(f"    - {h['host']}:{h['port']}")

        if diff['new_credentials']:
            print(f"\n  NEW CREDENTIALS ({len(diff['new_credentials'])}):")
            for c in diff['new_credentials']:
                print(f"    + {c['host']}:{c['port']} {c['username']}:{c['password']}")

        if diff['lost_credentials']:
            print(f"\n  LOST CREDENTIALS ({len(diff['lost_credentials'])}):")
            for c in diff['lost_credentials']:
                print(f"    - {c['host']}:{c['port']} {c['username']}:{c['password']}")

        if diff['host_key_changes']:
            print(f"\n  \033[91mHOST KEY CHANGES ({len(diff['host_key_changes'])}):\033[0m")
            for hk in diff['host_key_changes']:
                print(f"    ! {hk['host']}:{hk['port']}")
                print(f"      Previous: {hk['previous_type']} {hk['previous_fingerprint']}")
                print(f"      Current:  {hk['current_type']} {hk['current_fingerprint']}")

        if diff['ssh_version_changes']:
            print(f"\n  SSH VERSION CHANGES ({len(diff['ssh_version_changes'])}):")
            for sv in diff['ssh_version_changes']:
                print(f"    ~ {sv['host']}:{sv['port']}")
                print(f"      Previous: {sv['previous_version']}")
                print(f"      Current:  {sv['current_version']}")

        print(f"{'='*60}")

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
            elif self.output_format == "xml":
                self._save_xml(path)
            elif self.output_format == "html":
                self._save_html(path)
            elif self.output_format == "pdf":
                self._save_pdf(path)
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

    def _build_output_data(self) -> dict:
        """Build the common output data structure."""
        return {
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
                "timeout_errors": self.stats.timeout_errors,
                "skipped_lockout": self.stats.skipped_lockout,
                "skipped_stop_on_success": self.stats.skipped_stop_on_success,
            },
            "results": [r.to_dict() for r in self.results]
        }

    def _save_json(self, path: Path):
        """Save results in JSON format."""
        data = self._build_output_data()
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _save_csv(self, path: Path):
        """Save results in CSV format."""
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'host', 'port', 'username', 'password', 'success',
                'timestamp', 'banner', 'initial_output', 'error_message',
                'connection_time', 'host_key_type', 'host_key_fingerprint',
                'host_key_bits', 'os_info', 'os_family', 'ssh_version',
                'severity', 'severity_reasons', 'command_output',
                'honeypot_score', 'honeypot_reasons',
                'host_key_changed', 'host_key_previous',
                'password_strength_score', 'password_strength_label'
            ])
            for r in self.results:
                writer.writerow([
                    r.host, r.port, r.username, r.password, r.success,
                    r.timestamp, r.banner, r.initial_output, r.error_message,
                    r.connection_time, r.host_key_type, r.host_key_fingerprint,
                    r.host_key_bits, r.os_info, r.os_family, r.ssh_version,
                    r.severity,
                    '; '.join(r.severity_reasons) if r.severity_reasons else '',
                    r.command_output,
                    r.honeypot_score,
                    '; '.join(r.honeypot_reasons) if r.honeypot_reasons else '',
                    r.host_key_changed, r.host_key_previous,
                    r.password_strength_score, r.password_strength_label
                ])

    def _save_xml(self, path: Path):
        """Save results in XML format."""
        root = ET.Element("sshcheck_scan")
        root.set("version", __version__)

        # Scan info
        info_elem = ET.SubElement(root, "scan_info")
        ET.SubElement(info_elem, "program").text = __program_name__
        ET.SubElement(info_elem, "version").text = __version__
        ET.SubElement(info_elem, "start_time").text = (
            self.stats.start_time.isoformat() if self.stats.start_time else ""
        )
        ET.SubElement(info_elem, "end_time").text = (
            self.stats.end_time.isoformat() if self.stats.end_time else ""
        )
        ET.SubElement(info_elem, "duration_seconds").text = str(self.stats.get_duration())

        # Statistics
        stats_elem = ET.SubElement(root, "statistics")
        ET.SubElement(stats_elem, "total_attempts").text = str(self.stats.total_attempts)
        ET.SubElement(stats_elem, "successful_logins").text = str(self.stats.successful_logins)
        ET.SubElement(stats_elem, "failed_logins").text = str(self.stats.failed_logins)
        ET.SubElement(stats_elem, "authentication_errors").text = str(self.stats.authentication_errors)
        ET.SubElement(stats_elem, "connection_errors").text = str(self.stats.connection_errors)
        ET.SubElement(stats_elem, "timeout_errors").text = str(self.stats.timeout_errors)

        # Results
        results_elem = ET.SubElement(root, "results")
        for r in self.results:
            result_elem = ET.SubElement(results_elem, "result")
            ET.SubElement(result_elem, "host").text = r.host
            ET.SubElement(result_elem, "port").text = str(r.port)
            ET.SubElement(result_elem, "username").text = r.username
            ET.SubElement(result_elem, "password").text = r.password
            ET.SubElement(result_elem, "success").text = str(r.success).lower()
            ET.SubElement(result_elem, "timestamp").text = r.timestamp
            ET.SubElement(result_elem, "banner").text = r.banner or ""
            ET.SubElement(result_elem, "initial_output").text = r.initial_output or ""
            ET.SubElement(result_elem, "error_message").text = r.error_message or ""
            ET.SubElement(result_elem, "connection_time").text = str(r.connection_time)
            ET.SubElement(result_elem, "host_key_type").text = r.host_key_type or ""
            ET.SubElement(result_elem, "host_key_fingerprint").text = r.host_key_fingerprint or ""
            ET.SubElement(result_elem, "host_key_bits").text = str(r.host_key_bits)
            ET.SubElement(result_elem, "os_info").text = r.os_info or ""
            ET.SubElement(result_elem, "os_family").text = r.os_family or ""
            ET.SubElement(result_elem, "ssh_version").text = r.ssh_version or ""
            ET.SubElement(result_elem, "severity").text = r.severity or ""
            ET.SubElement(result_elem, "command_output").text = r.command_output or ""
            ET.SubElement(result_elem, "honeypot_score").text = str(r.honeypot_score)
            ET.SubElement(result_elem, "host_key_changed").text = str(r.host_key_changed).lower()
            ET.SubElement(result_elem, "host_key_previous").text = r.host_key_previous or ""
            ET.SubElement(result_elem, "password_strength_score").text = str(r.password_strength_score)
            ET.SubElement(result_elem, "password_strength_label").text = r.password_strength_label or ""

            if r.honeypot_reasons:
                hp_reasons_elem = ET.SubElement(result_elem, "honeypot_reasons")
                for reason in r.honeypot_reasons:
                    ET.SubElement(hp_reasons_elem, "reason").text = reason

            if r.severity_reasons:
                reasons_elem = ET.SubElement(result_elem, "severity_reasons")
                for reason in r.severity_reasons:
                    ET.SubElement(reasons_elem, "reason").text = reason

            if r.algorithms:
                algos_elem = ET.SubElement(result_elem, "algorithms")
                for cat, alg_list in r.algorithms.items():
                    cat_elem = ET.SubElement(algos_elem, cat)
                    for alg in alg_list:
                        ET.SubElement(cat_elem, "algorithm").text = alg

            if r.weak_algorithms:
                weak_elem = ET.SubElement(result_elem, "weak_algorithms")
                for cat, alg_list in r.weak_algorithms.items():
                    cat_elem = ET.SubElement(weak_elem, cat)
                    for alg in alg_list:
                        ET.SubElement(cat_elem, "algorithm").text = alg

        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        tree.write(path, encoding="unicode", xml_declaration=True)

    def _save_html(self, path: Path):
        """Save results in HTML format."""
        e = html_escape
        successful = [r for r in self.results if r.success]

        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d",
        }

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SSH Security Audit Report - {e(__program_name__)} v{e(__version__)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       margin: 0; padding: 20px; background: #f5f5f5; color: #333; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
h2 {{ color: #2c3e50; margin-top: 30px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 15px; margin: 20px 0; }}
.stat-card {{ background: white; padding: 15px; border-radius: 8px;
              box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
.stat-card .number {{ font-size: 2em; font-weight: bold; }}
.stat-card .label {{ color: #666; font-size: 0.9em; }}
.success .number {{ color: #28a745; }}
.failure .number {{ color: #dc3545; }}
table {{ width: 100%; border-collapse: collapse; background: white;
         box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-radius: 8px;
         overflow: hidden; margin: 15px 0; }}
th {{ background: #2c3e50; color: white; padding: 12px 15px; text-align: left; }}
td {{ padding: 10px 15px; border-bottom: 1px solid #eee; }}
tr:hover {{ background: #f8f9fa; }}
.severity {{ padding: 3px 8px; border-radius: 4px; color: white;
             font-weight: bold; font-size: 0.85em; text-transform: uppercase; }}
.tag {{ display: inline-block; background: #e9ecef; padding: 2px 8px;
        border-radius: 4px; font-size: 0.85em; margin: 2px; }}
.footer {{ text-align: center; color: #666; margin-top: 40px; padding: 20px;
           border-top: 1px solid #ddd; }}
pre {{ background: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto;
       font-size: 0.85em; }}
</style>
</head>
<body>
<div class="container">
<h1>SSH Security Audit Report</h1>
<p>Generated by {e(__program_name__)} v{e(__version__)} on \
{e(self.stats.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.stats.start_time else 'N/A')}</p>

<div class="stats">
  <div class="stat-card"><div class="number">{self.stats.total_attempts}</div>
    <div class="label">Total Attempts</div></div>
  <div class="stat-card success"><div class="number">{self.stats.successful_logins}</div>
    <div class="label">Successful Logins</div></div>
  <div class="stat-card failure"><div class="number">{self.stats.failed_logins}</div>
    <div class="label">Failed Logins</div></div>
  <div class="stat-card"><div class="number">{self.stats.get_duration():.1f}s</div>
    <div class="label">Duration</div></div>
</div>
"""

        if successful:
            html += "<h2>Successful Logins</h2>\n<table>\n"
            html += ("<tr><th>Host</th><th>Port</th><th>Username</th><th>Password</th>"
                     "<th>Severity</th><th>Banner / OS</th><th>Host Key</th></tr>\n")
            for r in successful:
                sev_color = severity_colors.get(r.severity, "#6c757d")
                os_text = f"{e(r.os_info)}" if r.os_info else ""
                banner_text = f"<code>{e(r.banner)}</code>" if r.banner else ""
                combined = f"{os_text}<br>{banner_text}" if os_text and banner_text else os_text or banner_text
                hk = f"<code>{e(r.host_key_type)}</code><br><small>{e(r.host_key_fingerprint)}</small>" if r.host_key_type else ""
                html += (f"<tr><td>{e(r.host)}</td><td>{r.port}</td>"
                         f"<td>{e(r.username)}</td><td>{e(r.password)}</td>"
                         f"<td><span class='severity' style='background:{sev_color}'>"
                         f"{e(r.severity)}</span></td>"
                         f"<td>{combined}</td><td>{hk}</td></tr>\n")

                if r.severity_reasons:
                    reasons_html = "".join(f"<span class='tag'>{e(reason)}</span> " for reason in r.severity_reasons)
                    html += f"<tr><td colspan='7'>{reasons_html}</td></tr>\n"

                if r.host_key_changed:
                    html += (f"<tr><td colspan='7' style='color:#dc3545;font-weight:bold'>"
                             f"⚠ HOST KEY CHANGED - possible MITM attack! "
                             f"Previous: {e(r.host_key_previous)}</td></tr>\n")

                if r.honeypot_score >= 0.5:
                    hp_detail = ', '.join(e(hr) for hr in (r.honeypot_reasons or []))
                    html += (f"<tr><td colspan='7' style='color:#fd7e14'>"
                             f"⚠ Possible honeypot (score: {r.honeypot_score:.1f}) — {hp_detail}"
                             f"</td></tr>\n")

                if r.password_strength_label:
                    pw_colors = {
                        "very_weak": "#dc3545", "weak": "#dc3545",
                        "moderate": "#ffc107", "strong": "#28a745",
                        "very_strong": "#28a745",
                    }
                    pw_color = pw_colors.get(r.password_strength_label, "#6c757d")
                    html += (f"<tr><td colspan='7'>Password Strength: "
                             f"<span style='color:{pw_color};font-weight:bold'>"
                             f"{e(r.password_strength_label.upper())}</span> "
                             f"({r.password_strength_score:.0f}/100)</td></tr>\n")

                if r.command_output:
                    html += f"<tr><td colspan='7'><strong>Command Output:</strong><pre>{e(r.command_output[:500])}</pre></td></tr>\n"
                elif r.initial_output:
                    html += f"<tr><td colspan='7'><strong>Shell Output:</strong><pre>{e(r.initial_output[:500])}</pre></td></tr>\n"

            html += "</table>\n"

        # All results table
        html += "<h2>All Results</h2>\n<table>\n"
        html += ("<tr><th>Host</th><th>Port</th><th>Username</th>"
                 "<th>Status</th><th>Severity</th><th>Details</th></tr>\n")
        for r in self.results:
            status = "SUCCESS" if r.success else "FAILED"
            status_color = "#28a745" if r.success else "#dc3545"
            sev_color = severity_colors.get(r.severity, "#6c757d")
            detail = e(r.error_message[:80]) if r.error_message else (e(r.banner[:80]) if r.banner else "")
            html += (f"<tr><td>{e(r.host)}</td><td>{r.port}</td>"
                     f"<td>{e(r.username)}</td>"
                     f"<td style='color:{status_color};font-weight:bold'>{status}</td>"
                     f"<td><span class='severity' style='background:{sev_color}'>"
                     f"{e(r.severity)}</span></td>"
                     f"<td>{detail}</td></tr>\n")
        html += "</table>\n"

        html += f"""
<div class="footer">
  <p>Generated by {e(__program_name__)} v{e(__version__)}</p>
  <p>Duration: {self.stats.get_duration():.2f} seconds</p>
</div>
</div>
</body>
</html>"""

        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)

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
            if self.stats.skipped_lockout > 0:
                f.write(f"  Skipped (lockout): {self.stats.skipped_lockout}\n")
            if self.stats.skipped_stop_on_success > 0:
                f.write(f"  Skipped (success): {self.stats.skipped_stop_on_success}\n")
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
                    f.write(f"Severity: {r.severity.upper() if r.severity else 'N/A'}\n")
                    f.write(f"Timestamp: {r.timestamp}\n")
                    if r.banner:
                        f.write(f"Banner: {r.banner}\n")
                    if r.os_info:
                        f.write(f"OS: {r.os_info} ({r.os_family})\n")
                    if r.ssh_version:
                        f.write(f"SSH Version: {r.ssh_version}\n")
                    if r.host_key_type:
                        f.write(f"Host Key: {r.host_key_type} ({r.host_key_bits} bits)\n")
                        f.write(f"Fingerprint: {r.host_key_fingerprint}\n")
                    if r.severity_reasons:
                        f.write(f"Findings:\n")
                        for reason in r.severity_reasons:
                            f.write(f"  - {reason}\n")
                    if r.host_key_changed:
                        f.write(f"!!! HOST KEY CHANGED - possible MITM attack !!!\n")
                        f.write(f"Previous fingerprint: {r.host_key_previous}\n")
                    if r.honeypot_score >= 0.5:
                        f.write(f"Honeypot score: {r.honeypot_score:.1f}\n")
                        for hr in (r.honeypot_reasons or []):
                            f.write(f"  - {hr}\n")
                    if r.password_strength_label:
                        f.write(f"Password Strength: {r.password_strength_label.upper()} ({r.password_strength_score:.0f}/100)\n")
                    if r.command_output:
                        f.write(f"Command Output:\n{r.command_output}\n")
                    elif r.initial_output:
                        f.write(f"Initial Output:\n{r.initial_output}\n")
                    f.write(f"{'-'*40}\n\n")
            else:
                f.write("No successful logins.\n\n")

            f.write(f"{'='*60}\n")
            f.write("ALL RESULTS\n")
            f.write(f"{'='*60}\n\n")

            for r in self.results:
                status = "SUCCESS" if r.success else "FAILED"
                sev = f" [{r.severity.upper()}]" if r.severity else ""
                f.write(f"[{status}]{sev} {r.host}:{r.port} {r.username}\n")
                if r.error_message:
                    f.write(f"  Error: {r.error_message}\n")

    def _save_pdf(self, path: Path):
        """
        Save results as a PDF report.

        Uses a pure-Python PDF generation approach that does not
        require external libraries like reportlab or fpdf.
        Generates a minimal but complete PDF 1.4 file.
        """
        successful = [r for r in self.results if r.success]
        severity_display = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO",
        }

        # Build PDF content lines
        lines = []
        lines.append(f"SSH Security Audit Report")
        lines.append(f"Generated by {__program_name__} v{__version__}")
        lines.append(f"Date: {self.stats.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.stats.start_time else 'N/A'}")
        lines.append("")
        lines.append("=" * 60)
        lines.append("SCAN STATISTICS")
        lines.append("=" * 60)
        lines.append(f"Total attempts:        {self.stats.total_attempts}")
        lines.append(f"Successful logins:     {self.stats.successful_logins}")
        lines.append(f"Failed logins:         {self.stats.failed_logins}")
        lines.append(f"  - Auth failures:     {self.stats.authentication_errors}")
        lines.append(f"  - Connection errors: {self.stats.connection_errors}")
        lines.append(f"  - Timeouts:          {self.stats.timeout_errors}")
        lines.append(f"Duration:              {self.stats.get_duration():.2f} seconds")
        lines.append("")

        if successful:
            lines.append("=" * 60)
            lines.append("SUCCESSFUL LOGINS")
            lines.append("=" * 60)
            lines.append("")
            for r in successful:
                sev_tag = severity_display.get(r.severity, r.severity.upper() if r.severity else "N/A")
                lines.append(f"Host: {r.host}:{r.port}")
                lines.append(f"Username: {r.username}")
                lines.append(f"Password: {r.password}")
                lines.append(f"Severity: {sev_tag}")
                if r.banner:
                    lines.append(f"Banner: {r.banner}")
                if r.os_info:
                    lines.append(f"OS: {r.os_info} ({r.os_family})")
                if r.ssh_version:
                    lines.append(f"SSH Version: {r.ssh_version}")
                if r.host_key_type:
                    lines.append(f"Host Key: {r.host_key_type} ({r.host_key_bits} bits)")
                    lines.append(f"Fingerprint: {r.host_key_fingerprint}")
                if r.password_strength_label:
                    lines.append(f"Password Strength: {r.password_strength_label.upper()} ({r.password_strength_score:.0f}/100)")
                if r.severity_reasons:
                    lines.append("Findings:")
                    for reason in r.severity_reasons:
                        lines.append(f"  - {reason}")
                if r.host_key_changed:
                    lines.append("!!! HOST KEY CHANGED - possible MITM attack !!!")
                if r.honeypot_score >= 0.5:
                    lines.append(f"Honeypot score: {r.honeypot_score:.1f}")
                if r.command_output:
                    lines.append(f"Command Output: {r.command_output[:300]}")
                elif r.initial_output:
                    lines.append(f"Output: {r.initial_output[:300]}")
                lines.append("-" * 40)
                lines.append("")

        lines.append("=" * 60)
        lines.append("ALL RESULTS")
        lines.append("=" * 60)
        lines.append("")
        for r in self.results:
            status = "SUCCESS" if r.success else "FAILED"
            sev = f" [{r.severity.upper()}]" if r.severity else ""
            lines.append(f"[{status}]{sev} {r.host}:{r.port} {r.username}")
            if r.error_message:
                lines.append(f"  Error: {r.error_message[:100]}")

        # Generate minimal PDF 1.4
        self._write_pdf_file(path, lines)

    def _write_pdf_file(self, path: Path, lines: List[str]):
        """Write a minimal PDF 1.4 file with the given text lines."""
        # PDF generation: build objects
        objects = []
        xref_offsets = []

        # Escape special PDF characters in a text string
        def pdf_escape(text: str) -> str:
            return text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')

        # Build pages of content (approx 55 lines per page)
        lines_per_page = 55
        font_size = 10
        leading = 12
        margin_left = 50
        margin_top = 750
        page_width = 612  # US Letter
        page_height = 792

        pages_content = []
        for i in range(0, len(lines), lines_per_page):
            page_lines = lines[i:i + lines_per_page]
            stream_parts = [f"BT /F1 {font_size} Tf"]
            y = margin_top
            for line in page_lines:
                # Truncate very long lines for PDF
                line = line[:100]
                escaped = pdf_escape(line)
                stream_parts.append(f"{margin_left} {y} Td ({escaped}) Tj")
                y -= leading
                stream_parts.append(f"0 0 Td")  # Reset position
            # Use absolute positioning for each line
            stream_lines = []
            stream_lines.append(f"BT")
            stream_lines.append(f"/F1 {font_size} Tf")
            y = margin_top
            for line in page_lines:
                line = line[:100]
                escaped = pdf_escape(line)
                stream_lines.append(f"1 0 0 1 {margin_left} {y} Tm")
                stream_lines.append(f"({escaped}) Tj")
                y -= leading
            stream_lines.append("ET")
            pages_content.append("\n".join(stream_lines))

        if not pages_content:
            pages_content = ["BT /F1 10 Tf 50 750 Td (No results.) Tj ET"]

        num_pages = len(pages_content)

        # Object 1: Catalog
        objects.append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj")

        # Object 2: Pages
        page_obj_refs = " ".join(f"{i + 4} 0 R" for i in range(num_pages))
        objects.append(
            f"2 0 obj\n<< /Type /Pages /Kids [{page_obj_refs}] "
            f"/Count {num_pages} >>\nendobj"
        )

        # Object 3: Font
        objects.append(
            "3 0 obj\n<< /Type /Font /Subtype /Type1 "
            "/BaseFont /Courier >>\nendobj"
        )

        # Page objects and their stream objects
        next_obj_id = 4
        for idx, content in enumerate(pages_content):
            page_obj_id = next_obj_id
            stream_obj_id = next_obj_id + 1
            next_obj_id += 2

            # Page object
            objects.append(
                f"{page_obj_id} 0 obj\n"
                f"<< /Type /Page /Parent 2 0 R "
                f"/MediaBox [0 0 {page_width} {page_height}] "
                f"/Contents {stream_obj_id} 0 R "
                f"/Resources << /Font << /F1 3 0 R >> >> >>\n"
                f"endobj"
            )

            # Stream object
            stream_bytes = content.encode('latin-1', errors='replace')
            stream_len = len(stream_bytes)
            objects.append(
                f"{stream_obj_id} 0 obj\n"
                f"<< /Length {stream_len} >>\n"
                f"stream\n{content}\nendstream\n"
                f"endobj"
            )

        # Build PDF file
        pdf_parts = []
        pdf_parts.append(b"%PDF-1.4\n")

        for obj_str in objects:
            xref_offsets.append(len(b"".join(pdf_parts)))
            pdf_parts.append(obj_str.encode('latin-1', errors='replace') + b"\n")

        xref_start = len(b"".join(pdf_parts))
        total_objs = len(objects) + 1  # +1 for free object entry

        xref_lines = [f"xref\n0 {total_objs}\n"]
        xref_lines.append("0000000000 65535 f \n")
        for offset in xref_offsets:
            xref_lines.append(f"{offset:010d} 00000 n \n")

        pdf_parts.append("".join(xref_lines).encode('latin-1'))
        pdf_parts.append(
            f"trailer\n<< /Size {total_objs} /Root 1 0 R >>\n"
            f"startxref\n{xref_start}\n%%EOF\n".encode('latin-1')
        )

        with open(path, 'wb') as f:
            f.write(b"".join(pdf_parts))

    def _save_diff_output(self, diff: Dict[str, Any], path: Path):
        """
        Save only the differential/delta changes to a file.

        In diff mode, instead of the full report, outputs only changes
        between current scan and the baseline.
        """
        output_data = {
            "scan_info": {
                "program": __program_name__,
                "version": __version__,
                "mode": "differential",
                "start_time": self.stats.start_time.isoformat() if self.stats.start_time else None,
                "end_time": self.stats.end_time.isoformat() if self.stats.end_time else None,
            },
            "changes": diff,
        }

        suffix = path.suffix.lower()
        if suffix == '.json':
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
        elif suffix == '.csv':
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['change_type', 'host', 'port', 'username', 'password', 'detail'])
                for h in diff.get('new_hosts', []):
                    writer.writerow(['new_host', h['host'], h['port'], '', '', ''])
                for h in diff.get('removed_hosts', []):
                    writer.writerow(['removed_host', h['host'], h['port'], '', '', ''])
                for c in diff.get('new_credentials', []):
                    writer.writerow(['new_credential', c['host'], c['port'], c['username'], c['password'], ''])
                for c in diff.get('lost_credentials', []):
                    writer.writerow(['lost_credential', c['host'], c['port'], c['username'], c['password'], ''])
                for hk in diff.get('host_key_changes', []):
                    writer.writerow(['host_key_change', hk['host'], hk['port'], '', '',
                                     f"{hk['previous_fingerprint']} -> {hk['current_fingerprint']}"])
                for sv in diff.get('ssh_version_changes', []):
                    writer.writerow(['ssh_version_change', sv['host'], sv['port'], '', '',
                                     f"{sv['previous_version']} -> {sv['current_version']}"])
        else:
            # Default: text format
            with open(path, 'w', encoding='utf-8') as f:
                f.write(f"SSH Security Audit - Differential Report\n")
                f.write(f"Generated by {__program_name__} v{__version__}\n")
                f.write(f"{'='*60}\n\n")
                summary = diff.get('summary', {})
                total = sum(summary.values())
                if total == 0:
                    f.write("No changes detected.\n")
                else:
                    if diff.get('new_hosts'):
                        f.write(f"NEW HOSTS ({len(diff['new_hosts'])}):\n")
                        for h in diff['new_hosts']:
                            f.write(f"  + {h['host']}:{h['port']}\n")
                        f.write("\n")
                    if diff.get('removed_hosts'):
                        f.write(f"REMOVED HOSTS ({len(diff['removed_hosts'])}):\n")
                        for h in diff['removed_hosts']:
                            f.write(f"  - {h['host']}:{h['port']}\n")
                        f.write("\n")
                    if diff.get('new_credentials'):
                        f.write(f"NEW CREDENTIALS ({len(diff['new_credentials'])}):\n")
                        for c in diff['new_credentials']:
                            f.write(f"  + {c['host']}:{c['port']} {c['username']}:{c['password']}\n")
                        f.write("\n")
                    if diff.get('lost_credentials'):
                        f.write(f"LOST CREDENTIALS ({len(diff['lost_credentials'])}):\n")
                        for c in diff['lost_credentials']:
                            f.write(f"  - {c['host']}:{c['port']} {c['username']}:{c['password']}\n")
                        f.write("\n")
                    if diff.get('host_key_changes'):
                        f.write(f"HOST KEY CHANGES ({len(diff['host_key_changes'])}):\n")
                        for hk in diff['host_key_changes']:
                            f.write(f"  ! {hk['host']}:{hk['port']}\n")
                            f.write(f"    Previous: {hk['previous_type']} {hk['previous_fingerprint']}\n")
                            f.write(f"    Current:  {hk['current_type']} {hk['current_fingerprint']}\n")
                        f.write("\n")
                    if diff.get('ssh_version_changes'):
                        f.write(f"SSH VERSION CHANGES ({len(diff['ssh_version_changes'])}):\n")
                        for sv in diff['ssh_version_changes']:
                            f.write(f"  ~ {sv['host']}:{sv['port']}\n")
                            f.write(f"    Previous: {sv['previous_version']}\n")
                            f.write(f"    Current:  {sv['current_version']}\n")
                        f.write("\n")


def _severity_rank(sev: SeverityLevel) -> int:
    """Return numeric rank for severity comparison."""
    ranks = {
        SeverityLevel.INFO: 0,
        SeverityLevel.LOW: 1,
        SeverityLevel.MEDIUM: 2,
        SeverityLevel.HIGH: 3,
        SeverityLevel.CRITICAL: 4,
    }
    return ranks.get(sev, 0)


def load_config_file(config_path: str) -> dict:
    """
    Load configuration from a YAML or JSON config file.

    Args:
        config_path: Path to the configuration file

    Returns:
        Dictionary of configuration values
    """
    path = Path(config_path)
    if not path.exists():
        print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
    except (PermissionError, IOError) as e:
        print(f"ERROR: Cannot read config file: {e}", file=sys.stderr)
        sys.exit(1)

    # Try JSON first, then YAML
    if path.suffix in ('.json',):
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON in config file: {e}", file=sys.stderr)
            sys.exit(1)

    if path.suffix in ('.yaml', '.yml'):
        if not HAS_YAML:
            print(
                "ERROR: PyYAML is required for YAML config files.\n"
                "Install it with: pip install pyyaml",
                file=sys.stderr
            )
            sys.exit(1)
        try:
            return yaml.safe_load(content) or {}
        except yaml.YAMLError as e:
            print(f"ERROR: Invalid YAML in config file: {e}", file=sys.stderr)
            sys.exit(1)

    # Try JSON then YAML as fallback for unknown extensions
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    if HAS_YAML:
        try:
            return yaml.safe_load(content) or {}
        except yaml.YAMLError:
            pass

    print(f"ERROR: Cannot parse config file: {config_path}\n"
          f"Supported formats: JSON (.json), YAML (.yaml, .yml)", file=sys.stderr)
    sys.exit(1)


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

  %(prog)s -t server.example.com --try-empty --user-as-pass -u root -u admin
      Test empty passwords and username-as-password

  %(prog)s -t 192.168.1.1 -u root -p pass -c "id; uname -a" -f html -o report.html
      Execute command on success and generate HTML report

  %(prog)s --config scan_profile.yaml
      Run scan using configuration file

  %(prog)s -t 192.168.1.0/24 --exclude 192.168.1.1 --exclude 192.168.1.254 -u root -p pass
      Scan subnet but exclude specific hosts

  %(prog)s -t 192.168.1.0/24 -U users.txt -P passwords.txt --spray -n 5
      Credential spraying: one password per round across all hosts/users

  %(prog)s --import-nmap scan.xml -U users.txt -P passwords.txt
      Import targets from Nmap XML output

  %(prog)s -t 192.168.1.1 -u root -p pass --detect-honeypot
      Scan with honeypot detection enabled

  %(prog)s -t 192.168.1.1 -u root -p pass --known-hosts hosts.json
      Check host keys against known hosts file for MITM detection

  %(prog)s -t 192.168.1.0/24 -u root -p pass --baseline previous_scan.json
      Compare results against a previous scan baseline

  %(prog)s -t 192.168.1.1 -u root -p pass --source-ip 10.0.0.5
      Scan using a specific source IP address

  %(prog)s -t 192.168.1.0/24 -u root -p pass --jitter 2.0
      Add 0-2 second random delay between attempts

  %(prog)s -t 192.168.1.1 -u root -p pass --score-passwords -f pdf -o report.pdf
      Score password strength and generate PDF report

  %(prog)s -t 192.168.1.0/24 --scan-ports -u root -p pass
      Discover SSH ports before scanning

  %(prog)s -t 192.168.1.0/24 -u root -p pass --baseline prev.json --diff -o changes.json -f json
      Output only the differences from baseline scan

Report bugs to: https://github.com/rom/sshcheck/issues
        """
    )

    # Config file
    parser.add_argument(
        '--config',
        metavar='FILE',
        help=(
            'Load configuration from YAML or JSON file. '
            'CLI arguments override config file values.'
        )
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
    pass_group.add_argument(
        '--try-empty',
        action='store_true',
        help='Also try empty/null password for each username.'
    )
    pass_group.add_argument(
        '--user-as-pass',
        action='store_true',
        help='Also try the username as the password for each user.'
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
        choices=['text', 'json', 'csv', 'xml', 'html', 'pdf'],
        default='text',
        help='Output format: text, json, csv, xml, html, or pdf. Default: text'
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

    # Scan control options
    scan_group = parser.add_argument_group('Scan Control')
    scan_group.add_argument(
        '--stop-on-success',
        action='store_true',
        help='Stop testing a host:port after the first successful login.'
    )
    scan_group.add_argument(
        '--max-attempts-per-user',
        type=int,
        default=0,
        metavar='NUM',
        help=(
            'Maximum failed password attempts per username per host before '
            'skipping. Protects against account lockout. 0 = unlimited (default).'
        )
    )
    scan_group.add_argument(
        '-c', '--command',
        metavar='CMD',
        help='Execute command on successful login and capture output.'
    )
    scan_group.add_argument(
        '--resume',
        metavar='FILE',
        help=(
            'Resume scan from checkpoint file. The checkpoint file is '
            'automatically saved during scanning.'
        )
    )
    scan_group.add_argument(
        '--checkpoint',
        metavar='FILE',
        help='Save scan progress to checkpoint file for resume support.'
    )
    scan_group.add_argument(
        '--spray',
        action='store_true',
        help=(
            'Enable credential spray mode. Tries one password across all '
            'users/hosts before moving to the next password. Helps avoid '
            'account lockouts in enterprise environments.'
        )
    )

    # Target exclusion
    exclude_group = parser.add_argument_group('Target Exclusion')
    exclude_group.add_argument(
        '--exclude',
        action='append',
        dest='exclude_hosts',
        metavar='HOST',
        help=(
            'Host(s) to exclude from scanning. Accepts: single IP, '
            'CIDR range, IP range, or hostname. Can be specified multiple times.'
        )
    )
    exclude_group.add_argument(
        '--exclude-file',
        metavar='FILE',
        help=(
            'File containing hosts to exclude (one per line). '
            'Same format as target files.'
        )
    )

    # Security features
    security_group = parser.add_argument_group('Security Features')
    security_group.add_argument(
        '--detect-honeypot',
        action='store_true',
        help=(
            'Enable honeypot detection. Analyzes SSH banners, response '
            'patterns, and behavior for signs of SSH honeypots (Cowrie, Kippo, etc.).'
        )
    )
    security_group.add_argument(
        '--known-hosts',
        metavar='FILE',
        help=(
            'Check host keys against a known hosts file for MITM detection. '
            'Supports OpenSSH known_hosts format and sshcheck JSON format. '
            'Discovered keys are saved back to this file after scanning.'
        )
    )
    security_group.add_argument(
        '--baseline',
        metavar='FILE',
        help=(
            'Compare scan results against a previous scan baseline (JSON). '
            'Reports new/removed hosts, changed credentials, host key changes, '
            'and SSH version changes.'
        )
    )

    # Nmap integration
    nmap_group = parser.add_argument_group('Nmap Integration')
    nmap_group.add_argument(
        '--import-nmap',
        metavar='FILE',
        help=(
            'Import targets from an Nmap XML output file. Extracts hosts '
            'with open SSH ports. Can be combined with -t for additional targets.'
        )
    )

    # Source IP binding
    network_group = parser.add_argument_group('Network Options')
    network_group.add_argument(
        '--source-ip',
        metavar='IP',
        help=(
            'Bind to a specific source IP address for outgoing connections. '
            'Useful for testing from different network interfaces or VLANs.'
        )
    )

    # Service Discovery
    discovery_group = parser.add_argument_group('Service Discovery')
    discovery_group.add_argument(
        '--scan-ports',
        action='store_true',
        help=(
            'Discover SSH services before scanning. Performs a TCP connect '
            'scan on common SSH ports (22, 2222, 2200, etc.) to find SSH '
            'services. Discovered ports are added to the scan.'
        )
    )
    discovery_group.add_argument(
        '--discovery-ports',
        metavar='PORTS',
        help=(
            'Comma-separated list of ports to check during service discovery. '
            'Default: 22,2222,2200,22222,8022,830,222,2022,2220,10022'
        )
    )

    # Differential output
    diff_group = parser.add_argument_group('Differential Output')
    diff_group.add_argument(
        '--diff',
        action='store_true',
        dest='diff_mode',
        help=(
            'Enable differential/delta output mode. When used with --baseline, '
            'the output file contains only changes between current and baseline '
            'scans instead of the full report.'
        )
    )

    # Password scoring
    scoring_group = parser.add_argument_group('Password Analysis')
    scoring_group.add_argument(
        '--score-passwords',
        action='store_true',
        help=(
            'Score password strength for successful logins. Evaluates length, '
            'character diversity, common patterns, and entropy. Reports a '
            '0-100 score with labels (very_weak, weak, moderate, strong, very_strong).'
        )
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
    perf_group.add_argument(
        '--jitter',
        type=float,
        default=0.0,
        metavar='SECONDS',
        help=(
            'Add random delay (0 to SECONDS) between connection attempts. '
            'Helps avoid rate limiting and IDS detection. Default: 0 (no jitter).'
        )
    )

    # Other options
    parser.add_argument(
        '-V', '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )

    return parser.parse_args()


def apply_config(args: argparse.Namespace, config: dict):
    """
    Apply config file values to args, only for values not set on CLI.

    Args:
        args: Parsed command-line arguments
        config: Configuration dictionary from file
    """
    # Map config keys to argparse dest names, types, and parser defaults
    # (config_key: (attr_name, expected_type, parser_default))
    mapping = {
        'targets': ('targets', list, None),
        'target_file': ('target_file', str, None),
        'users': ('users', list, None),
        'user_file': ('user_file', str, None),
        'passwords': ('passwords', list, None),
        'password_file': ('password_file', str, None),
        'ports': ('ports', list, None),
        'port_file': ('port_file', str, None),
        'output': ('output', str, None),
        'format': ('format', str, 'text'),
        'verbose': ('verbose', bool, False),
        'quiet': ('quiet', bool, False),
        'threads': ('threads', int, 1),
        'timeout': ('timeout', int, 10),
        'try_empty': ('try_empty', bool, False),
        'user_as_pass': ('user_as_pass', bool, False),
        'stop_on_success': ('stop_on_success', bool, False),
        'max_attempts_per_user': ('max_attempts_per_user', int, 0),
        'command': ('command', str, None),
        'checkpoint': ('checkpoint', str, None),
        'spray': ('spray', bool, False),
        'exclude_hosts': ('exclude_hosts', list, None),
        'detect_honeypot': ('detect_honeypot', bool, False),
        'known_hosts': ('known_hosts', str, None),
        'baseline': ('baseline', str, None),
        'import_nmap': ('import_nmap', str, None),
        'source_ip': ('source_ip', str, None),
        'jitter': ('jitter', float, 0.0),
        'score_passwords': ('score_passwords', bool, False),
        'diff_mode': ('diff_mode', bool, False),
        'scan_ports': ('scan_ports', bool, False),
        'discovery_ports': ('discovery_ports', str, None),
    }

    for config_key, (attr_name, expected_type, default) in mapping.items():
        if config_key in config:
            current = getattr(args, attr_name, None)
            # Only apply config if CLI didn't change the value from its default
            if current is None or current == default:
                value = config[config_key]
                if expected_type == list and isinstance(value, str):
                    value = [value]
                setattr(args, attr_name, value)


def main():
    """Main entry point for the SSH audit client."""
    args = parse_arguments()

    # Load and apply config file if specified
    if args.config:
        config = load_config_file(args.config)
        apply_config(args, config)

    # Handle --resume as shorthand for --checkpoint with existing file
    checkpoint_file = args.checkpoint
    if args.resume:
        checkpoint_file = args.resume
        if not Path(args.resume).exists():
            print(f"ERROR: Resume file not found: {args.resume}", file=sys.stderr)
            sys.exit(1)

    # Import targets from Nmap XML if specified
    nmap_targets = []
    if args.import_nmap:
        try:
            nmap_results = SSHAuditClient.import_nmap_xml(args.import_nmap)
            if nmap_results:
                # Parse "host:port" format from nmap results
                for hp in nmap_results:
                    if ':' in hp:
                        h, p = hp.rsplit(':', 1)
                        nmap_targets.append(h)
                        try:
                            port_num = int(p)
                            if args.ports is None:
                                args.ports = []
                            if port_num not in args.ports:
                                args.ports.append(port_num)
                        except ValueError:
                            pass
                    else:
                        nmap_targets.append(hp)
                print(f"Imported {len(nmap_results)} SSH targets from Nmap XML",
                      file=sys.stderr if args.quiet else sys.stdout)
            else:
                print("WARNING: No SSH targets found in Nmap XML file.",
                      file=sys.stderr)
        except (FileNotFoundError, ValueError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

    # Collect targets
    targets = []
    if args.targets:
        targets.extend(args.targets)
    if nmap_targets:
        targets.extend(nmap_targets)
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

    if not passwords and not args.try_empty and not args.user_as_pass:
        print(
            "ERROR: No passwords specified.\n"
            "Please provide passwords using -p/--password or -P/--password-file options,\n"
            "or use --try-empty / --user-as-pass.\n"
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

    # Collect excluded hosts
    exclude_hosts = []
    if args.exclude_hosts:
        exclude_hosts.extend(args.exclude_hosts)
    if args.exclude_file:
        try:
            client = SSHAuditClient()
            exclude_hosts.extend(client._read_file_lines(args.exclude_file, "exclude"))
        except (FileNotFoundError, PermissionError, IOError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

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

    # Validate max-attempts-per-user
    if args.max_attempts_per_user < 0:
        print(
            "ERROR: --max-attempts-per-user must be >= 0.\n"
            f"Provided value: {args.max_attempts_per_user}",
            file=sys.stderr
        )
        sys.exit(1)

    # Validate jitter
    jitter_val = args.jitter
    if jitter_val < 0:
        print(
            "ERROR: --jitter must be >= 0.\n"
            f"Provided value: {jitter_val}",
            file=sys.stderr
        )
        sys.exit(1)

    # Validate source IP
    source_ip = args.source_ip
    if source_ip:
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            print(
                f"ERROR: Invalid source IP address: {source_ip}\n"
                f"Please provide a valid IPv4 or IPv6 address.",
                file=sys.stderr
            )
            sys.exit(1)

    # Validate diff mode requires baseline
    diff_mode = args.diff_mode
    if diff_mode and not args.baseline:
        print(
            "ERROR: --diff requires --baseline to be specified.\n"
            "The diff mode compares against a previous scan baseline.",
            file=sys.stderr
        )
        sys.exit(1)

    # Service discovery: scan for SSH ports before main scan
    if args.scan_ports:
        discovery_ports = None
        if args.discovery_ports:
            try:
                discovery_ports = [
                    int(p.strip()) for p in args.discovery_ports.split(',')
                    if p.strip()
                ]
            except ValueError:
                print(
                    "ERROR: Invalid --discovery-ports format. Use comma-separated port numbers.",
                    file=sys.stderr
                )
                sys.exit(1)

        if not args.quiet:
            print(f"Discovering SSH services on {len(targets)} target(s)...")

        discovered_ports = set(ports)
        for target in targets:
            # Expand targets for discovery
            tmp_client = SSHAuditClient()
            for host in tmp_client._parse_targets([target]):
                found = SSHAuditClient.discover_ssh_ports(
                    host,
                    ports=discovery_ports,
                    timeout=min(args.timeout, 3),
                    source_ip=source_ip,
                )
                for port_num, banner in found:
                    if port_num not in discovered_ports:
                        discovered_ports.add(port_num)
                        if not args.quiet:
                            banner_info = f" ({banner})" if banner else ""
                            print(f"  Discovered SSH on {host}:{port_num}{banner_info}")

        ports = sorted(discovered_ports)
        if not args.quiet:
            print(f"Ports to scan: {ports}\n")

    # Create and run audit client
    client = SSHAuditClient(
        timeout=args.timeout,
        verbose=args.verbose,
        quiet=args.quiet,
        threads=args.threads,
        output_file=args.output,
        output_format=args.format,
        try_empty=args.try_empty,
        user_as_pass=args.user_as_pass,
        stop_on_success=args.stop_on_success,
        max_attempts_per_user=args.max_attempts_per_user,
        command=args.command,
        checkpoint_file=checkpoint_file,
        spray_mode=args.spray,
        exclude_hosts=exclude_hosts if exclude_hosts else None,
        detect_honeypot=args.detect_honeypot,
        known_hosts_file=args.known_hosts,
        baseline_file=args.baseline,
        source_ip=source_ip,
        jitter=jitter_val,
        score_passwords=args.score_passwords,
        diff_mode=diff_mode,
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
        # Save checkpoint on interrupt
        if checkpoint_file:
            client._save_checkpoint(
                [(r.host, r.port, r.username, r.password) for r in client.results]
            )
            print(f"Checkpoint saved to: {checkpoint_file}", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\nERROR: Unexpected error occurred: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
