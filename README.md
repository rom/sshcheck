# sshcheck - SSH Security Audit Client

A Python-based SSH security audit tool for testing login capabilities across multiple hosts. Designed for authorized penetration testing, security assessments, and network audits.

## Features

- **Multi-target scanning**: Scan single IPs, CIDR ranges, IP ranges, or hostnames
- **Credential testing**: Test multiple username/password combinations
- **SSH key authentication**: Test with RSA, Ed25519, ECDSA, and DSA private keys
- **Combo file support**: Use `user:password` combo files for credential testing
- **Multi-port support**: Test SSH on non-standard ports
- **OS/software fingerprinting**: Identify SSH server software and operating system from banners
- **Vulnerability matching**: Check detected SSH versions against known CVEs
- **Algorithm enumeration**: Enumerate KEX, cipher, MAC, and host key algorithms with weakness detection
- **Host key fingerprints**: Collect SHA-256 and MD5 host key fingerprints
- **Output capture**: Captures SSH banners and initial shell output (welcome messages, prompts)
- **Multiple output formats**: Text, JSON, and CSV output
- **Progress bar**: Visual progress bar with ETA calculation
- **Color output**: Colored terminal output with `--no-color` option for piping
- **Proxy support**: Route connections through SOCKS4, SOCKS5, or HTTP proxies
- **Concurrent scanning**: Multi-threaded execution for faster scans
- **Comprehensive error handling**: Detailed error messages for troubleshooting
- **Cross-platform**: Works on various Linux distributions

## Requirements

- Python 3.6 or later
- paramiko library
- PySocks library (optional, for SOCKS proxy support)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/rom/sshcheck.git
cd sshcheck

# Install dependencies
pip install -r requirements.txt

# Install optional SOCKS proxy support
pip install pysocks

# Make executable (optional)
chmod +x sshcheck.py
```

### Dependencies

```bash
pip install paramiko          # Required: SSH protocol support
pip install pysocks           # Optional: SOCKS proxy support
```

## Usage

### Basic Syntax

```bash
./sshcheck.py -t <target> -u <username> -p <password> [options]
```

### Command Line Options

#### Target Specification

| Option | Description |
|--------|-------------|
| `-t, --target HOST` | Target host(s) to scan. Accepts: single IP, CIDR range, IP range, or hostname. Can be specified multiple times. |
| `-T, --target-file FILE` | File containing target hosts (one per line) |

#### Username Specification

| Option | Description |
|--------|-------------|
| `-u, --user USER` | Username(s) to try. Can be specified multiple times. |
| `-U, --user-file FILE` | File containing usernames (one per line) |

#### Password Specification

| Option | Description |
|--------|-------------|
| `-p, --password PASS` | Password(s) to try. Can be specified multiple times. Also used as passphrase for encrypted keys. |
| `-P, --password-file FILE` | File containing passwords (one per line) |

#### Key Authentication

| Option | Description |
|--------|-------------|
| `-k, --key FILE` | SSH private key file(s) for key-based auth. Supports RSA, Ed25519, ECDSA, DSA. Can be specified multiple times. |
| `-K, --key-file FILE` | File containing paths to SSH private key files (one per line) |

#### Combo File

| Option | Description |
|--------|-------------|
| `-C, --combo-file FILE` | File containing `username:password` combinations (one per line). Colons in passwords are supported. |

#### Port Specification

| Option | Description |
|--------|-------------|
| `--port PORT` | SSH port(s) to try. Default: 22. Can be specified multiple times. |
| `--port-file FILE` | File containing ports (one per line) |

#### Output Options

| Option | Description |
|--------|-------------|
| `-o, --output FILE` | Save results to specified file |
| `-f, --format FORMAT` | Output format: `text`, `json`, or `csv`. Default: `text` |
| `-v, --verbose` | Enable verbose output with detailed error messages |
| `-q, --quiet` | Suppress progress output, only show summary |
| `--no-color` | Disable colored output. Useful for piping to files. |

#### Performance Options

| Option | Description |
|--------|-------------|
| `-n, --threads NUM` | Number of concurrent threads. Default: 1 |
| `--timeout SECONDS` | Connection timeout in seconds. Default: 10 |

#### Proxy Options

| Option | Description |
|--------|-------------|
| `--proxy URL` | Route connections through a proxy. Formats: `socks5://host:port`, `socks4://host:port`, `http://host:port`. SOCKS requires PySocks. |

#### Other Options

| Option | Description |
|--------|-------------|
| `-V, --version` | Display version information |
| `-h, --help` | Display help message |

## Examples

### Scan single host with single credentials

```bash
./sshcheck.py -t 192.168.1.1 -u admin -p password123
```

### Scan entire subnet

```bash
./sshcheck.py -t 192.168.1.0/24 -u root -p admin123
```

### Scan IP range

```bash
./sshcheck.py -t 192.168.1.1-254 -u admin -p password
```

### Scan using credential lists and save JSON output

```bash
./sshcheck.py -T targets.txt -U users.txt -P passwords.txt -o results.json -f json
```

### Multi-threaded scanning with custom timeout

```bash
./sshcheck.py -t 10.0.0.0/24 -u root -p password -n 10 --timeout 5
```

### Scan non-standard SSH port

```bash
./sshcheck.py -t server.example.com -u root -p secret --port 2222
```

### Scan using SSH key authentication

```bash
./sshcheck.py -t 192.168.1.1 -u admin -k ~/.ssh/id_rsa
```

### Scan with encrypted key (passphrase via -p)

```bash
./sshcheck.py -t 192.168.1.1 -u admin -k ~/.ssh/id_rsa -p my_passphrase
```

### Scan using multiple key types

```bash
./sshcheck.py -t 192.168.1.1 -u admin -k ~/.ssh/id_rsa -k ~/.ssh/id_ed25519
```

### Scan using combo file

```bash
./sshcheck.py -t 192.168.1.1 -C combos.txt
```

### Scan through a SOCKS5 proxy (e.g., Tor)

```bash
./sshcheck.py -t 192.168.1.1 -u root -p pass --proxy socks5://127.0.0.1:9050
```

### Scan through an HTTP proxy

```bash
./sshcheck.py -t 192.168.1.1 -u root -p pass --proxy http://proxy.corp.com:8080
```

### Scan with color output disabled (for logging)

```bash
./sshcheck.py -t 192.168.1.1 -u root -p pass --no-color > scan_results.log
```

### Scan multiple ports

```bash
./sshcheck.py -t 192.168.1.1 -u root -p pass --port 22 --port 2222 --port 22222
```

### Verbose output with multiple credentials

```bash
./sshcheck.py -t 192.168.1.1 -u root -u admin -p pass1 -p pass2 -v
```

## Input File Formats

### Target File (targets.txt)

```text
# Network devices
192.168.1.1
192.168.1.2

# Subnet scan
10.0.0.0/24

# IP range
172.16.0.1-50

# Hostnames
server1.example.com
server2.example.com
```

### Username File (users.txt)

```text
# Common usernames
root
admin
administrator
user
guest
test
```

### Password File (passwords.txt)

```text
# Common passwords
password
admin
123456
password123
root
toor
```

### Combo File (combos.txt)

```text
# Format: username:password
# Colons in passwords are supported (split on first colon)
root:password
admin:admin123
test:test
oracle:oracle
user:p@ss:w0rd
```

### Port File (ports.txt)

```text
# Standard SSH port
22

# Alternative SSH ports
2222
22222
8022
```

## Output Formats

### Text Format

Human-readable format showing scan statistics, successful logins, host key fingerprints, software fingerprints, vulnerabilities, and weak algorithm findings.

### JSON Format

Structured JSON with full scan details including extended fields:

```json
{
  "scan_info": {
    "program": "sshcheck",
    "version": "2.0.0",
    "start_time": "2026-01-15T10:30:00",
    "end_time": "2026-01-15T10:30:45",
    "duration_seconds": 45.32,
    "proxy": null
  },
  "statistics": {
    "total_attempts": 60,
    "successful_logins": 2,
    "failed_logins": 58,
    "authentication_errors": 55,
    "connection_errors": 2,
    "timeout_errors": 1
  },
  "results": [
    {
      "host": "192.168.1.1",
      "port": 22,
      "username": "admin",
      "password": "password123",
      "success": true,
      "timestamp": "2026-01-15T10:30:05",
      "auth_method": "password",
      "key_file": "",
      "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
      "connection_time": 0.523,
      "fingerprint_info": {
        "software": "OpenSSH",
        "software_version": "8.9p1",
        "os_guess": "Ubuntu Linux",
        "protocol_version": "2.0"
      },
      "host_key_info": {
        "key_type": "ssh-ed25519",
        "key_bits": 256,
        "fingerprint_sha256": "SHA256:...",
        "fingerprint_md5": "MD5:aa:bb:cc:..."
      },
      "vulnerabilities": [
        {
          "cve": "CVE-2023-48795",
          "name": "Terrapin Attack",
          "severity": "MEDIUM",
          "affected": "OpenSSH < 9.6",
          "description": "Prefix truncation attack on BPP"
        }
      ]
    }
  ]
}
```

### CSV Format

Comma-separated values with extended columns for spreadsheet import:

```csv
host,port,username,password,auth_method,key_file,success,timestamp,banner,initial_output,error_message,connection_time,software,software_version,os_guess,host_key_type,host_key_bits,host_key_sha256,vulnerabilities
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | At least one successful login was found |
| 1 | No successful logins found or error occurred |
| 130 | Scan was interrupted by user (Ctrl+C) |

## Security Audit Features

### OS/Software Fingerprinting

sshcheck identifies SSH server software and operating system from the SSH banner. Recognized servers include:

- OpenSSH (Ubuntu, Debian, RHEL/CentOS, Fedora, FreeBSD, Windows)
- Dropbear SSH (embedded/IoT devices)
- libssh
- Cisco IOS SSH
- MikroTik RouterOS
- Huawei VRP
- And more

### Vulnerability Matching

Detected SSH software versions are checked against a database of known CVEs, including:

- **CVE-2024-6387** (regreSSHion) - Remote code execution in OpenSSH 8.5-9.7
- **CVE-2023-48795** (Terrapin Attack) - Prefix truncation in OpenSSH, Dropbear, libssh
- **CVE-2023-38408** - RCE via ssh-agent forwarding
- **CVE-2021-41617** - Privilege escalation in OpenSSH
- **CVE-2018-15473** - Username enumeration in OpenSSH
- And more

### Algorithm Weakness Detection

sshcheck reports weak/deprecated algorithms, including:

- **KEX**: DH group1 (Logjam), SHA-1 based key exchange
- **Ciphers**: RC4/arcfour, 3DES-CBC (Sweet32), CBC mode ciphers (padding oracle)
- **MACs**: MD5-based, SHA-1 based, short-tag UMAC
- **Host Keys**: DSA (1024-bit limit), SHA-1 RSA signatures

### Host Key Fingerprints

For each target, sshcheck collects:
- Key type and bit length
- SHA-256 fingerprint
- MD5 fingerprint

## Error Messages

| Error | Description |
|-------|-------------|
| Authentication failed | Username/password combination rejected |
| Connection timed out | Host did not respond within timeout |
| Connection refused | SSH service not running on target port |
| No route to host | Network path unavailable |
| Network is unreachable | Cannot reach target network |

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=sshcheck

# Run specific test class
python -m pytest tests/test_sshcheck.py::TestBannerFingerprinting -v
python -m pytest tests/test_sshcheck.py::TestVulnerabilityChecking -v
python -m pytest tests/test_sshcheck.py::TestComboFileParsing -v
python -m pytest tests/test_sshcheck.py::TestProxyParsing -v
```

## Installing the Man Page

```bash
# Copy man page to system location
sudo cp sshcheck.1 /usr/local/share/man/man1/

# Update man database
sudo mandb

# View man page
man sshcheck
```

## Security Considerations

- **Authorization**: Only use this tool on systems you own or have explicit written permission to test
- **Password visibility**: Passwords on the command line may be visible in process listings. Use `-P` with password files for sensitive credentials
- **Rate limiting**: High thread counts may trigger intrusion detection systems or rate limiting
- **Legal compliance**: Unauthorized scanning may violate computer crime laws in your jurisdiction
- **Proxy usage**: When using proxies, ensure you have authorization to route traffic through them

## Troubleshooting

### "paramiko is not installed"

Install the required dependency:
```bash
pip install paramiko
```

### "PySocks is required for SOCKS proxy support"

Install the optional dependency:
```bash
pip install pysocks
```

### Connection timeouts

- Increase timeout with `--timeout 30`
- Check network connectivity to target
- Verify firewall rules allow SSH traffic

### High failure rate

- Reduce thread count with `-n 5`
- Increase timeout for slow networks
- Check if targets have fail2ban or similar protection

### Permission denied errors

- Ensure you have read permissions on input files
- Ensure you have write permissions for output directory

### Key authentication issues

- Verify key file permissions (`chmod 600 ~/.ssh/id_rsa`)
- Use `-p` to provide passphrase for encrypted keys
- Check that the key type is supported (RSA, Ed25519, ECDSA, DSA)

## Contributing

Contributions are welcome! Please submit pull requests or open issues on GitHub.

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. The authors are not responsible for any misuse or damage caused by this program. Always obtain proper authorization before scanning any systems.
