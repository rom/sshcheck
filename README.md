# sshcheck - SSH Security Audit Client

A Python-based SSH security audit tool for testing login capabilities across multiple hosts. Designed for authorized penetration testing, security assessments, and network audits.

## Features

- **Multi-target scanning**: Scan single IPs, CIDR ranges, IP ranges, or hostnames
- **Credential testing**: Test multiple username/password combinations
- **Empty/null password testing**: Automatically test blank passwords with `--try-empty`
- **Username-as-password testing**: Test each username as its own password with `--user-as-pass`
- **Multi-port support**: Test SSH on non-standard ports
- **Host key fingerprinting**: Collect and report SSH host key type, fingerprint, and key size
- **Algorithm enumeration**: Detect supported KEX, cipher, MAC, and host key algorithms; flag weak ones
- **OS/version fingerprinting**: Identify OS and SSH version from server banners
- **Severity scoring**: Automatic risk assessment (critical/high/medium/low/info) based on findings
- **Command execution**: Run commands on successful login and capture output
- **Output capture**: Captures SSH banners and initial shell output (welcome messages, prompts)
- **Multiple output formats**: Text, JSON, CSV, XML, and HTML report output
- **Configuration files**: YAML or JSON config files for reusable scan profiles
- **Resume/checkpoint**: Save scan progress and resume interrupted scans
- **Account lockout protection**: Limit failed attempts per user to avoid lockouts
- **Stop on first success**: Skip remaining credentials after finding valid login per host
- **Concurrent scanning**: Multi-threaded execution for faster scans
- **Comprehensive error handling**: Detailed error messages for troubleshooting

## Requirements

- Python 3.6 or later
- paramiko library
- pyyaml library (optional, for YAML config files)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/rom/sshcheck.git
cd sshcheck

# Install dependencies
pip install -r requirements.txt

# Make executable (optional)
chmod +x sshcheck.py
```

### Dependencies

```bash
pip install paramiko        # Required
pip install pyyaml          # Optional: for YAML config files
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
| `-p, --password PASS` | Password(s) to try. Can be specified multiple times. |
| `-P, --password-file FILE` | File containing passwords (one per line) |
| `--try-empty` | Also try empty/null password for each username |
| `--user-as-pass` | Also try the username as the password for each user |

#### Port Specification

| Option | Description |
|--------|-------------|
| `--port PORT` | SSH port(s) to try. Default: 22. Can be specified multiple times. |
| `--port-file FILE` | File containing ports (one per line) |

#### Output Options

| Option | Description |
|--------|-------------|
| `-o, --output FILE` | Save results to specified file |
| `-f, --format FORMAT` | Output format: `text`, `json`, `csv`, `xml`, or `html`. Default: `text` |
| `-v, --verbose` | Enable verbose output with detailed error messages |
| `-q, --quiet` | Suppress progress output, only show summary |

#### Scan Control

| Option | Description |
|--------|-------------|
| `--stop-on-success` | Stop testing a host:port after the first successful login |
| `--max-attempts-per-user NUM` | Max failed attempts per username per host before skipping (lockout protection). 0 = unlimited (default) |
| `-c, --command CMD` | Execute command on successful login and capture output |
| `--checkpoint FILE` | Save scan progress to checkpoint file |
| `--resume FILE` | Resume scan from a checkpoint file |

#### Configuration

| Option | Description |
|--------|-------------|
| `--config FILE` | Load configuration from YAML or JSON file. CLI arguments override config file values. |

#### Performance Options

| Option | Description |
|--------|-------------|
| `-n, --threads NUM` | Number of concurrent threads. Default: 1 |
| `--timeout SECONDS` | Connection timeout in seconds. Default: 10 |

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

### Test empty passwords and username-as-password

```bash
./sshcheck.py -t 192.168.1.1 --try-empty --user-as-pass -u root -u admin -u test
```

### Execute command on successful login with HTML report

```bash
./sshcheck.py -t 192.168.1.1 -u root -p pass -c "id; uname -a" -f html -o report.html
```

### Scan using credential lists and save JSON output

```bash
./sshcheck.py -T targets.txt -U users.txt -P passwords.txt -o results.json -f json
```

### Multi-threaded scanning with lockout protection

```bash
./sshcheck.py -t 10.0.0.0/24 -U users.txt -P passwords.txt -n 10 --max-attempts-per-user 3
```

### Stop after first valid credential per host

```bash
./sshcheck.py -t 192.168.1.0/24 -U users.txt -P passwords.txt --stop-on-success
```

### Scan with checkpoint (resume on interrupt)

```bash
./sshcheck.py -T targets.txt -U users.txt -P passwords.txt --checkpoint scan.progress

# Resume after interruption
./sshcheck.py -T targets.txt -U users.txt -P passwords.txt --resume scan.progress
```

### Use a configuration file

```bash
./sshcheck.py --config examples/scan_profile.json
```

### Generate XML output for tool integration

```bash
./sshcheck.py -t 192.168.1.1 -u root -p pass -f xml -o results.xml
```

## Configuration File

sshcheck supports JSON and YAML configuration files. CLI arguments override config file values.

### JSON Example (`scan_profile.json`)

```json
{
  "targets": ["192.168.1.0/24"],
  "users": ["root", "admin", "ubuntu"],
  "passwords": ["password", "admin", "changeme"],
  "ports": [22, 2222],
  "threads": 10,
  "timeout": 15,
  "try_empty": true,
  "user_as_pass": true,
  "stop_on_success": true,
  "max_attempts_per_user": 3,
  "command": "id; uname -a",
  "format": "html",
  "output": "audit_report.html",
  "checkpoint": "scan_checkpoint.json"
}
```

### YAML Example (`scan_profile.yaml`)

```yaml
targets:
  - 192.168.1.0/24
users:
  - root
  - admin
  - ubuntu
passwords:
  - password
  - admin
  - changeme
ports:
  - 22
  - 2222
threads: 10
timeout: 15
try_empty: true
user_as_pass: true
stop_on_success: true
max_attempts_per_user: 3
command: "id; uname -a"
format: html
output: audit_report.html
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

### Text Format (default)

Human-readable format showing scan statistics, severity ratings, and detailed results.

### JSON Format

Structured JSON with full scan details including host key info, algorithms, OS fingerprinting, and severity assessments.

### CSV Format

Comma-separated values with columns for all fields including new security assessment data.

### XML Format

Structured XML output suitable for integration with other security tools.

### HTML Format

Styled HTML report with:
- Summary statistics cards
- Successful logins table with severity badges
- Host key and OS information
- Command output display
- Color-coded severity levels (critical/high/medium/low/info)

## Severity Scoring

Each finding is assessed for severity based on multiple factors:

| Severity | Criteria |
|----------|----------|
| **CRITICAL** | Root/admin login with default or empty password |
| **HIGH** | Successful login for non-root user |
| **MEDIUM** | Weak host keys (DSA, short RSA), vulnerable SSH versions |
| **LOW** | Weak algorithms supported (RC4, 3DES, MD5-based MACs) |
| **INFO** | No significant findings |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | At least one successful login was found |
| 1 | No successful logins found or error occurred |
| 130 | Scan was interrupted by user (Ctrl+C) |

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
python -m pytest tests/test_sshcheck.py::TestSeverity -v
python -m pytest tests/test_sshcheck.py::TestOSFingerprinting -v
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
- **Rate limiting**: High thread counts may trigger intrusion detection systems or rate limiting. Use `--max-attempts-per-user` to avoid account lockouts
- **Legal compliance**: Unauthorized scanning may violate computer crime laws in your jurisdiction

## Troubleshooting

### "paramiko is not installed"

Install the required dependency:
```bash
pip install paramiko
```

### "PyYAML is required for YAML config files"

Install the optional YAML support:
```bash
pip install pyyaml
```

### Connection timeouts

- Increase timeout with `--timeout 30`
- Check network connectivity to target
- Verify firewall rules allow SSH traffic

### High failure rate

- Reduce thread count with `-n 5`
- Increase timeout for slow networks
- Check if targets have fail2ban or similar protection
- Use `--max-attempts-per-user 3` to avoid lockouts

### Resuming interrupted scans

Use `--checkpoint` to save progress, then `--resume` to continue:
```bash
./sshcheck.py -T targets.txt -U users.txt -P passwords.txt --checkpoint scan.progress
# After Ctrl+C...
./sshcheck.py -T targets.txt -U users.txt -P passwords.txt --resume scan.progress
```

## Contributing

Contributions are welcome! Please submit pull requests or open issues on GitHub.

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. The authors are not responsible for any misuse or damage caused by this program. Always obtain proper authorization before scanning any systems.
