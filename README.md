# sshcheck - SSH Security Audit Client

A Python-based SSH security audit tool for testing login capabilities across multiple hosts. Designed for authorized penetration testing, security assessments, and network audits.

## Features

- **Multi-target scanning**: Scan single IPs, CIDR ranges, IP ranges, or hostnames
- **Credential testing**: Test multiple username/password combinations
- **Credential spray mode**: Try one password across all users/hosts before the next (avoids lockouts)
- **Empty/null password testing**: Automatically test blank passwords with `--try-empty`
- **Username-as-password testing**: Test each username as its own password with `--user-as-pass`
- **Multi-port support**: Test SSH on non-standard ports
- **Target exclusion**: Exclude specific hosts, CIDRs, or ranges from scanning
- **Host key fingerprinting**: Collect and report SSH host key type, fingerprint, and key size
- **Host key continuity check**: Detect host key changes (possible MITM) against known hosts
- **Algorithm enumeration**: Detect supported KEX, cipher, MAC, and host key algorithms; flag weak ones
- **OS/version fingerprinting**: Identify OS and SSH version from server banners
- **Honeypot detection**: Identify likely SSH honeypots (Cowrie, Kippo) from banners and behavior
- **Severity scoring**: Automatic risk assessment (critical/high/medium/low/info) based on findings
- **Baseline comparison**: Compare scan results against previous scans to detect changes
- **Nmap XML import**: Import targets from Nmap scan results
- **Command execution**: Run commands on successful login and capture output
- **Output capture**: Captures SSH banners and initial shell output (welcome messages, prompts)
- **Source IP binding**: Bind outgoing connections to a specific network interface/IP
- **Service discovery**: TCP connect scan to discover SSH ports before brute-forcing
- **Password strength scoring**: Score password strength when login succeeds (0-100 with labels)
- **Jitter/randomization**: Add random delay between attempts to avoid IDS detection
- **Differential/delta output**: Output only changes between current and baseline scan
- **PDF report generation**: Generate PDF security audit reports
- **Multiple output formats**: Text, JSON, CSV, XML, HTML, and PDF report output
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
| `-f, --format FORMAT` | Output format: `text`, `json`, `csv`, `xml`, `html`, or `pdf`. Default: `text` |
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
| `--spray` | Credential spray mode: try one password across all users/hosts before the next |

#### Target Exclusion

| Option | Description |
|--------|-------------|
| `--exclude HOST` | Host(s) to exclude from scanning. Accepts same formats as `-t`. Can be specified multiple times. |
| `--exclude-file FILE` | File containing hosts to exclude (one per line) |

#### Security Features

| Option | Description |
|--------|-------------|
| `--detect-honeypot` | Enable honeypot detection (analyzes banners, response patterns for Cowrie, Kippo, etc.) |
| `--known-hosts FILE` | Check host keys against known hosts file for MITM detection. Supports OpenSSH and JSON formats. Discovered keys are saved back after scanning. |
| `--baseline FILE` | Compare results against a previous scan baseline (JSON). Reports new/removed hosts, changed credentials, host key changes, SSH version changes. |

#### Nmap Integration

| Option | Description |
|--------|-------------|
| `--import-nmap FILE` | Import targets from Nmap XML output. Extracts hosts with open SSH ports. Can be combined with `-t`. |

#### Configuration

| Option | Description |
|--------|-------------|
| `--config FILE` | Load configuration from YAML or JSON file. CLI arguments override config file values. |

#### Network Options

| Option | Description |
|--------|-------------|
| `--source-ip IP` | Bind to a specific source IP address for outgoing connections. Useful for testing from different network interfaces or VLANs. |

#### Service Discovery

| Option | Description |
|--------|-------------|
| `--scan-ports` | Discover SSH services before scanning. Performs TCP connect scan on common SSH ports to find SSH services. |
| `--discovery-ports PORTS` | Comma-separated list of ports to check during discovery. Default: 22,2222,2200,22222,8022,830,222,2022,2220,10022 |

#### Differential Output

| Option | Description |
|--------|-------------|
| `--diff` | Enable differential/delta output mode. When used with `--baseline`, the output file contains only changes between scans instead of the full report. |

#### Password Analysis

| Option | Description |
|--------|-------------|
| `--score-passwords` | Score password strength for successful logins. Reports a 0-100 score with labels (very_weak, weak, moderate, strong, very_strong). |

#### Performance Options

| Option | Description |
|--------|-------------|
| `-n, --threads NUM` | Number of concurrent threads. Default: 1 |
| `--timeout SECONDS` | Connection timeout in seconds. Default: 10 |
| `--jitter SECONDS` | Add random delay (0 to SECONDS) between connection attempts. Helps avoid rate limiting and IDS detection. Default: 0 |

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

### Credential spray mode (avoids account lockouts)

```bash
./sshcheck.py -t 192.168.1.0/24 -U users.txt -P passwords.txt --spray -n 5
```

### Scan with host exclusions

```bash
./sshcheck.py -t 192.168.1.0/24 --exclude 192.168.1.1 --exclude 192.168.1.254 -u root -p pass
./sshcheck.py -t 10.0.0.0/24 --exclude-file critical_hosts.txt -U users.txt -P passwords.txt
```

### Import targets from Nmap scan results

```bash
# First run Nmap to discover SSH hosts
nmap -p 22,2222 -sV -oX scan.xml 192.168.1.0/24

# Then use sshcheck to audit discovered SSH hosts
./sshcheck.py --import-nmap scan.xml -U users.txt -P passwords.txt
```

### Honeypot detection

```bash
./sshcheck.py -t 192.168.1.1 -u root -p pass --detect-honeypot
```

### Host key continuity check (MITM detection)

```bash
# First scan saves host keys
./sshcheck.py -t 192.168.1.0/24 -u root -p pass --known-hosts known_hosts.json

# Subsequent scans detect host key changes
./sshcheck.py -t 192.168.1.0/24 -u root -p pass --known-hosts known_hosts.json
```

### Baseline comparison (detect changes between scans)

```bash
# Run initial scan and save results
./sshcheck.py -t 192.168.1.0/24 -U users.txt -P passwords.txt -o baseline.json -f json

# Later, run again with baseline comparison
./sshcheck.py -t 192.168.1.0/24 -U users.txt -P passwords.txt --baseline baseline.json -o current.json -f json
```

### Scan with source IP binding

```bash
./sshcheck.py -t 192.168.1.0/24 -u root -p pass --source-ip 10.0.0.5
```

### Jitter between connection attempts

```bash
./sshcheck.py -t 192.168.1.0/24 -U users.txt -P passwords.txt --jitter 2.0
```

### Password strength scoring

```bash
./sshcheck.py -t 192.168.1.0/24 -U users.txt -P passwords.txt --score-passwords
```

### Generate PDF report

```bash
./sshcheck.py -t 192.168.1.0/24 -U users.txt -P passwords.txt -f pdf -o report.pdf --score-passwords
```

### Discover SSH ports before scanning

```bash
./sshcheck.py -t 192.168.1.0/24 --scan-ports -U users.txt -P passwords.txt
./sshcheck.py -t 192.168.1.1 --scan-ports --discovery-ports 22,2222,8022 -u root -p pass
```

### Differential/delta output

```bash
# First scan: save baseline
./sshcheck.py -t 192.168.1.0/24 -U users.txt -P passwords.txt -o baseline.json -f json

# Second scan: output only changes
./sshcheck.py -t 192.168.1.0/24 -U users.txt -P passwords.txt --baseline baseline.json --diff -o changes.json -f json
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
  "spray": false,
  "detect_honeypot": true,
  "known_hosts": "known_hosts.json",
  "score_passwords": true,
  "jitter": 1.0,
  "scan_ports": false,
  "source_ip": null,
  "diff_mode": false,
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
spray: false
detect_honeypot: true
known_hosts: known_hosts.json
score_passwords: true
jitter: 1.0
scan_ports: false
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

Comma-separated values with columns for all ScanResult fields including host key info, OS fingerprinting, severity reasons, honeypot detection, MITM detection, and password strength scores.

### XML Format

Structured XML output with full scan details including algorithms, severity reasons, honeypot scores, host key change detection, and password strength data. Suitable for integration with other security tools.

### HTML Format

Styled HTML report with:
- Summary statistics cards
- Successful logins table with severity badges
- Host key and OS information
- Command output display
- Color-coded severity levels (critical/high/medium/low/info)

### PDF Format

Self-contained PDF report generated with no external dependencies:
- Scan statistics summary
- Successful logins with full details
- Password strength scores (when enabled)
- All scan results listing
- Multi-page support for large scans

## Credential Spray Mode

In normal mode, sshcheck tries all passwords for a given user on a host before moving on. This can trigger account lockouts in enterprise environments.

Spray mode (`--spray`) changes the order: it tries **one password across all users and hosts** before moving to the next password. This mimics real-world attack patterns and dramatically reduces the risk of lockout.

```
Normal mode:  host1/user1/pass1, host1/user1/pass2, host1/user1/pass3, host1/user2/pass1, ...
Spray mode:   host1/user1/pass1, host1/user2/pass1, host2/user1/pass1, host2/user2/pass1, ...pass2...
```

## Honeypot Detection

When `--detect-honeypot` is enabled, sshcheck analyzes each connection for signs of SSH honeypots (Cowrie, Kippo, etc.):

- **Known honeypot banners**: Matches against known Cowrie/Kippo SSH banner signatures
- **Suspicious banner patterns**: Regex patterns matching common honeypot software
- **Default honeypot output**: Known default hostnames and shell output patterns
- **Timing analysis**: Suspiciously fast connections may indicate emulated services
- **Trivial credential acceptance**: Root login with empty or common passwords

Each result gets a honeypot score (0.0-1.0). Scores >= 0.5 are flagged as likely honeypots.

## Host Key Continuity Check

The `--known-hosts` option detects potential MITM (Man-in-the-Middle) attacks by comparing discovered host keys against previously known keys.

**Supported formats:**
- **sshcheck JSON format**: `{"host:port": {"type": "ssh-ed25519", "fingerprint": "SHA256:..."}}`
- **OpenSSH known_hosts format**: Standard `hostname key-type base64-key` format

On first run, discovered keys are **saved to the file**. On subsequent runs, any key changes are flagged as **CRITICAL** severity findings.

## Baseline Comparison

The `--baseline` option compares current scan results against a previous scan to detect changes:

- **New hosts**: Hosts present now but not in baseline
- **Removed hosts**: Hosts in baseline but not present now
- **New credentials**: Credentials that work now but didn't before
- **Lost credentials**: Credentials that stopped working
- **Host key changes**: SSH host key fingerprint changes
- **SSH version changes**: Software version upgrades or downgrades

A diff report is printed to stdout and saved as a `.diff.json` file alongside the output file.

## Source IP Binding

The `--source-ip` option binds all outgoing connections (banner grabbing, SSH connections) to a specific local IP address. This is useful when:

- Testing from a multi-homed machine with multiple network interfaces
- Scanning from a specific VLAN or network segment
- Ensuring traffic routes through a particular path

## Jitter/Randomization

The `--jitter` option adds a random delay (from 0 to the specified value in seconds) between each connection attempt. Benefits include:

- Avoiding rate limiting and connection throttling
- Reducing likelihood of triggering IDS/IPS alerts
- Mimicking more natural traffic patterns
- Works in both single-threaded and multi-threaded modes

## Password Strength Scoring

When `--score-passwords` is enabled, every successful login is scored on a 0-100 scale:

| Score Range | Label | Description |
|-------------|-------|-------------|
| 80-100 | VERY_STRONG | Excellent password with high entropy |
| 60-79 | STRONG | Good password with diverse characters |
| 40-59 | MODERATE | Acceptable but could be stronger |
| 20-39 | WEAK | Easily guessable or short |
| 0-19 | VERY_WEAK | Trivial, common, or empty password |

The scoring evaluates: length, character class diversity (upper, lower, digits, special), entropy, common password lists, username similarity, sequential characters, and repeated patterns.

## Service Discovery

The `--scan-ports` option performs a TCP connect scan on common SSH ports before the main credential scan. It:

- Discovers SSH services on non-standard ports automatically
- Grabs SSH banners to confirm the service
- Adds discovered ports to the scan target list
- Default ports scanned: 22, 2222, 2200, 22222, 8022, 830, 222, 2022, 2220, 10022
- Custom ports can be specified with `--discovery-ports`

## Differential Output

The `--diff` option (used with `--baseline`) changes the output to contain **only changes** between the current scan and the baseline:

- Supports JSON, CSV, and text output formats
- Shows new/removed hosts, credentials, host key and version changes
- Ideal for automated monitoring and alerting pipelines
- Much smaller output than full reports when tracking changes over time

## PDF Report

The `--format pdf` option generates a PDF security audit report with no external dependencies. The PDF includes:

- Scan statistics and summary
- Successful logins with severity, host keys, OS info
- Password strength scores (if `--score-passwords` enabled)
- Honeypot and MITM detection results
- All scan results listing

## Nmap XML Import

Import targets from Nmap XML output (`-oX`) to scan only hosts with SSH ports open:

```bash
nmap -p 22,2222,22222 -sV -oX nmap_scan.xml 10.0.0.0/24
./sshcheck.py --import-nmap nmap_scan.xml -U users.txt -P passwords.txt
```

Nmap results are filtered for:
- Hosts in `up` state
- TCP ports in `open` state
- Ports with `ssh` service name, or common SSH ports (22, 2222, 22222, 8022)

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
