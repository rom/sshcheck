# sshcheck - SSH Security Audit Client

A Python-based SSH security audit tool for testing login capabilities across multiple hosts. Designed for authorized penetration testing, security assessments, and network audits.

## Features

- **Multi-target scanning**: Scan single IPs, CIDR ranges, IP ranges, or hostnames
- **Credential testing**: Test multiple username/password combinations
- **Multi-port support**: Test SSH on non-standard ports
- **Output capture**: Captures SSH banners and initial shell output (welcome messages, prompts)
- **Multiple output formats**: Text, JSON, and CSV output
- **Concurrent scanning**: Multi-threaded execution for faster scans
- **Comprehensive error handling**: Detailed error messages for troubleshooting
- **Cross-platform**: Works on various Linux distributions

## Requirements

- Python 3.6 or later
- paramiko library

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
pip install paramiko
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

Human-readable format showing scan statistics and detailed results:

```
============================================================
SSH Security Audit - sshcheck v1.0.0
============================================================
Targets: 5 host(s)
Usernames: 3
Passwords: 4
Ports: [22]
Total combinations: 60
============================================================

[1/60] (  1.7%) [SUCCESS] 192.168.1.1:22 user=admin
    Output: Welcome to Ubuntu 22.04 LTS...

============================================================
SCAN SUMMARY
============================================================
Total attempts:        60
Successful logins:     2
Failed logins:         58
  - Auth failures:     55
  - Connection errors: 2
  - Timeouts:          1
Duration:              45.32 seconds
============================================================
```

### JSON Format

Structured JSON with full scan details:

```json
{
  "scan_info": {
    "program": "sshcheck",
    "version": "1.0.0",
    "start_time": "2026-01-15T10:30:00",
    "end_time": "2026-01-15T10:30:45",
    "duration_seconds": 45.32
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
      "initial_output": "Welcome to Ubuntu 22.04 LTS\n...",
      "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
      "error_message": "",
      "connection_time": 0.523
    }
  ]
}
```

### CSV Format

Comma-separated values for spreadsheet import:

```csv
host,port,username,password,success,timestamp,banner,initial_output,error_message,connection_time
192.168.1.1,22,admin,password123,True,2026-01-15T10:30:05,SSH-2.0-OpenSSH_8.9,"Welcome to Ubuntu",,0.523
192.168.1.2,22,root,toor,False,2026-01-15T10:30:10,,,Authentication failed,1.234
```

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
python -m pytest tests/test_sshcheck.py::TestSSHAuditClientTargetParsing -v
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

## Troubleshooting

### "paramiko is not installed"

Install the required dependency:
```bash
pip install paramiko
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

## Contributing

Contributions are welcome! Please submit pull requests or open issues on GitHub.

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. The authors are not responsible for any misuse or damage caused by this program. Always obtain proper authorization before scanning any systems.
