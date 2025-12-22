# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Email security concerns to: [security@example.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution**: Depends on severity

### Severity Levels

| Level    | Description                        | Response Time |
| -------- | ---------------------------------- | ------------- |
| Critical | Remote code execution, data breach | 24 hours      |
| High     | Privilege escalation, DoS          | 72 hours      |
| Medium   | Information disclosure             | 1 week        |
| Low      | Minor issues                       | 2 weeks       |

## Security Best Practices

### For Users

1. **Authorization**: Only test systems you own or have explicit permission to test
2. **Rate Limiting**: Use appropriate rate limits to avoid unintended damage
3. **Logging**: Enable audit logging for accountability
4. **Updates**: Keep NetStress updated to the latest version

### For Developers

1. **Input Validation**: Validate all user inputs
2. **Memory Safety**: Use Rust for performance-critical code
3. **Secrets**: Never commit secrets or credentials
4. **Dependencies**: Regularly update dependencies

## Built-in Safety Features

NetStress includes several safety mechanisms:

### Target Validation

```python
# Blocked by default
BLOCKED_PATTERNS = [
    "*.gov",
    "*.mil",
    "*.edu",
    "localhost",
    "127.0.0.1",
    "10.*",
    "192.168.*",
    "172.16.*"
]
```

### Rate Limiting

- Default maximum rate: 100,000 PPS
- Configurable per-target limits
- Automatic throttling on resource exhaustion

### Audit Logging

All operations are logged with:

- Timestamp
- Target information
- User/session ID
- Operation type
- Result

### Emergency Stop

- Keyboard interrupt (Ctrl+C)
- API endpoint for remote stop
- Automatic stop on error threshold

## Compliance

NetStress is designed for:

- Authorized penetration testing
- Security research
- Network stress testing
- Educational purposes

**NOT** for:

- Unauthorized attacks
- Malicious activities
- Disrupting services without permission

## Legal Notice

Users are solely responsible for ensuring their use of NetStress complies with:

- Local laws and regulations
- Terms of service of target systems
- Organizational policies

The developers assume no liability for misuse.

## Security Acknowledgments

We thank the following for responsible disclosure:

- (List will be updated as reports are received)
