# TLS Mutual Authentication for Distributed NetStress

This document describes the TLS mutual authentication implementation for secure communication between NetStress controllers and agents (Requirement 7.5).

## Overview

The distributed NetStress system now supports TLS mutual authentication, where both the controller and agents authenticate each other using X.509 certificates. This ensures secure, encrypted communication and prevents unauthorized agents from connecting to the controller.

## Features

- **Automatic Certificate Generation**: CA, controller, and agent certificates are generated automatically
- **Mutual Authentication**: Both controller and agents verify each other's certificates
- **Certificate Management**: Tools for listing, revoking, and managing certificates
- **Secure Communication**: All distributed communication is encrypted using TLS 1.2+
- **Certificate Renewal**: Automatic detection of expired certificates

## Architecture

```
┌─────────────────┐    TLS Mutual Auth    ┌─────────────────┐
│   Controller    │◄─────────────────────►│     Agent       │
│                 │                       │                 │
│ - Server Cert   │                       │ - Client Cert   │
│ - CA Cert       │                       │ - CA Cert       │
│ - Validates     │                       │ - Validates     │
│   Agent Certs   │                       │   Server Cert   │
└─────────────────┘                       └─────────────────┘
```

## Configuration

### Controller Configuration

```python
from core.distributed import DistributedController, ControllerConfig

config = ControllerConfig(
    bind_address="0.0.0.0",
    bind_port=9999,
    use_mutual_tls=True,           # Enable TLS mutual auth
    cert_dir=".netstress/certs",   # Certificate directory
    auto_generate_certs=True,      # Auto-generate certificates
)

controller = DistributedController(config)
```

### Agent Configuration

```python
from core.distributed import DistributedAgent, AgentConfig

config = AgentConfig(
    controller_host="controller.example.com",
    controller_port=9999,
    use_mutual_tls=True,           # Enable TLS mutual auth
    cert_dir=".netstress/certs",   # Certificate directory
)

agent = DistributedAgent(config)
```

## Certificate Management

### Using the CLI Tool

The certificate manager CLI provides easy certificate management:

```bash
# List all certificates
python -m core.distributed.cert_manager_cli list

# Generate CA certificate
python -m core.distributed.cert_manager_cli generate-ca

# Generate controller certificate
python -m core.distributed.cert_manager_cli generate-controller controller-01 \
    --bind-address localhost --bind-address 192.168.1.100

# Generate agent certificate
python -m core.distributed.cert_manager_cli generate-agent agent-01 \
    --hostname worker-01.example.com

# Revoke agent certificate
python -m core.distributed.cert_manager_cli revoke-agent agent-01

# Clean up expired certificates
python -m core.distributed.cert_manager_cli cleanup
```

### Programmatic Certificate Management

```python
from core.distributed.certificates import CertificateManager

# Initialize certificate manager
cert_manager = CertificateManager(".netstress/certs")

# Generate CA certificate
ca_cert, ca_key = cert_manager.ensure_ca_certificate()

# Generate controller certificate
controller_cert, controller_key = cert_manager.ensure_controller_certificate(
    "controller-01", ["localhost", "192.168.1.100"]
)

# Generate agent certificate
agent_cert, agent_key = cert_manager.generate_agent_certificate(
    "agent-01", "worker-01.example.com"
)

# List agent certificates
certs = cert_manager.list_agent_certificates()
for cert in certs:
    print(f"Agent: {cert['agent_id']}, Valid: {cert['valid']}")

# Revoke agent certificate
cert_manager.revoke_agent_certificate("agent-01")
```

## Certificate Directory Structure

```
.netstress/certs/
├── ca.crt                    # CA certificate
├── ca.key                    # CA private key
├── controller.crt            # Controller certificate
├── controller.key            # Controller private key
├── agent-agent01.crt         # Agent certificate
├── agent-agent01.key         # Agent private key
├── agent-agent02.crt         # Another agent certificate
└── agent-agent02.key         # Another agent private key
```

## Security Features

### Certificate Properties

- **CA Certificate**: 4096-bit RSA key, 10-year validity
- **Server/Client Certificates**: 2048-bit RSA key, 1-year validity
- **Encryption**: TLS 1.2+ with modern cipher suites
- **Key Usage**: Proper key usage extensions for server/client auth

### Mutual Authentication Flow

1. **Agent Connection**: Agent connects to controller with TLS
2. **Server Authentication**: Agent verifies controller's certificate against CA
3. **Client Authentication**: Controller requests and verifies agent's certificate
4. **Secure Channel**: Encrypted communication established

### Certificate Validation

- Certificate chain validation against CA
- Certificate expiration checking
- Hostname/IP verification for controller certificates
- Automatic cleanup of expired certificates

## Troubleshooting

### Common Issues

1. **Certificate Not Found**

   ```
   Error: Certificate not found
   Solution: Run certificate generation or check cert_dir path
   ```

2. **Certificate Expired**

   ```
   Error: Certificate expired
   Solution: Regenerate certificates or run cleanup command
   ```

3. **Hostname Mismatch**

   ```
   Error: Hostname verification failed
   Solution: Ensure controller certificate includes correct hostnames/IPs
   ```

4. **Permission Denied**
   ```
   Error: Permission denied accessing certificate files
   Solution: Check file permissions (certificates: 644, private keys: 600)
   ```

### Debug Information

Enable debug logging to troubleshoot TLS issues:

```python
import logging
logging.getLogger('core.distributed').setLevel(logging.DEBUG)
```

### Certificate Status

Check certificate status programmatically:

```python
# Get TLS status from controller
status = controller.get_tls_status()
print(f"Mutual TLS enabled: {status['mutual_tls_enabled']}")
print(f"Certificate manager available: {status['cert_manager_available']}")
print(f"Agent certificates: {status['agent_certificates']}")
```

## Migration from Non-TLS

To migrate existing deployments to TLS mutual authentication:

1. **Update Configuration**: Set `use_mutual_tls=True` in controller and agent configs
2. **Generate Certificates**: Run certificate generation for controller and existing agents
3. **Restart Services**: Restart controller and agents with new configuration
4. **Verify Connection**: Check that agents reconnect successfully with TLS

## Performance Impact

TLS mutual authentication adds minimal overhead:

- **Connection Establishment**: ~10-50ms additional latency for TLS handshake
- **Data Transfer**: <1% CPU overhead for encryption/decryption
- **Memory Usage**: ~1-2MB additional memory per connection for TLS context

## Dependencies

The TLS mutual authentication feature requires:

- `cryptography` library for certificate generation and management
- Python 3.7+ for modern TLS support
- OpenSSL 1.1.1+ for TLS 1.3 support (optional)

Install dependencies:

```bash
pip install cryptography
```

## Security Considerations

- **Private Key Protection**: Private keys are stored with 600 permissions
- **Certificate Rotation**: Certificates should be rotated before expiration
- **CA Security**: CA private key should be protected and backed up securely
- **Network Security**: TLS provides transport security but doesn't replace network security
- **Certificate Revocation**: Revoked certificates are deleted (no CRL support yet)

## Future Enhancements

Planned improvements for TLS mutual authentication:

- Certificate Revocation Lists (CRL) support
- OCSP (Online Certificate Status Protocol) support
- Hardware Security Module (HSM) integration
- Automatic certificate renewal
- Certificate transparency logging
