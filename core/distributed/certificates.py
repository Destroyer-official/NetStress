"""
Certificate Management for Distributed Communication

Provides certificate generation and management for TLS mutual authentication
between controller and agents (Requirement 7.5).

Features:
- CA certificate generation
- Agent certificate generation with mutual auth
- Certificate validation and verification
- Automatic certificate renewal
"""

import os
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Tuple, List
import logging

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logger = logging.getLogger(__name__)


class CertificateError(Exception):
    """Certificate-related errors"""
    pass


class CertificateManager:
    """
    Manages certificates for distributed TLS communication.
    
    Provides:
    - CA certificate generation
    - Agent certificate generation with mutual auth
    - Certificate validation and verification
    - Automatic certificate renewal
    """
    
    def __init__(self, cert_dir: str = ".netstress/certs"):
        if not CRYPTO_AVAILABLE:
            raise CertificateError(
                "cryptography library not available. Install with: pip install cryptography"
            )
        
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        
        # Certificate paths
        self.ca_cert_path = self.cert_dir / "ca.crt"
        self.ca_key_path = self.cert_dir / "ca.key"
        self.controller_cert_path = self.cert_dir / "controller.crt"
        self.controller_key_path = self.cert_dir / "controller.key"
        
        # Certificate validity
        self.cert_validity_days = 365
        self.ca_validity_days = 3650  # 10 years for CA
        
        logger.info(f"Certificate manager initialized: {self.cert_dir}")
    
    def ensure_ca_certificate(self) -> Tuple[str, str]:
        """
        Ensure CA certificate exists, create if needed.
        
        Returns:
            Tuple of (cert_path, key_path)
        """
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            # Verify existing CA certificate
            if self._verify_certificate(self.ca_cert_path):
                logger.info("Using existing CA certificate")
                return str(self.ca_cert_path), str(self.ca_key_path)
            else:
                logger.warning("Existing CA certificate invalid, regenerating")
        
        logger.info("Generating new CA certificate")
        return self._generate_ca_certificate()
    
    def ensure_controller_certificate(self, controller_id: str, 
                                    bind_addresses: List[str] = None) -> Tuple[str, str]:
        """
        Ensure controller certificate exists, create if needed.
        
        Args:
            controller_id: Unique controller identifier
            bind_addresses: List of IP addresses/hostnames controller binds to
            
        Returns:
            Tuple of (cert_path, key_path)
        """
        if self.controller_cert_path.exists() and self.controller_key_path.exists():
            # Verify existing certificate
            if self._verify_certificate(self.controller_cert_path):
                logger.info("Using existing controller certificate")
                return str(self.controller_cert_path), str(self.controller_key_path)
            else:
                logger.warning("Existing controller certificate invalid, regenerating")
        
        # Ensure CA exists
        ca_cert_path, ca_key_path = self.ensure_ca_certificate()
        
        logger.info(f"Generating controller certificate for {controller_id}")
        return self._generate_controller_certificate(
            controller_id, bind_addresses or ["localhost", "127.0.0.1"]
        )
    
    def generate_agent_certificate(self, agent_id: str, 
                                 agent_hostname: str = None) -> Tuple[str, str]:
        """
        Generate certificate for an agent.
        
        Args:
            agent_id: Unique agent identifier
            agent_hostname: Agent hostname (optional)
            
        Returns:
            Tuple of (cert_path, key_path)
        """
        # Ensure CA exists
        ca_cert_path, ca_key_path = self.ensure_ca_certificate()
        
        # Ensure agent_id doesn't already have "agent-" prefix
        clean_agent_id = agent_id.replace("agent-", "") if agent_id.startswith("agent-") else agent_id
        agent_cert_path = self.cert_dir / f"agent-{clean_agent_id}.crt"
        agent_key_path = self.cert_dir / f"agent-{clean_agent_id}.key"
        
        logger.info(f"Generating agent certificate for {agent_id}")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Load CA certificate and key
        with open(ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        
        with open(ca_key_path, 'rb') as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        
        # Create certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "NetStress"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetStress Agent"),
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        ])
        
        # Subject Alternative Names
        san_list = [x509.DNSName(agent_id)]
        if agent_hostname:
            san_list.append(x509.DNSName(agent_hostname))
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            int(hashlib.sha256(agent_id.encode()).hexdigest()[:16], 16)
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=self.cert_validity_days)
        ).add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        ).sign(ca_key, hashes.SHA256())
        
        # Write certificate
        with open(agent_cert_path, 'wb') as f:
            f.write(cert.public_bytes(Encoding.PEM))
        
        # Write private key
        with open(agent_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))
        
        # Set restrictive permissions
        os.chmod(agent_key_path, 0o600)
        os.chmod(agent_cert_path, 0o644)
        
        logger.info(f"Agent certificate generated: {agent_cert_path}")
        return str(agent_cert_path), str(agent_key_path)
    
    def _generate_ca_certificate(self) -> Tuple[str, str]:
        """Generate CA certificate and private key"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,  # Stronger key for CA
        )
        
        # Create CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "NetStress"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetStress CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "NetStress Root CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=self.ca_validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(private_key, hashes.SHA256())
        
        # Write CA certificate
        with open(self.ca_cert_path, 'wb') as f:
            f.write(cert.public_bytes(Encoding.PEM))
        
        # Write CA private key
        with open(self.ca_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))
        
        # Set restrictive permissions
        os.chmod(self.ca_key_path, 0o600)
        os.chmod(self.ca_cert_path, 0o644)
        
        logger.info(f"CA certificate generated: {self.ca_cert_path}")
        return str(self.ca_cert_path), str(self.ca_key_path)
    
    def _generate_controller_certificate(self, controller_id: str, 
                                       bind_addresses: List[str]) -> Tuple[str, str]:
        """Generate controller certificate"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Load CA certificate and key
        with open(self.ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        
        with open(self.ca_key_path, 'rb') as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        
        # Create certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "NetStress"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetStress Controller"),
            x509.NameAttribute(NameOID.COMMON_NAME, controller_id),
        ])
        
        # Subject Alternative Names for all bind addresses
        san_list = [x509.DNSName(controller_id)]
        for addr in bind_addresses:
            try:
                # Try as IP address first
                import ipaddress
                ip = ipaddress.ip_address(addr)
                san_list.append(x509.IPAddress(ip))
            except ValueError:
                # Not an IP, treat as DNS name
                san_list.append(x509.DNSName(addr))
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            int(hashlib.sha256(controller_id.encode()).hexdigest()[:16], 16)
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=self.cert_validity_days)
        ).add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        ).sign(ca_key, hashes.SHA256())
        
        # Write certificate
        with open(self.controller_cert_path, 'wb') as f:
            f.write(cert.public_bytes(Encoding.PEM))
        
        # Write private key
        with open(self.controller_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))
        
        # Set restrictive permissions
        os.chmod(self.controller_key_path, 0o600)
        os.chmod(self.controller_cert_path, 0o644)
        
        logger.info(f"Controller certificate generated: {self.controller_cert_path}")
        return str(self.controller_cert_path), str(self.controller_key_path)
    
    def _verify_certificate(self, cert_path: Path) -> bool:
        """Verify certificate is valid and not expired"""
        try:
            with open(cert_path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
            
            # Check if certificate is expired (use timezone-aware properties)
            now = datetime.now(timezone.utc)
            not_valid_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_valid_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
            if now < not_valid_before or now > not_valid_after:
                logger.warning(f"Certificate expired: {cert_path}")
                return False
            
            # Check if certificate expires soon (within 30 days)
            expires_soon = now + timedelta(days=30)
            if not_valid_after < expires_soon:
                logger.warning(f"Certificate expires soon: {cert_path}")
                # Still valid, but should be renewed
            
            return True
            
        except Exception as e:
            logger.error(f"Certificate verification failed: {cert_path}: {e}")
            return False
    
    def get_ca_certificate_path(self) -> str:
        """Get path to CA certificate"""
        self.ensure_ca_certificate()
        return str(self.ca_cert_path)
    
    def list_agent_certificates(self) -> List[Dict[str, str]]:
        """List all agent certificates"""
        certs = []
        for cert_file in self.cert_dir.glob("agent-*.crt"):
            # Extract the clean agent ID from filename
            clean_agent_id = cert_file.stem.replace("agent-", "")
            # Reconstruct the full agent ID (add agent- prefix if not present)
            agent_id = f"agent-{clean_agent_id}" if not clean_agent_id.startswith("agent-") else clean_agent_id
            key_file = self.cert_dir / f"agent-{clean_agent_id}.key"
            
            if key_file.exists():
                certs.append({
                    'agent_id': agent_id,
                    'cert_path': str(cert_file),
                    'key_path': str(key_file),
                    'valid': self._verify_certificate(cert_file)
                })
        
        return certs
    
    def revoke_agent_certificate(self, agent_id: str) -> bool:
        """Revoke (delete) agent certificate"""
        # Ensure agent_id doesn't already have "agent-" prefix
        clean_agent_id = agent_id.replace("agent-", "") if agent_id.startswith("agent-") else agent_id
        cert_path = self.cert_dir / f"agent-{clean_agent_id}.crt"
        key_path = self.cert_dir / f"agent-{clean_agent_id}.key"
        
        removed = False
        if cert_path.exists():
            cert_path.unlink()
            removed = True
        
        if key_path.exists():
            key_path.unlink()
            removed = True
        
        if removed:
            logger.info(f"Revoked certificate for agent: {agent_id}")
        
        return removed
    
    def cleanup_expired_certificates(self) -> int:
        """Remove expired certificates"""
        removed = 0
        
        for cert_file in self.cert_dir.glob("agent-*.crt"):
            if not self._verify_certificate(cert_file):
                agent_id = cert_file.stem.replace("agent-", "")
                if self.revoke_agent_certificate(agent_id):
                    removed += 1
        
        if removed > 0:
            logger.info(f"Cleaned up {removed} expired agent certificates")
        
        return removed


def create_ssl_context_server(cert_path: str, key_path: str, ca_path: str):
    """
    Create SSL context for server (controller) with mutual authentication.
    
    Args:
        cert_path: Path to server certificate
        key_path: Path to server private key
        ca_path: Path to CA certificate for client verification
        
    Returns:
        SSL context configured for mutual auth
    """
    import ssl
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert_path, key_path)
    
    # Require client certificates (mutual auth)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(ca_path)
    
    # Modern TLS settings
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    
    return context


def create_ssl_context_client(cert_path: str, key_path: str, ca_path: str, 
                            server_hostname: str = None):
    """
    Create SSL context for client (agent) with mutual authentication.
    
    Args:
        cert_path: Path to client certificate
        key_path: Path to client private key
        ca_path: Path to CA certificate for server verification
        server_hostname: Expected server hostname (for verification)
        
    Returns:
        SSL context configured for mutual auth
    """
    import ssl
    
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(cert_path, key_path)
    context.load_verify_locations(ca_path)
    
    # Verify server certificate
    context.check_hostname = bool(server_hostname)
    context.verify_mode = ssl.CERT_REQUIRED
    
    # Modern TLS settings
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    
    return context