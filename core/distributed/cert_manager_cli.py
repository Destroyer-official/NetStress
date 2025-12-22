#!/usr/bin/env python3
"""
Certificate Manager CLI

Command-line tool for managing TLS certificates for distributed NetStress.
Supports certificate generation, listing, and revocation.
"""

import argparse
import sys
import os
from pathlib import Path
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.distributed.certificates import CertificateManager, CertificateError


def list_certificates(cert_manager: CertificateManager) -> None:
    """List all certificates"""
    print("Certificate Status:")
    print("=" * 60)
    
    # CA Certificate
    try:
        ca_path = cert_manager.get_ca_certificate_path()
        ca_valid = cert_manager._verify_certificate(Path(ca_path))
        print(f"CA Certificate: {ca_path}")
        print(f"  Status: {'Valid' if ca_valid else 'Invalid/Expired'}")
    except Exception as e:
        print(f"CA Certificate: Error - {e}")
    
    print()
    
    # Controller Certificate
    controller_valid = cert_manager._verify_certificate(cert_manager.controller_cert_path)
    if cert_manager.controller_cert_path.exists():
        print(f"Controller Certificate: {cert_manager.controller_cert_path}")
        print(f"  Status: {'Valid' if controller_valid else 'Invalid/Expired'}")
    else:
        print("Controller Certificate: Not found")
    
    print()
    
    # Agent Certificates
    agent_certs = cert_manager.list_agent_certificates()
    if agent_certs:
        print("Agent Certificates:")
        for cert in agent_certs:
            status = "Valid" if cert['valid'] else "Invalid/Expired"
            print(f"  {cert['agent_id']}: {status}")
            print(f"    Certificate: {cert['cert_path']}")
            print(f"    Private Key: {cert['key_path']}")
    else:
        print("Agent Certificates: None found")


def generate_ca(cert_manager: CertificateManager) -> None:
    """Generate CA certificate"""
    print("Generating CA certificate...")
    try:
        cert_path, key_path = cert_manager._generate_ca_certificate()
        print(f"CA certificate generated:")
        print(f"  Certificate: {cert_path}")
        print(f"  Private Key: {key_path}")
    except Exception as e:
        print(f"Error generating CA certificate: {e}")
        sys.exit(1)


def generate_controller(cert_manager: CertificateManager, controller_id: str, 
                       bind_addresses: List[str]) -> None:
    """Generate controller certificate"""
    print(f"Generating controller certificate for {controller_id}...")
    try:
        cert_path, key_path = cert_manager.ensure_controller_certificate(
            controller_id, bind_addresses
        )
        print(f"Controller certificate generated:")
        print(f"  Certificate: {cert_path}")
        print(f"  Private Key: {key_path}")
    except Exception as e:
        print(f"Error generating controller certificate: {e}")
        sys.exit(1)


def generate_agent(cert_manager: CertificateManager, agent_id: str, 
                  hostname: str = None) -> None:
    """Generate agent certificate"""
    print(f"Generating agent certificate for {agent_id}...")
    try:
        cert_path, key_path = cert_manager.generate_agent_certificate(agent_id, hostname)
        print(f"Agent certificate generated:")
        print(f"  Certificate: {cert_path}")
        print(f"  Private Key: {key_path}")
    except Exception as e:
        print(f"Error generating agent certificate: {e}")
        sys.exit(1)


def revoke_agent(cert_manager: CertificateManager, agent_id: str) -> None:
    """Revoke agent certificate"""
    print(f"Revoking certificate for agent {agent_id}...")
    try:
        success = cert_manager.revoke_agent_certificate(agent_id)
        if success:
            print(f"Certificate revoked for agent: {agent_id}")
        else:
            print(f"No certificate found for agent: {agent_id}")
    except Exception as e:
        print(f"Error revoking certificate: {e}")
        sys.exit(1)


def cleanup_expired(cert_manager: CertificateManager) -> None:
    """Clean up expired certificates"""
    print("Cleaning up expired certificates...")
    try:
        removed = cert_manager.cleanup_expired_certificates()
        print(f"Removed {removed} expired certificate(s)")
    except Exception as e:
        print(f"Error cleaning up certificates: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="NetStress Certificate Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list                                    # List all certificates
  %(prog)s generate-ca                             # Generate CA certificate
  %(prog)s generate-controller controller-01       # Generate controller cert
  %(prog)s generate-agent agent-01                 # Generate agent certificate
  %(prog)s revoke-agent agent-01                   # Revoke agent certificate
  %(prog)s cleanup                                 # Remove expired certificates
        """
    )
    
    parser.add_argument(
        '--cert-dir', 
        default='.netstress/certs',
        help='Certificate directory (default: .netstress/certs)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # List command
    subparsers.add_parser('list', help='List all certificates')
    
    # Generate CA command
    subparsers.add_parser('generate-ca', help='Generate CA certificate')
    
    # Generate controller command
    controller_parser = subparsers.add_parser('generate-controller', 
                                            help='Generate controller certificate')
    controller_parser.add_argument('controller_id', help='Controller ID')
    controller_parser.add_argument('--bind-address', action='append', 
                                 help='Bind addresses (can be specified multiple times)')
    
    # Generate agent command
    agent_parser = subparsers.add_parser('generate-agent', 
                                       help='Generate agent certificate')
    agent_parser.add_argument('agent_id', help='Agent ID')
    agent_parser.add_argument('--hostname', help='Agent hostname')
    
    # Revoke agent command
    revoke_parser = subparsers.add_parser('revoke-agent', 
                                        help='Revoke agent certificate')
    revoke_parser.add_argument('agent_id', help='Agent ID to revoke')
    
    # Cleanup command
    subparsers.add_parser('cleanup', help='Remove expired certificates')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Initialize certificate manager
    try:
        cert_manager = CertificateManager(args.cert_dir)
    except CertificateError as e:
        print(f"Error: {e}")
        print("\nTo install required dependencies:")
        print("  pip install cryptography")
        sys.exit(1)
    except Exception as e:
        print(f"Error initializing certificate manager: {e}")
        sys.exit(1)
    
    # Execute command
    try:
        if args.command == 'list':
            list_certificates(cert_manager)
        
        elif args.command == 'generate-ca':
            generate_ca(cert_manager)
        
        elif args.command == 'generate-controller':
            bind_addresses = args.bind_address or ['localhost', '127.0.0.1']
            generate_controller(cert_manager, args.controller_id, bind_addresses)
        
        elif args.command == 'generate-agent':
            generate_agent(cert_manager, args.agent_id, args.hostname)
        
        elif args.command == 'revoke-agent':
            revoke_agent(cert_manager, args.agent_id)
        
        elif args.command == 'cleanup':
            cleanup_expired(cert_manager)
        
        else:
            print(f"Unknown command: {args.command}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()