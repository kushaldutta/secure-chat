#!/usr/bin/env python3
"""
Certificate Setup Script for Secure Chat
This script helps set up certificate-based authentication.
"""

import os
import sys
from cryptography.hazmat.primitives import serialization
from crypto_utils import generate_keys, serialize_public_key
from cert_utils import (
    generate_self_signed_certificate, serialize_certificate,
    save_certificate_fingerprint, get_certificate_fingerprint
)

def main():
    print("=" * 60)
    print("🔐 SECURE CHAT CERTIFICATE SETUP")
    print("=" * 60)
    
    # Check if certificate already exists
    if os.path.exists("server_fingerprint.txt"):
        print("[!] Certificate fingerprint file already exists!")
        response = input("Do you want to regenerate? (y/N): ").strip().lower()
        if response != 'y':
            print("[*] Keeping existing certificate")
            return
    
    print("\n[*] Generating server certificate...")
    
    try:
        # Generate server key pair
        print("[*] Generating server key pair...")
        server_private_key, server_public_key = generate_keys()
        
        # Generate certificate
        print("[*] Creating self-signed certificate...")
        certificate = generate_self_signed_certificate(
            server_private_key, 
            server_public_key,
            "Secure Chat Server (127.0.0.1:5000)"
        )
        
        # Save certificate fingerprint
        print("[*] Saving certificate fingerprint...")
        fingerprint = save_certificate_fingerprint(certificate)
        
        # Save private key (for server use)
        print("[*] Saving server private key...")
        with open("server_private_key.pem", "wb") as f:
            f.write(server_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save certificate (for server use)
        print("[*] Saving server certificate...")
        with open("server_certificate.pem", "wb") as f:
            f.write(serialize_certificate(certificate))
        
        print("\n" + "=" * 60)
        print("✅ CERTIFICATE SETUP COMPLETE")
        print("=" * 60)
        print(f"📄 Certificate fingerprint: {fingerprint}")
        print(f"📁 Files created:")
        print(f"   - server_fingerprint.txt (for clients)")
        print(f"   - server_private_key.pem (for server)")
        print(f"   - server_certificate.pem (for server)")
        print(f"\n📋 Next steps:")
        print(f"   1. Copy server_fingerprint.txt to all client machines")
        print(f"   2. Start the server (it will use the certificate)")
        print(f"   3. Start clients (they will validate the certificate)")
        print(f"\n⚠️  Security notes:")
        print(f"   - Keep server_private_key.pem secure and private")
        print(f"   - Distribute server_fingerprint.txt to trusted clients only")
        print(f"   - Certificate is valid for 1 year")
        
    except Exception as e:
        print(f"[!] Certificate setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 