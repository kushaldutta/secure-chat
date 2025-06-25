#!/usr/bin/env python3
"""
Certificate Validation Demo for Secure Chat
This demo shows how certificate validation prevents MITM attacks.
"""

import os
import sys
import time
import threading
import subprocess
from cryptography.hazmat.primitives import serialization
from crypto_utils import generate_keys, serialize_public_key
from cert_utils import (
    generate_self_signed_certificate, serialize_certificate,
    save_certificate_fingerprint, get_certificate_fingerprint,
    deserialize_certificate, validate_certificate, CertError
)
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

def print_header(title):
    print("\n" + "=" * 80)
    print(f"🔐 {title}")
    print("=" * 80)

def print_step(step, description):
    print(f"\n📋 STEP {step}: {description}")
    print("-" * 60)

def print_success(message):
    print(f"✅ {message}")

def print_warning(message):
    print(f"⚠️  {message}")

def print_error(message):
    print(f"❌ {message}")

def print_info(message):
    print(f"ℹ️  {message}")

def demo_1_normal_operation():
    """Demo 1: Normal certificate validation"""
    print_header("DEMO 1: NORMAL CERTIFICATE VALIDATION")
    
    print_step(1, "Generate legitimate server certificate")
    server_private_key, server_public_key = generate_keys()
    certificate = generate_self_signed_certificate(
        server_private_key, server_public_key, "Legitimate Server"
    )
    fingerprint = get_certificate_fingerprint(certificate)
    print_success(f"Generated certificate with fingerprint: {fingerprint[:16]}...")
    
    print_step(2, "Save fingerprint for client verification")
    with open("demo_fingerprint.txt", "w") as f:
        f.write(f"Server Certificate Fingerprint (SHA-256):\n{fingerprint}\n")
    print_success("Fingerprint saved to demo_fingerprint.txt")
    
    print_step(3, "Simulate client receiving certificate")
    cert_bytes = serialize_certificate(certificate)
    received_cert = deserialize_certificate(cert_bytes)
    
    print_step(4, "Client validates certificate")
    try:
        validate_certificate(received_cert, fingerprint)
        print_success("Certificate validation PASSED - legitimate server detected!")
        print_info("Client proceeds with secure connection")
    except CertError as e:
        print_error(f"Certificate validation FAILED: {e}")

def demo_2_mitm_attack():
    """Demo 2: MITM attack detection"""
    print_header("DEMO 2: MITM ATTACK DETECTION")
    
    print_step(1, "Generate legitimate server certificate")
    legit_private_key, legit_public_key = generate_keys()
    legit_cert = generate_self_signed_certificate(
        legit_private_key, legit_public_key, "Legitimate Server"
    )
    legit_fingerprint = get_certificate_fingerprint(legit_cert)
    print_success(f"Legitimate server fingerprint: {legit_fingerprint[:16]}...")
    
    print_step(2, "Generate attacker's fake certificate")
    attacker_private_key, attacker_public_key = generate_keys()
    fake_cert = generate_self_signed_certificate(
        attacker_private_key, attacker_public_key, "Fake Server"
    )
    fake_fingerprint = get_certificate_fingerprint(fake_cert)
    print_warning(f"Attacker's fake fingerprint: {fake_fingerprint[:16]}...")
    
    print_step(3, "Client expects legitimate server fingerprint")
    expected_fingerprint = legit_fingerprint
    print_info(f"Client expects: {expected_fingerprint[:16]}...")
    
    print_step(4, "Attacker intercepts connection and sends fake certificate")
    fake_cert_bytes = serialize_certificate(fake_cert)
    received_cert = deserialize_certificate(fake_cert_bytes)
    
    print_step(5, "Client validates fake certificate")
    try:
        validate_certificate(received_cert, expected_fingerprint)
        print_error("Certificate validation PASSED - this should NOT happen!")
    except CertError as e:
        print_success(f"Certificate validation FAILED: {e}")
        print_success("MITM attack DETECTED! Client refuses connection.")
        print_info("This prevents the attacker from intercepting your messages")

def demo_3_certificate_tampering():
    """Demo 3: Certificate tampering detection"""
    print_header("DEMO 3: CERTIFICATE TAMPERING DETECTION")
    
    print_step(1, "Generate original certificate")
    private_key, public_key = generate_keys()
    original_cert = generate_self_signed_certificate(
        private_key, public_key, "Original Server"
    )
    original_fingerprint = get_certificate_fingerprint(original_cert)
    print_success(f"Original fingerprint: {original_fingerprint[:16]}...")
    
    print_step(2, "Attacker tries to modify certificate")
    print_warning("Attacker attempts to change certificate details...")
    
    # Create a modified certificate (simulating tampering)
    modified_cert = generate_self_signed_certificate(
        private_key, public_key, "Modified Server"  # Different name
    )
    modified_fingerprint = get_certificate_fingerprint(modified_cert)
    print_warning(f"Modified fingerprint: {modified_fingerprint[:16]}...")
    
    print_step(3, "Client validates modified certificate")
    try:
        validate_certificate(modified_cert, original_fingerprint)
        print_error("Certificate validation PASSED - this should NOT happen!")
    except CertError as e:
        print_success(f"Certificate validation FAILED: {e}")
        print_success("Certificate tampering DETECTED!")

def demo_4_expired_certificate():
    """Demo 4: Expired certificate detection"""
    print_header("DEMO 4: EXPIRED CERTIFICATE DETECTION")
    
    print_step(1, "Generate certificate with past expiration date")
    from datetime import datetime, timedelta
    
    private_key, public_key = generate_keys()
    
    # Create a certificate that's already expired
    now = datetime.utcnow()
    past_date = now - timedelta(days=1)  # 1 day ago
    future_date = now - timedelta(hours=1)  # 1 hour ago (already expired)
    
    # Create certificate manually with expired dates
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Expired Server"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Chat"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    
    expired_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        past_date
    ).not_valid_after(
        future_date
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    print_success("Created certificate that expired 1 hour ago")
    
    print_step(2, "Client validates expired certificate")
    try:
        validate_certificate(expired_cert)
        print_error("Certificate validation PASSED - this should NOT happen!")
    except CertError as e:
        print_success(f"Certificate validation FAILED: {e}")
        print_success("Expired certificate DETECTED!")

def demo_5_fingerprint_comparison():
    """Demo 5: Visual fingerprint comparison"""
    print_header("DEMO 5: FINGERPRINT COMPARISON")
    
    print_step(1, "Generate multiple certificates")
    certs = []
    for i in range(3):
        private_key, public_key = generate_keys()
        cert = generate_self_signed_certificate(
            private_key, public_key, f"Server {i+1}"
        )
        fingerprint = get_certificate_fingerprint(cert)
        certs.append((cert, fingerprint))
        print_info(f"Server {i+1} fingerprint: {fingerprint}")
    
    print_step(2, "Show fingerprint uniqueness")
    print_info("Notice how each certificate has a completely different fingerprint:")
    for i, (cert, fingerprint) in enumerate(certs):
        print(f"   Server {i+1}: {fingerprint[:16]}...")
    
    print_step(3, "Demonstrate fingerprint matching")
    expected = certs[0][1]  # Use first certificate's fingerprint
    print_info(f"Expected fingerprint: {expected[:16]}...")
    
    for i, (cert, fingerprint) in enumerate(certs):
        if fingerprint == expected:
            print_success(f"Server {i+1} matches expected fingerprint")
        else:
            print_warning(f"Server {i+1} does NOT match expected fingerprint")

def interactive_demo():
    """Interactive demo where user can test different scenarios"""
    print_header("INTERACTIVE CERTIFICATE DEMO")
    
    print("Choose a demo scenario:")
    print("1. Normal operation (legitimate server)")
    print("2. MITM attack detection")
    print("3. Certificate tampering detection")
    print("4. Expired certificate detection")
    print("5. Fingerprint comparison")
    print("6. Run all demos")
    print("0. Exit")
    
    while True:
        choice = input("\nEnter your choice (0-6): ").strip()
        
        if choice == "0":
            print("Goodbye!")
            break
        elif choice == "1":
            demo_1_normal_operation()
        elif choice == "2":
            demo_2_mitm_attack()
        elif choice == "3":
            demo_3_certificate_tampering()
        elif choice == "4":
            demo_4_expired_certificate()
        elif choice == "5":
            demo_5_fingerprint_comparison()
        elif choice == "6":
            demo_1_normal_operation()
            demo_2_mitm_attack()
            demo_3_certificate_tampering()
            demo_4_expired_certificate()
            demo_5_fingerprint_comparison()
        else:
            print("Invalid choice. Please enter 0-6.")

def main():
    print_header("CERTIFICATE VALIDATION DEMO")
    print("This demo shows how certificate validation prevents various attacks.")
    print("It demonstrates the security improvements in your secure chat application.")
    
    if len(sys.argv) > 1 and sys.argv[1] == "--all":
        # Run all demos automatically
        demo_1_normal_operation()
        demo_2_mitm_attack()
        demo_3_certificate_tampering()
        demo_4_expired_certificate()
        demo_5_fingerprint_comparison()
    else:
        # Interactive mode
        interactive_demo()

if __name__ == "__main__":
    main() 