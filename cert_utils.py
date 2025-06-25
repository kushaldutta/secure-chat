from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import datetime
import os
import base64
import ipaddress

class CertError(Exception):
    """Custom exception for certificate operations"""
    pass

def generate_self_signed_certificate(private_key, public_key, common_name="Secure Chat Server"):
    """Generate a self-signed certificate for the server"""
    try:
        # Create certificate subject and issuer (same for self-signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Chat"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        
        # Create certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        return cert
    except Exception as e:
        raise CertError(f"Failed to generate certificate: {e}")

def serialize_certificate(certificate):
    """Serialize certificate to PEM format"""
    try:
        return certificate.public_bytes(serialization.Encoding.PEM)
    except Exception as e:
        raise CertError(f"Failed to serialize certificate: {e}")

def deserialize_certificate(certificate_bytes):
    """Deserialize certificate from PEM format"""
    try:
        return x509.load_pem_x509_certificate(certificate_bytes)
    except Exception as e:
        raise CertError(f"Failed to deserialize certificate: {e}")

def get_certificate_fingerprint(certificate):
    """Generate SHA-256 fingerprint of certificate"""
    try:
        return certificate.fingerprint(hashes.SHA256()).hex()
    except Exception as e:
        raise CertError(f"Failed to generate certificate fingerprint: {e}")

def validate_certificate(certificate, expected_fingerprint=None):
    """Validate certificate and optionally check fingerprint"""
    try:
        # Check if certificate is expired
        now = datetime.datetime.utcnow()
        if now < certificate.not_valid_before or now > certificate.not_valid_after:
            raise CertError("Certificate is expired or not yet valid")
        
        # Check if certificate is self-signed (for our use case)
        if certificate.subject != certificate.issuer:
            raise CertError("Certificate is not self-signed")
        
        # Validate fingerprint if provided
        if expected_fingerprint:
            actual_fingerprint = get_certificate_fingerprint(certificate)
            if actual_fingerprint != expected_fingerprint:
                raise CertError(f"Certificate fingerprint mismatch. Expected: {expected_fingerprint}, Got: {actual_fingerprint}")
        
        return True
    except Exception as e:
        raise CertError(f"Certificate validation failed: {e}")

def extract_public_key_from_certificate(certificate):
    """Extract public key from certificate"""
    try:
        return certificate.public_key()
    except Exception as e:
        raise CertError(f"Failed to extract public key from certificate: {e}")

def save_certificate_fingerprint(certificate, filename="server_fingerprint.txt"):
    """Save certificate fingerprint to file for client verification"""
    try:
        fingerprint = get_certificate_fingerprint(certificate)
        with open(filename, 'w') as f:
            f.write(f"Server Certificate Fingerprint (SHA-256):\n{fingerprint}\n")
            f.write(f"Valid from: {certificate.not_valid_before}\n")
            f.write(f"Valid until: {certificate.not_valid_after}\n")
            f.write(f"Subject: {certificate.subject}\n")
        print(f"[+] Certificate fingerprint saved to {filename}")
        return fingerprint
    except Exception as e:
        raise CertError(f"Failed to save certificate fingerprint: {e}")

def load_expected_fingerprint(filename="server_fingerprint.txt"):
    """Load expected certificate fingerprint from file"""
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
            # Extract fingerprint from first line
            fingerprint_line = lines[1].strip()  # Skip header line
            return fingerprint_line
    except Exception as e:
        raise CertError(f"Failed to load expected fingerprint: {e}") 