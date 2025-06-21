from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hmac
from cryptography.exceptions import InvalidKey
import os
import base64
import json
import time

class CryptoError(Exception):
    """Custom exception for cryptographic operations"""
    pass

# Generate EC key pair (for ECDH)
def generate_keys():
    """Generate a new EC key pair using SECP384R1 curve"""
    try:
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        raise CryptoError(f"Failed to generate keys: {e}")

# Serialize public key to send it over the wire
def serialize_public_key(public_key):
    """Serialize public key to PEM format"""
    try:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception as e:
        raise CryptoError(f"Failed to serialize public key: {e}")

# Deserialize received public key
def deserialize_public_key(public_key_bytes):
    """Deserialize public key from PEM format"""
    try:
        return serialization.load_pem_public_key(public_key_bytes)
    except Exception as e:
        raise CryptoError(f"Failed to deserialize public key: {e}")

# Generate a random salt for key derivation
def generate_salt(length=32):
    """Generate a random salt for key derivation"""
    return os.urandom(length)

# Derive shared AES key using ECDH + HKDF with salt
def derive_shared_key(private_key, peer_public_key_bytes, salt=None):
    """Derive shared key using ECDH + HKDF with optional salt"""
    try:
        peer_public_key = deserialize_public_key(peer_public_key_bytes)
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        
        if salt is None:
            salt = generate_salt()
            
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'secure-chat-handshake',
        ).derive(shared_secret)
        
        return derived_key, salt
    except Exception as e:
        raise CryptoError(f"Failed to derive shared key: {e}")

# Encrypt message with AES-GCM and additional metadata
def encrypt_message(key, plaintext, additional_data=None):
    """Encrypt message with AES-GCM and optional additional data"""
    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        
        # Prepare additional data for authentication
        if additional_data is None:
            additional_data = b''
        
        # Encrypt the message
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), additional_data)
        
        # Create message structure with metadata
        message_data = {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'timestamp': int(time.time()),
            'version': '1.0'
        }
        
        return json.dumps(message_data).encode('utf-8')
    except Exception as e:
        raise CryptoError(f"Failed to encrypt message: {e}")

# Decrypt message with validation
def decrypt_message(key, encrypted_data, additional_data=None):
    """Decrypt message with AES-GCM and validate metadata"""
    try:
        # Parse the message structure
        if isinstance(encrypted_data, bytes):
            message_data = json.loads(encrypted_data.decode('utf-8'))
        else:
            message_data = encrypted_data
            
        nonce = base64.b64decode(message_data['nonce'])
        ciphertext = base64.b64decode(message_data['ciphertext'])
        
        # Validate timestamp (reject messages older than 5 minutes)
        current_time = int(time.time())
        if current_time - message_data['timestamp'] > 300:  # 5 minutes
            raise CryptoError("Message timestamp is too old")
        
        aesgcm = AESGCM(key)
        
        # Prepare additional data for authentication
        if additional_data is None:
            additional_data = b''
        
        # Decrypt the message
        plaintext = aesgcm.decrypt(nonce, ciphertext, additional_data)
        return plaintext.decode('utf-8')
    except Exception as e:
        raise CryptoError(f"Failed to decrypt message: {e}")

# Generate HMAC for message integrity
def generate_hmac(key, message):
    """Generate HMAC for message integrity verification"""
    try:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message)
        return h.finalize()
    except Exception as e:
        raise CryptoError(f"Failed to generate HMAC: {e}")

# Verify HMAC
def verify_hmac(key, message, signature):
    """Verify HMAC signature"""
    try:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message)
        h.verify(signature)
        return True
    except Exception as e:
        raise CryptoError(f"HMAC verification failed: {e}")

# Generate a secure random identifier
def generate_session_id():
    """Generate a secure random session identifier"""
    return base64.b64encode(os.urandom(16)).decode('utf-8')

# Key fingerprint for verification
def get_key_fingerprint(public_key_bytes):
    """Generate a fingerprint of the public key for verification"""
    try:
        import hashlib
        return hashlib.sha256(public_key_bytes).hexdigest()[:16]
    except Exception as e:
        raise CryptoError(f"Failed to generate key fingerprint: {e}")
