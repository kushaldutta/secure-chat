#!/usr/bin/env python3
"""
Demo script showcasing the secure chat cryptographic features.
This demonstrates the key exchange, encryption, and security features.
"""

import time
import threading
from crypto_utils import (
    generate_keys, serialize_public_key, derive_shared_key,
    encrypt_message, decrypt_message, get_key_fingerprint,
    generate_session_id, CryptoError
)

def demo_key_exchange():
    """Demonstrate ECDH key exchange between two parties"""
    print("🔑 DEMO: Elliptic Curve Diffie-Hellman Key Exchange")
    print("=" * 60)
    
    # Simulate Alice and Bob
    print("Alice and Bob want to establish a secure communication channel...")
    
    # Generate key pairs
    alice_priv, alice_pub = generate_keys()
    bob_priv, bob_pub = generate_keys()
    
    print(f"✅ Alice generated her key pair")
    print(f"✅ Bob generated his key pair")
    
    # Exchange public keys
    alice_pub_bytes = serialize_public_key(alice_pub)
    bob_pub_bytes = serialize_public_key(bob_pub)
    
    alice_fingerprint = get_key_fingerprint(alice_pub_bytes)
    bob_fingerprint = get_key_fingerprint(bob_pub_bytes)
    
    print(f"📤 Alice sends her public key to Bob (fingerprint: {alice_fingerprint})")
    print(f"📤 Bob sends his public key to Alice (fingerprint: {bob_fingerprint})")
    
    # Derive shared keys
    alice_shared_key, alice_salt = derive_shared_key(alice_priv, bob_pub_bytes)
    bob_shared_key, bob_salt = derive_shared_key(bob_priv, alice_pub_bytes)
    
    # Verify both parties have the same key
    if alice_shared_key == bob_shared_key:
        print("✅ SUCCESS: Both parties derived the same shared key!")
        print(f"   Shared key: {alice_shared_key.hex()[:32]}...")
        print(f"   Key length: {len(alice_shared_key)} bytes")
    else:
        print("❌ ERROR: Key exchange failed!")
        return None
    
    return alice_shared_key

def demo_encryption(shared_key):
    """Demonstrate AES-GCM encryption and decryption"""
    print("\n🔐 DEMO: AES-GCM Authenticated Encryption")
    print("=" * 60)
    
    messages = [
        "Hello, this is a secret message!",
        "The quick brown fox jumps over the lazy dog.",
        "🚀 Secure communication is awesome! 🔐",
        "This message contains special characters: !@#$%^&*()_+"
    ]
    
    for i, message in enumerate(messages, 1):
        print(f"\n📝 Message {i}: '{message}'")
        
        # Encrypt
        encrypted = encrypt_message(shared_key, message)
        print(f"🔒 Encrypted: {len(encrypted)} bytes")
        
        # Decrypt
        decrypted = decrypt_message(shared_key, encrypted)
        print(f"🔓 Decrypted: '{decrypted}'")
        
        # Verify
        if message == decrypted:
            print("✅ SUCCESS: Message encrypted and decrypted correctly!")
        else:
            print("❌ ERROR: Message corruption detected!")

def demo_security_features(shared_key):
    """Demonstrate security features like tampering detection"""
    print("\n🛡️ DEMO: Security Features")
    print("=" * 60)
    
    # Test tampering detection
    print("Testing tampering detection...")
    original_msg = "This is a secret message"
    encrypted = encrypt_message(shared_key, original_msg)
    
    # Try to modify the encrypted data
    if isinstance(encrypted, bytes):
        modified = encrypted[:-1] + b'X'
        try:
            decrypt_message(shared_key, modified)
            print("❌ ERROR: Tampering not detected!")
        except CryptoError as e:
            print("✅ SUCCESS: Tampering detected and rejected!")
            print(f"   Error: {e}")
    
    # Test wrong key
    print("\nTesting wrong key rejection...")
    wrong_key = b'0' * 32
    try:
        decrypt_message(wrong_key, encrypted)
        print("❌ ERROR: Wrong key not rejected!")
    except CryptoError as e:
        print("✅ SUCCESS: Wrong key rejected!")
        print(f"   Error: {e}")

def demo_session_management():
    """Demonstrate session management features"""
    print("\n🆔 DEMO: Session Management")
    print("=" * 60)
    
    # Generate session IDs
    session_ids = [generate_session_id() for _ in range(5)]
    
    print("Generated session IDs:")
    for i, session_id in enumerate(session_ids, 1):
        print(f"   Session {i}: {session_id}")
    
    # Verify uniqueness
    unique_ids = set(session_ids)
    if len(unique_ids) == len(session_ids):
        print("✅ SUCCESS: All session IDs are unique!")
    else:
        print("❌ ERROR: Duplicate session IDs detected!")

def demo_performance():
    """Demonstrate performance characteristics"""
    print("\n⚡ DEMO: Performance Characteristics")
    print("=" * 60)
    
    # Generate keys for testing
    priv, pub = generate_keys()
    pub_bytes = serialize_public_key(pub)
    
    # Test key derivation performance
    print("Testing key derivation performance...")
    start_time = time.time()
    for _ in range(50):
        derive_shared_key(priv, pub_bytes)
    key_time = time.time() - start_time
    print(f"✅ 50 key derivations: {key_time:.3f}s ({50/key_time:.1f} ops/sec)")
    
    # Test encryption/decryption performance
    shared_key, salt = derive_shared_key(priv, pub_bytes)
    test_msg = "Performance test message"
    
    print("Testing encryption/decryption performance...")
    start_time = time.time()
    for _ in range(500):
        encrypted = encrypt_message(shared_key, test_msg)
        decrypt_message(shared_key, encrypted)
    crypto_time = time.time() - start_time
    print(f"✅ 500 encrypt/decrypt cycles: {crypto_time:.3f}s ({500/crypto_time:.1f} ops/sec)")

def main():
    """Run the complete demo"""
    print("🔐 SECURE CHAT CRYPTOGRAPHIC DEMO")
    print("=" * 60)
    print("This demo showcases the cryptographic features of the secure chat system.")
    print()
    
    try:
        # Run all demos
        shared_key = demo_key_exchange()
        if shared_key:
            demo_encryption(shared_key)
            demo_security_features(shared_key)
        demo_session_management()
        demo_performance()
        
        print("\n" + "=" * 60)
        print("🎉 DEMO COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print("\nKey features demonstrated:")
        print("✅ Elliptic Curve Diffie-Hellman key exchange")
        print("✅ AES-GCM authenticated encryption")
        print("✅ Message integrity and tampering detection")
        print("✅ Session management with unique IDs")
        print("✅ Performance characteristics")
        print("\nThe secure chat system is ready to use!")
        print("Run 'python server.py' to start the server")
        print("Run 'python client.py' to connect a client")
        
    except Exception as e:
        print(f"\n❌ DEMO FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 