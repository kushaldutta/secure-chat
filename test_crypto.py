#!/usr/bin/env python3
"""
Comprehensive test suite for the secure chat cryptographic utilities.
This demonstrates various cryptographic concepts and validates the implementation.
"""

import time
import json
from crypto_utils import (
    generate_keys, serialize_public_key, derive_shared_key, 
    encrypt_message, decrypt_message, generate_salt, generate_session_id,
    get_key_fingerprint, generate_hmac, verify_hmac, CryptoError
)

def test_key_generation():
    print("🔑 Testing Key Generation...")
    priv1, pub1 = generate_keys()
    priv2, pub2 = generate_keys()
    pub1_bytes = serialize_public_key(pub1)
    pub2_bytes = serialize_public_key(pub2)
    assert pub1_bytes != pub2_bytes, "Generated keys should be different"
    print("✅ Key generation test passed")

def test_key_exchange():
    print("\n🤝 Testing Key Exchange...")
    alice_priv, alice_pub = generate_keys()
    bob_priv, bob_pub = generate_keys()
    alice_pub_bytes = serialize_public_key(alice_pub)
    bob_pub_bytes = serialize_public_key(bob_pub)
    
    # Alice generates salt and sends it to Bob
    salt = generate_salt()
    alice_shared_key, _ = derive_shared_key(alice_priv, bob_pub_bytes, salt)
    bob_shared_key, _ = derive_shared_key(bob_priv, alice_pub_bytes, salt)
    
    assert alice_shared_key == bob_shared_key, "Shared keys should be identical"
    print("✅ Key exchange test passed")
    print(f"   Shared key length: {len(alice_shared_key)} bytes")
    print(f"   Salt length: {len(salt)} bytes")

def test_encryption_decryption():
    print("\n🔐 Testing Encryption/Decryption...")
    priv1, pub1 = generate_keys()
    priv2, pub2 = generate_keys()
    pub1_bytes = serialize_public_key(pub1)
    pub2_bytes = serialize_public_key(pub2)
    
    # Use shared salt for key derivation
    salt = generate_salt()
    shared_key, _ = derive_shared_key(priv1, pub2_bytes, salt)
    
    test_messages = [
        "Hello, World!",
        "This is a test message with special characters: !@#$%^&*()",
        "Unicode test: 🚀🔐💻",
        "",
        "A" * 1000,
    ]
    for msg in test_messages:
        encrypted = encrypt_message(shared_key, msg)
        decrypted = decrypt_message(shared_key, encrypted)
        assert msg == decrypted, f"Message mismatch: '{msg}' != '{decrypted}'"
        print(f"✅ Encrypted/decrypted: '{msg[:50]}{'...' if len(msg) > 50 else ''}'")

def test_message_integrity():
    print("\n🛡️ Testing Message Integrity...")
    priv1, pub1 = generate_keys()
    priv2, pub2 = generate_keys()
    pub1_bytes = serialize_public_key(pub1)
    pub2_bytes = serialize_public_key(pub2)
    # Use shared salt for key derivation
    salt = generate_salt()
    shared_key, _ = derive_shared_key(priv1, pub2_bytes, salt)
    original_msg = "Secret message"
    encrypted = encrypt_message(shared_key, original_msg)
    decrypted = decrypt_message(shared_key, encrypted)
    assert decrypted == original_msg, "Decryption should work with correct key"
    wrong_key = b'0' * 32
    try:
        decrypt_message(wrong_key, encrypted)
        assert False, "Should have failed with wrong key"
    except CryptoError:
        print("✅ Tampering detection works (wrong key rejected)")
    encrypted_bytes = encrypted
    if isinstance(encrypted_bytes, bytes):
        modified = encrypted_bytes[:-1] + b'X'
        try:
            decrypt_message(shared_key, modified)
            assert False, "Should have failed with modified data"
        except CryptoError:
            print("✅ Tampering detection works (modified data rejected)")

def test_timestamp_validation():
    print("\n⏰ Testing Timestamp Validation...")
    priv1, pub1 = generate_keys()
    priv2, pub2 = generate_keys()
    pub1_bytes = serialize_public_key(pub1)
    pub2_bytes = serialize_public_key(pub2)
    # Use shared salt for key derivation
    salt = generate_salt()
    shared_key, _ = derive_shared_key(priv1, pub2_bytes, salt)
    msg = "Test message"
    encrypted = encrypt_message(shared_key, msg)
    decrypted = decrypt_message(shared_key, encrypted)
    assert decrypted == msg, "Fresh message should decrypt successfully"
    if isinstance(encrypted, bytes):
        message_data = json.loads(encrypted.decode('utf-8'))
        message_data['timestamp'] = int(time.time()) - 400
        old_encrypted = json.dumps(message_data).encode('utf-8')
        try:
            decrypt_message(shared_key, old_encrypted)
            assert False, "Should have rejected old message"
        except CryptoError as e:
            if "timestamp is too old" in str(e):
                print("✅ Timestamp validation works (old message rejected)")
            else:
                raise

def test_hmac_functionality():
    print("\n🔏 Testing HMAC Functionality...")
    key = b'secret_key_for_hmac_testing'
    message = b'This is a test message for HMAC'
    hmac_signature = generate_hmac(key, message)
    print(f"✅ HMAC generated: {len(hmac_signature)} bytes")
    assert verify_hmac(key, message, hmac_signature), "HMAC verification should succeed"
    print("✅ HMAC verification works")
    wrong_key = b'wrong_key_for_hmac_testing'
    try:
        verify_hmac(wrong_key, message, hmac_signature)
        assert False, "Should have failed with wrong key"
    except CryptoError:
        print("✅ HMAC verification fails with wrong key")
    modified_message = b'This is a modified message for HMAC'
    try:
        verify_hmac(key, modified_message, hmac_signature)
        assert False, "Should have failed with modified message"
    except CryptoError:
        print("✅ HMAC verification fails with modified message")

def test_utility_functions():
    print("\n🛠️ Testing Utility Functions...")
    salt1 = generate_salt(16)
    salt2 = generate_salt(32)
    assert len(salt1) == 16, "Salt should be 16 bytes"
    assert len(salt2) == 32, "Salt should be 32 bytes"
    assert salt1 != salt2, "Salts should be different"
    print("✅ Salt generation works")
    session_id1 = generate_session_id()
    session_id2 = generate_session_id()
    assert session_id1 != session_id2, "Session IDs should be different"
    print("✅ Session ID generation works")
    priv, pub = generate_keys()
    pub_bytes = serialize_public_key(pub)
    fingerprint = get_key_fingerprint(pub_bytes)
    assert len(fingerprint) == 16, "Fingerprint should be 16 characters"
    print("✅ Key fingerprint generation works")

def test_error_handling():
    print("\n⚠️ Testing Error Handling...")
    try:
        derive_shared_key(None, b'invalid_key_data')
        assert False, "Should have failed with invalid key"
    except CryptoError:
        print("✅ Invalid key handling works")
    try:
        decrypt_message(b'0' * 32, b'invalid_encrypted_data')
        assert False, "Should have failed with invalid encrypted data"
    except CryptoError:
        print("✅ Invalid encrypted data handling works")

def performance_test():
    print("\n⚡ Performance Test...")
    priv, pub = generate_keys()
    pub_bytes = serialize_public_key(pub)
    
    # Use shared salt for key derivation
    salt = generate_salt()
    
    start_time = time.time()
    for _ in range(100):
        derive_shared_key(priv, pub_bytes, salt)
    key_derivation_time = time.time() - start_time
    print(f"✅ 100 key derivations: {key_derivation_time:.3f}s")
    
    shared_key, _ = derive_shared_key(priv, pub_bytes, salt)
    test_msg = "Performance test message"
    start_time = time.time()
    for _ in range(1000):
        encrypted = encrypt_message(shared_key, test_msg)
        decrypt_message(shared_key, encrypted)
    crypto_time = time.time() - start_time
    print(f"✅ 1000 encrypt/decrypt cycles: {crypto_time:.3f}s")

def main():
    print("=" * 60)
    print("🔐 SECURE CHAT CRYPTOGRAPHIC TEST SUITE")
    print("=" * 60)
    try:
        test_key_generation()
        test_key_exchange()
        test_encryption_decryption()
        test_message_integrity()
        test_timestamp_validation()
        test_hmac_functionality()
        test_utility_functions()
        test_error_handling()
        performance_test()
        print("\n" + "=" * 60)
        print("🎉 ALL TESTS PASSED! 🎉")
        print("=" * 60)
        print("\nCryptographic features tested:")
        print("✅ Elliptic Curve Diffie-Hellman (ECDH) key exchange")
        print("✅ AES-GCM authenticated encryption")
        print("✅ HKDF key derivation with salt")
        print("✅ Message integrity and tampering detection")
        print("✅ Timestamp validation for replay protection")
        print("✅ HMAC for additional message authentication")
        print("✅ Error handling and validation")
        print("✅ Performance optimization")
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    return 0

if __name__ == "__main__":
    exit(main()) 