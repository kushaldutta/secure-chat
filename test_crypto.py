from crypto_utils import generate_keys, serialize_public_key, derive_shared_key, encrypt_message, decrypt_message

# Simulate 2 users
priv1, pub1 = generate_keys()
priv2, pub2 = generate_keys()

# Exchange public keys
pub1_bytes = serialize_public_key(pub1)
pub2_bytes = serialize_public_key(pub2)

# Derive shared keys
key1 = derive_shared_key(priv1, pub2_bytes)
key2 = derive_shared_key(priv2, pub1_bytes)

# Test that both keys are the same
assert key1 == key2

# Encrypt and decrypt a message
msg = "Hello my name is Kushal"
ciphertext = encrypt_message(key1, msg)
plaintext = decrypt_message(key2, ciphertext)

print("Decrypted message:", plaintext)
