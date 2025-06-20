import socket
from crypto_utils import generate_keys, serialize_public_key, derive_shared_key, decrypt_message
import threading

HOST = '127.0.0.1'
PORT = 5000

def listen_for_messages(sock, aes_key):
    try:
        while True:
            encrypted_msg = sock.recv(4096)
            if not encrypted_msg:
                break
            plaintext = decrypt_message(aes_key, encrypted_msg)
            print(f"\n[Server] {plaintext}")
    except Exception as e:
        print("[!] Connection closed or error:", e)

def main():
    print("[*] Connecting to server...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    # Step 1: Key exchange
    priv_key, pub_key = generate_keys()
    server_pub_bytes = client_socket.recv(2048)         # receive server's pub key
    client_socket.sendall(serialize_public_key(pub_key)) # send our pub key
    aes_key = derive_shared_key(priv_key, server_pub_bytes)

    # Start thread to listen
    threading.Thread(target=listen_for_messages, args=(client_socket, aes_key), daemon=True).start()

    # Sending messages
    from crypto_utils import encrypt_message
    while True:
        msg = input("You: ")
        encrypted = encrypt_message(aes_key, msg)
        client_socket.sendall(encrypted)

if __name__ == "__main__":
    main()
