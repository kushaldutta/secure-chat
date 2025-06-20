import socket
from crypto_utils import generate_keys, serialize_public_key, derive_shared_key, decrypt_message
import threading

HOST = '127.0.0.1'
PORT = 5000

def handle_client(conn, aes_key):
    print("[+] Secure connection established.")
    try:
        while True:
            encrypted_msg = conn.recv(4096)
            if not encrypted_msg:
                break
            decrypted = decrypt_message(aes_key, encrypted_msg)
            print(f"\n[Client] {decrypted}")
    except Exception as e:
        print("[!] Connection closed or error:", e)

def main():
    print("[*] Starting server...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    conn, addr = server_socket.accept()
    print(f"[+] Connected by {addr}")

    # Step 1: Key exchange
    priv_key, pub_key = generate_keys()
    conn.sendall(serialize_public_key(pub_key))  # send our pub key
    client_pub_bytes = conn.recv(2048)           # receive client pub key
    aes_key = derive_shared_key(priv_key, client_pub_bytes)

    # Start thread to handle incoming messages
    threading.Thread(target=handle_client, args=(conn, aes_key), daemon=True).start()

    # Sending messages
    from crypto_utils import encrypt_message
    while True:
        msg = input("You: ")
        encrypted = encrypt_message(aes_key, msg)
        conn.sendall(encrypted)

if __name__ == "__main__":
    main()
