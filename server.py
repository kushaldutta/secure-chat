import socket
import threading
import json
import time
from crypto_utils import (
    generate_keys, serialize_public_key, derive_shared_key, 
    decrypt_message, encrypt_message, generate_session_id,
    get_key_fingerprint, CryptoError, generate_salt
)
from cert_utils import (
    generate_self_signed_certificate, serialize_certificate,
    save_certificate_fingerprint, CertError
)

HOST = '127.0.0.1'
PORT = 5000

class SecureChatServer:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.clients = {}  # {client_id: {'conn': socket, 'aes_key': key, 'username': str}}
        self.server_private_key, self.server_public_key = generate_keys()
        self.server_fingerprint = get_key_fingerprint(serialize_public_key(self.server_public_key))
        
        # Generate server certificate
        try:
            self.server_certificate = generate_self_signed_certificate(
                self.server_private_key, 
                self.server_public_key,
                f"Secure Chat Server ({self.host}:{self.port})"
            )
            self.certificate_fingerprint = save_certificate_fingerprint(self.server_certificate)
            print(f"[+] Server certificate generated with fingerprint: {self.certificate_fingerprint}")
        except CertError as e:
            print(f"[!] Failed to generate certificate: {e}")
            raise
        
    def start(self):
        """Start the secure chat server"""
        print(f"[*] Starting Secure Chat Server on {self.host}:{self.port}")
        print(f"[*] Server Key Fingerprint: {self.server_fingerprint}")
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"[+] Server listening on {self.host}:{self.port}")
            
            while True:
                client_socket, address = server_socket.accept()
                print(f"[+] New connection from {address}")
                
                # Handle each client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[!] Server shutting down...")
        except Exception as e:
            print(f"[!] Server error: {e}")
        finally:
            server_socket.close()
    
    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        client_id = generate_session_id()
        username = f"User-{client_id[:8]}"  # Default username
        
        try:
            # Step 1: Key exchange
            print(f"[*] Performing key exchange with {address}")
            
            # Generate salt for key derivation
            salt = generate_salt()
            
            # Send server's certificate (contains public key)
            server_cert_bytes = serialize_certificate(self.server_certificate)
            client_socket.sendall(server_cert_bytes)
            
            # Receive client's public key
            client_pub_key_bytes = client_socket.recv(2048)
            if not client_pub_key_bytes:
                raise CryptoError("No public key received from client")
            
            # Send salt to client
            client_socket.sendall(salt)
            
            # Derive shared key using the salt
            aes_key, _ = derive_shared_key(self.server_private_key, client_pub_key_bytes, salt)
            client_fingerprint = get_key_fingerprint(client_pub_key_bytes)
            
            print(f"[+] Key exchange completed with {address}")
            print(f"[+] Client fingerprint: {client_fingerprint}")
            
            # Receive client's username
            try:
                username_data = client_socket.recv(1024)
                if username_data:
                    received_username = decrypt_message(aes_key, username_data)
                    if received_username and received_username.strip():
                        username = received_username.strip()
                        print(f"[+] Client username: {username}")
            except Exception as e:
                print(f"[!] Failed to receive username, using default: {e}")
            
            # Store client information
            self.clients[client_id] = {
                'conn': client_socket,
                'aes_key': aes_key,
                'username': username,
                'address': address,
                'fingerprint': client_fingerprint,
                'connected_at': time.time()
            }
            
            # Send welcome message
            welcome_msg = f"Welcome to Secure Chat! Your session ID: {client_id[:8]}"
            encrypted_welcome = encrypt_message(aes_key, welcome_msg)
            client_socket.sendall(encrypted_welcome)
            
            # Broadcast client joined
            self.broadcast_message(f"{username} joined the chat", exclude_client_id=client_id)
            
            # Handle incoming messages
            self.receive_messages(client_id)
            
        except CryptoError as e:
            print(f"[!] Cryptographic error with {address}: {e}")
        except Exception as e:
            print(f"[!] Error handling client {address}: {e}")
        finally:
            self.remove_client(client_id)
    
    def receive_messages(self, client_id):
        """Receive and process messages from a client"""
        if client_id not in self.clients:
            return
            
        client_info = self.clients[client_id]
        client_socket = client_info['conn']
        aes_key = client_info['aes_key']
        
        try:
            while True:
                encrypted_data = client_socket.recv(4096)
                if not encrypted_data:
                    break
                
                # Decrypt message
                try:
                    message = decrypt_message(aes_key, encrypted_data)
                    
                    # Check if this is a username change message
                    if message.startswith("USERNAME_CHANGE:"):
                        # Parse username change
                        parts = message.split(":")
                        if len(parts) == 3:
                            old_username = parts[1]
                            new_username = parts[2]
                            
                            # Update username in server records
                            client_info['username'] = new_username
                            
                            # Broadcast username change to other clients
                            change_notification = f"{old_username} changed their username to {new_username}"
                            self.broadcast_message(change_notification, exclude_client_id=client_id)
                            
                            print(f"[*] {old_username} changed username to {new_username}")
                            continue
                    
                    # Regular message - use current username from client_info
                    current_username = client_info['username']
                    print(f"\n[{current_username}] {message}")
                    
                    # Broadcast to other clients with current username
                    self.broadcast_message(f"{current_username}: {message}", exclude_client_id=client_id)
                    
                except CryptoError as e:
                    print(f"[!] Failed to decrypt message from {client_info['username']}: {e}")
                    continue
                    
        except Exception as e:
            print(f"[!] Error receiving messages from {client_info['username']}: {e}")
    
    def broadcast_message(self, message, exclude_client_id=None):
        """Broadcast message to all connected clients"""
        disconnected_clients = []
        
        for client_id, client_info in self.clients.items():
            if client_id == exclude_client_id:
                continue
                
            try:
                encrypted_msg = encrypt_message(client_info['aes_key'], message)
                client_info['conn'].sendall(encrypted_msg)
            except Exception as e:
                print(f"[!] Failed to send message to {client_info['username']}: {e}")
                disconnected_clients.append(client_id)
        
        # Remove disconnected clients
        for client_id in disconnected_clients:
            self.remove_client(client_id)
    
    def remove_client(self, client_id):
        """Remove a client from the server"""
        if client_id in self.clients:
            client_info = self.clients[client_id]
            username = client_info['username']
            
            try:
                client_info['conn'].close()
            except:
                pass
            
            del self.clients[client_id]
            print(f"[-] {username} disconnected")
            
            # Broadcast client left
            self.broadcast_message(f"{username} left the chat")
    
    def get_client_count(self):
        """Get the number of connected clients"""
        return len(self.clients)
    
    def list_clients(self):
        """List all connected clients"""
        print(f"\n[*] Connected clients ({self.get_client_count()}):")
        for client_id, client_info in self.clients.items():
            uptime = int(time.time() - client_info['connected_at'])
            print(f"  - {client_info['username']} ({client_info['address']}) - {uptime}s")

def main():
    server = SecureChatServer()
    
    # Start server in a separate thread
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    
    # Command interface for server admin
    print("\n[*] Server commands:")
    print("  'clients' - List connected clients")
    print("  'quit' - Shutdown server")
    print("  'help' - Show this help")
    
    try:
        while True:
            command = input("\nServer> ").strip().lower()
            
            if command == 'clients':
                server.list_clients()
            elif command == 'quit':
                print("[!] Shutting down server...")
                break
            elif command == 'help':
                print("Available commands:")
                print("  'clients' - List connected clients")
                print("  'quit' - Shutdown server")
                print("  'help' - Show this help")
            elif command:
                print(f"Unknown command: {command}")
                
    except KeyboardInterrupt:
        print("\n[!] Shutting down server...")

if __name__ == "__main__":
    main()
