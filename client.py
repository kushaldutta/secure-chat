import socket
import threading
import time
import sys
from crypto_utils import (
    generate_keys, serialize_public_key, derive_shared_key, 
    decrypt_message, encrypt_message, get_key_fingerprint, CryptoError
)

HOST = '127.0.0.1'
PORT = 5000

class SecureChatClient:
    def __init__(self, host=HOST, port=PORT, username=None):
        self.host = host
        self.port = port
        self.username = username or f"User-{int(time.time()) % 10000}"
        self.client_socket = None
        self.aes_key = None
        self.server_fingerprint = None
        self.connected = False
        self.session_id = None
        
    def connect(self):
        """Connect to the secure chat server"""
        try:
            print(f"[*] Connecting to {self.host}:{self.port}...")
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            
            # Perform key exchange
            self._perform_key_exchange()
            
            # Send our username to the server
            encrypted_username = encrypt_message(self.aes_key, self.username)
            self.client_socket.sendall(encrypted_username)
            
            # Receive welcome message
            welcome_data = self.client_socket.recv(4096)
            if welcome_data:
                welcome_msg = decrypt_message(self.aes_key, welcome_data)
                print(f"[+] {welcome_msg}")
                
            self.connected = True
            return True
            
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False
    
    def _perform_key_exchange(self):
        """Perform ECDH key exchange with the server"""
        print("[*] Performing key exchange...")
        
        # Generate our key pair
        self.private_key, self.public_key = generate_keys()
        self.client_fingerprint = get_key_fingerprint(serialize_public_key(self.public_key))
        
        # Receive server's public key
        server_pub_key_bytes = self.client_socket.recv(2048)
        if not server_pub_key_bytes:
            raise CryptoError("No public key received from server")
        
        # Send our public key
        self.client_socket.sendall(serialize_public_key(self.public_key))
        
        # Receive salt from server
        salt = self.client_socket.recv(32)
        if len(salt) != 32:
            raise CryptoError("Invalid salt received from server")
        
        # Derive shared key using the received salt
        self.aes_key, _ = derive_shared_key(self.private_key, server_pub_key_bytes, salt)
        self.server_fingerprint = get_key_fingerprint(server_pub_key_bytes)
        
        print(f"[+] Key exchange completed!")
        print(f"[+] Server fingerprint: {self.server_fingerprint}")
        print(f"[+] Client fingerprint: {self.client_fingerprint}")
    
    def start(self):
        """Start the chat client"""
        if not self.connect():
            return
        
        print(f"\n[*] Connected to secure chat server")
        print(f"[*] Your username: {self.username}")
        print(f"[*] Type 'help' for available commands")
        print(f"[*] Type 'quit' to disconnect\n")
        
        # Start listening thread
        listen_thread = threading.Thread(target=self._listen_for_messages, daemon=True)
        listen_thread.start()
        
        # Main input loop
        try:
            while self.connected:
                try:
                    message = input(f"{self.username}> ").strip()
                    
                    if not message:
                        continue
                    
                    if message.lower() == 'quit':
                        print("[*] Disconnecting...")
                        break
                    elif message.lower() == 'help':
                        self._show_help()
                    elif message.lower() == 'status':
                        self._show_status()
                    elif message.lower().startswith('/'):
                        # Handle special commands
                        self._handle_command(message)
                    else:
                        # Send regular message
                        self._send_message(message)
                        
                except KeyboardInterrupt:
                    print("\n[*] Disconnecting...")
                    break
                except Exception as e:
                    print(f"[!] Error: {e}")
                    
        finally:
            self.disconnect()
    
    def _listen_for_messages(self):
        """Listen for incoming messages from the server"""
        try:
            while self.connected:
                encrypted_data = self.client_socket.recv(4096)
                if not encrypted_data:
                    print("[!] Server disconnected")
                    break
                
                try:
                    message = decrypt_message(self.aes_key, encrypted_data)
                    print(f"\n{message}")
                    print(f"{self.username}> ", end='', flush=True)
                except CryptoError as e:
                    print(f"\n[!] Failed to decrypt message: {e}")
                    print(f"{self.username}> ", end='', flush=True)
                    
        except Exception as e:
            if self.connected:
                print(f"\n[!] Connection error: {e}")
    
    def _send_message(self, message):
        """Send an encrypted message to the server"""
        try:
            encrypted_msg = encrypt_message(self.aes_key, message)
            self.client_socket.sendall(encrypted_msg)
        except Exception as e:
            print(f"[!] Failed to send message: {e}")
    
    def _handle_command(self, command):
        """Handle special commands"""
        cmd_parts = command.split()
        cmd = cmd_parts[0].lower()
        
        if cmd == '/username' and len(cmd_parts) > 1:
            old_username = self.username
            new_username = cmd_parts[1]
            self.username = new_username
            
            # Send username change message to server
            change_message = f"USERNAME_CHANGE:{old_username}:{new_username}"
            self._send_message(change_message)
            
            print(f"[*] Username changed from {old_username} to {new_username}")
        elif cmd == '/fingerprint':
            print(f"[*] Server fingerprint: {self.server_fingerprint}")
            print(f"[*] Client fingerprint: {self.client_fingerprint}")
        elif cmd == '/ping':
            start_time = time.time()
            self._send_message("PING")
            print(f"[*] PING sent (response time will be shown when received)")
        else:
            print(f"[!] Unknown command: {cmd}")
    
    def _show_help(self):
        """Show available commands"""
        print("\nAvailable commands:")
        print("  /username <name>  - Change your username")
        print("  /fingerprint     - Show key fingerprints")
        print("  /ping           - Send ping to server")
        print("  status          - Show connection status")
        print("  help            - Show this help")
        print("  quit            - Disconnect from server")
        print()
    
    def _show_status(self):
        """Show connection status"""
        print(f"\nConnection Status:")
        print(f"  Server: {self.host}:{self.port}")
        print(f"  Username: {self.username}")
        print(f"  Connected: {self.connected}")
        print(f"  Server Fingerprint: {self.server_fingerprint}")
        print(f"  Client Fingerprint: {self.client_fingerprint}")
        print()
    
    def disconnect(self):
        """Disconnect from the server"""
        self.connected = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        print("[*] Disconnected from server")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure Chat Client')
    parser.add_argument('--host', default=HOST, help='Server host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=PORT, help='Server port (default: 5000)')
    parser.add_argument('--username', help='Your username')
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("🔐 SECURE CHAT CLIENT")
    print("=" * 50)
    
    client = SecureChatClient(
        host=args.host,
        port=args.port,
        username=args.username
    )
    
    try:
        client.start()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    main()
