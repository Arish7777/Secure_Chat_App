import socket
import threading
import json
import logging
import time
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SecureChatClient')

class ChatClient:
    def __init__(self, username, server_host='localhost', server_port=5555):
        """Initialize the chat client"""
        self.username = username
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = None
        self.connected = False
        self.message_callback = None
        self.status_callback = None
        
        # Generate client's RSA keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Server's public key (to be received from server)
        self.server_public_key = None
        
        logger.info(f"Client keys generated for {username}")
    
    def get_public_key_bytes(self):
        """Return the client's public key in bytes format for sharing"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def connect(self):
        """Connect to the chat server"""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_host, self.server_port))
            logger.info(f"Connected to server at {self.server_host}:{self.server_port}")
            
            # Perform key exchange with server
            if self.key_exchange():
                self.connected = True
                
                # Start listening for messages from server
                receive_thread = threading.Thread(target=self.receive_messages)
                receive_thread.daemon = True
                receive_thread.start()
                
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to connect to server: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the chat server"""
        self.connected = False
        if self.client_socket:
            self.client_socket.close()
            self.client_socket = None
        logger.info("Disconnected from server")
    
    def key_exchange(self):
        """Perform key exchange with the server"""
        try:
            # Receive server's public key
            server_public_key_bytes = self.client_socket.recv(4096)
            self.server_public_key = serialization.load_pem_public_key(
                server_public_key_bytes,
                backend=default_backend()
            )
            logger.info("Received server's public key")
            
            # Send client's public key
            self.client_socket.send(self.get_public_key_bytes())
            logger.info("Sent client's public key")
            
            # Send encrypted username
            encrypted_username = self.server_public_key.encrypt(
                self.username.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.client_socket.send(encrypted_username)
            logger.info("Sent encrypted username")
            
            # Wait for authentication response
            encrypted_response = self.client_socket.recv(4096)
            decrypted_response = self.private_key.decrypt(
                encrypted_response,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            response = json.loads(decrypted_response.decode('utf-8'))
            
            if response.get('type') == 'auth_success':
                logger.info(f"Authentication successful: {response.get('message')}")
                return True
            else:
                logger.error(f"Authentication failed: {response.get('message')}")
                return False
        except Exception as e:
            logger.error(f"Key exchange failed: {e}")
            return False
    
    def receive_messages(self):
        """Listen for messages from the server"""
        while self.connected:
            try:
                encrypted_data = self.client_socket.recv(4096)
                if not encrypted_data:
                    logger.info("Server disconnected")
                    self.disconnect()
                    break
                
                # Decrypt the message using the client's private key
                decrypted_data = self.private_key.decrypt(
                    encrypted_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                message = json.loads(decrypted_data.decode('utf-8'))
                self.process_message(message)
            except socket.error as e:
                if self.connected:
                    logger.error(f"Socket error: {e}")
                    self.disconnect()
                break
            except Exception as e:
                logger.error(f"Error receiving message: {e}")
                time.sleep(0.1)  # Prevent CPU overload on error
    
    def process_message(self, message):
        """Process a received message"""
        try:
            if message.get('type') == 'message' or message.get('type') == 'direct_message':
                # Call the message callback function if set
                if self.message_callback:
                    self.message_callback(message)
                else:
                    # Default behavior: just print the message
                    sender = message.get('sender', 'Unknown')
                    content = message.get('content', '')
                    is_direct = message.get('type') == 'direct_message'
                    has_file = message.get('has_file', False)
                    
                    msg_type = "Direct message" if is_direct else "Message"
                    file_info = " (with file)" if has_file else ""
                    
                    logger.info(f"{msg_type} from {sender}{file_info}: {content}")
            
            elif message.get('type') == 'user_status' or message.get('type') == 'user_list':
                # Call the status callback function if set
                if self.status_callback:
                    self.status_callback(message)
                else:
                    # Default behavior: just print the status
                    if message.get('type') == 'user_status':
                        username = message.get('username', 'Unknown')
                        status = message.get('status', 'unknown')
                        logger.info(f"User {username} is now {status}")
                    elif message.get('type') == 'user_list':
                        users = message.get('users', [])
                        logger.info(f"Active users: {', '.join(users)}")
            
            elif message.get('type') == 'error':
                error_type = message.get('error', 'unknown')
                error_msg = message.get('message', 'Unknown error')
                logger.error(f"Error ({error_type}): {error_msg}")
            
            elif message.get('type') == 'message_delivered':
                recipient = message.get('recipient', 'Unknown')
                logger.info(f"Message delivered to {recipient}")
            
            else:
                logger.warning(f"Unknown message type: {message.get('type')}")
        
        except Exception as e:
            logger.error(f"Error processing message: {e}")
    
    def send_message(self, message_type, content, recipient=None, file_path=None):
        """Send a message to the server"""
        if not self.connected:
            logger.error("Not connected to server")
            return False
        
        try:
            message = {
                'type': message_type,
                'content': content
            }
            
            if message_type == 'direct':
                if not recipient:
                    logger.error("Recipient required for direct message")
                    return False
                message['recipient'] = recipient
            
            # Handle file attachments if provided
            if file_path and os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as file:
                        file_data = file.read()
                        file_name = os.path.basename(file_path)
                        # Base64 encode the file data
                        message['file_data'] = {
                            'name': file_name,
                            'data': base64.b64encode(file_data).decode('utf-8'),
                            'size': len(file_data)
                        }
                except Exception as e:
                    logger.error(f"Error reading file {file_path}: {e}")
                    return False
            
            # Encrypt the message with the server's public key
            json_message = json.dumps(message).encode('utf-8')
            encrypted_message = self.server_public_key.encrypt(
                json_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Send the encrypted message
            self.client_socket.send(encrypted_message)
            return True
        
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            return False
    
    def broadcast_message(self, content, file_path=None):
        """Send a message to all users"""
        return self.send_message('broadcast', content, file_path=file_path)
    
    def send_direct_message(self, recipient, content, file_path=None):
        """Send a direct message to a specific user"""
        return self.send_message('direct', content, recipient=recipient, file_path=file_path)
    
    def set_message_callback(self, callback):
        """Set a callback function to handle incoming messages"""
        self.message_callback = callback
    
    def set_status_callback(self, callback):
        """Set a callback function to handle status updates"""
        self.status_callback = callback


if __name__ == "__main__":
    # Simple command-line test client
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python client.py <username> [server_host] [server_port]")
        sys.exit(1)
    
    username = sys.argv[1]
    server_host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
    server_port = int(sys.argv[3]) if len(sys.argv) > 3 else 5555
    
    client = ChatClient(username, server_host, server_port)
    
    if client.connect():
        print(f"Connected to server as {username}!")
        
        # Simple message loop
        try:
            while True:
                cmd = input("\nEnter command (b: broadcast, d: direct, q: quit): ").strip().lower()
                
                if cmd == 'q':
                    break
                elif cmd == 'b':
                    message = input("Message: ")
                    client.broadcast_message(message)
                elif cmd == 'd':
                    recipient = input("Recipient: ")
                    message = input("Message: ")
                    client.send_direct_message(recipient, message)
                else:
                    print("Unknown command")
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            client.disconnect()
    else:
        print("Failed to connect to server")