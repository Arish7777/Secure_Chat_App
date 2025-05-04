import socket
import threading
import json
import logging
import time
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SecureChatServer')

class ChatServer:
    def __init__(self, host='0.0.0.0', port=5555):
        """Initialize the chat server"""
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # {client_addr: {'socket': socket_obj, 'username': username, 'public_key': key}}
        self.running = False
        
        # Generate server's RSA keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        logger.info("Server RSA keys generated")
    
    def get_public_key_bytes(self):
        """Return the server's public key in bytes format for sharing"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def start(self):
        """Start the chat server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)  # Maximum number of queued connections
            
            self.running = True
            logger.info(f"Server started on {self.host}:{self.port}")
            
            self.accept_connections()
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            self.stop()
    
    def stop(self):
        """Stop the chat server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        
        # Close all client connections
        for client_info in self.clients.values():
            if client_info['socket']:
                client_info['socket'].close()
        
        self.clients = {}
        logger.info("Server stopped")
    
    def accept_connections(self):
        """Accept incoming client connections"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f"New connection from {client_address}")
                
                # Start a new thread to handle this client
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")
                    time.sleep(0.1)  # Prevent CPU overload on error
    
    def handle_client(self, client_socket, client_address):
        """Handle communication with a client"""
        try:
            # First, perform initial key exchange
            self.key_exchange(client_socket, client_address)
            
            # Then handle messages
            while self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        raise ConnectionError("Client disconnected")
                    
                    # Process the message
                    self.process_message(data, client_address)
                except ConnectionError as e:
                    logger.info(f"Client {client_address} disconnected: {e}")
                    break
                except Exception as e:
                    logger.error(f"Error handling message from {client_address}: {e}")
        except Exception as e:
            logger.error(f"Error handling client {client_address}: {e}")
        finally:
            # Clean up when client disconnects
            username = self.clients.get(client_address, {}).get('username', 'Unknown')
            if client_address in self.clients:
                client_socket.close()
                del self.clients[client_address]
            
            # Notify other clients about the disconnection
            self.broadcast_user_status(username, False)
            logger.info(f"Connection with {username} ({client_address}) closed")
    
    def key_exchange(self, client_socket, client_address):
        """Perform key exchange with a client"""
        try:
            # Send server's public key
            server_public_key_bytes = self.get_public_key_bytes()
            client_socket.send(server_public_key_bytes)
            
            # Receive client's public key
            client_public_key_bytes = client_socket.recv(4096)
            client_public_key = serialization.load_pem_public_key(
                client_public_key_bytes,
                backend=default_backend()
            )
            
            # Receive client's username (encrypted with the server's public key)
            encrypted_username = client_socket.recv(4096)
            username_bytes = self.private_key.decrypt(
                encrypted_username,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            username = username_bytes.decode('utf-8')
            
            # Store client information
            self.clients[client_address] = {
                'socket': client_socket,
                'username': username,
                'public_key': client_public_key
            }
            
            logger.info(f"Key exchange completed with {username} ({client_address})")
            
            # Notify client that authentication was successful
            auth_success_msg = json.dumps({
                'type': 'auth_success', 
                'message': f'Welcome, {username}!'
            }).encode('utf-8')
            
            encrypted_msg = client_public_key.encrypt(
                auth_success_msg,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            client_socket.send(encrypted_msg)
            
            # Send list of active users to the new client
            active_users = [info['username'] for info in self.clients.values()]
            user_list_msg = json.dumps({
                'type': 'user_list',
                'users': active_users
            }).encode('utf-8')
            
            encrypted_user_list = client_public_key.encrypt(
                user_list_msg,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            client_socket.send(encrypted_user_list)
            
            # Notify other clients about the new user
            self.broadcast_user_status(username, True)
            
        except Exception as e:
            logger.error(f"Key exchange failed with {client_address}: {e}")
            raise
    
    def process_message(self, encrypted_data, sender_address):
        """Process a message received from a client"""
        try:
            # Decrypt the message using server's private key
            decrypted_data = self.private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            message = json.loads(decrypted_data.decode('utf-8'))
            sender_username = self.clients[sender_address]['username']
            
            if message['type'] == 'broadcast':
                # Broadcast message to all clients
                self.broadcast_message(sender_username, message['content'], message.get('file_data'))
            elif message['type'] == 'direct':
                # Send direct message to specific user
                self.direct_message(
                    sender_username, 
                    message['recipient'], 
                    message['content'],
                    message.get('file_data')
                )
            elif message['type'] == 'status':
                # Handle status update
                logger.info(f"Status update from {sender_username}: {message['status']}")
            else:
                logger.warning(f"Unknown message type from {sender_username}: {message['type']}")
                
        except Exception as e:
            logger.error(f"Error processing message from {sender_address}: {e}")
    
    def broadcast_message(self, sender, content, file_data=None):
        """Send a message to all connected clients"""
        for client_addr, client_info in self.clients.items():
            message = {
                'type': 'message',
                'sender': sender,
                'content': content,
                'timestamp': time.time(),
                'broadcast': True
            }
            
            if file_data:
                message['file_data'] = file_data
                message['has_file'] = True
            
            self.send_to_client(client_addr, message)
    
    def direct_message(self, sender, recipient, content, file_data=None):
        """Send a direct message to a specific client"""
        recipient_addr = None
        
        # Find the recipient's address
        for addr, info in self.clients.items():
            if info['username'] == recipient:
                recipient_addr = addr
                break
        
        if recipient_addr:
            message = {
                'type': 'direct_message',
                'sender': sender,
                'content': content,
                'timestamp': time.time()
            }
            
            if file_data:
                message['file_data'] = file_data
                message['has_file'] = True
                
            self.send_to_client(recipient_addr, message)
            
            # Also send a confirmation to the sender if it's not the sender
            sender_addr = None
            for addr, info in self.clients.items():
                if info['username'] == sender:
                    sender_addr = addr
                    break
            
            if sender_addr and sender_addr != recipient_addr:
                confirm_message = {
                    'type': 'message_delivered',
                    'recipient': recipient,
                    'timestamp': time.time()
                }
                self.send_to_client(sender_addr, confirm_message)
        else:
            # Notify sender that recipient was not found
            sender_addr = None
            for addr, info in self.clients.items():
                if info['username'] == sender:
                    sender_addr = addr
                    break
            
            if sender_addr:
                error_message = {
                    'type': 'error',
                    'error': 'recipient_not_found',
                    'message': f"User {recipient} not found or offline"
                }
                self.send_to_client(sender_addr, error_message)
    
    def broadcast_user_status(self, username, is_online):
        """Broadcast a user's status (online/offline) to all clients"""
        status_message = {
            'type': 'user_status',
            'username': username,
            'status': 'online' if is_online else 'offline',
            'timestamp': time.time()
        }
        
        # Create a copy of the clients dictionary to avoid modification during iteration
        clients_copy = dict(self.clients)
        for client_addr, client_info in clients_copy.items():
            if client_info['username'] != username:  # Don't need to send to the user themselves
                try:
                    self.send_to_client(client_addr, status_message)
                except Exception as e:
                    logger.error(f"Failed to send status update to {client_addr}: {e}")
                    # Remove disconnected client
                    if client_addr in self.clients:
                        del self.clients[client_addr]
    
    def send_to_client(self, client_addr, message):
        """Encrypt and send a message to a specific client"""
        try:
            if client_addr in self.clients:
                client_info = self.clients[client_addr]
                json_message = json.dumps(message).encode('utf-8')
                
                # Encrypt the message with the client's public key
                encrypted_message = client_info['public_key'].encrypt(
                    json_message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                client_info['socket'].send(encrypted_message)
        except Exception as e:
            logger.error(f"Failed to send message to {client_addr}: {e}")


if __name__ == "__main__":
    server = ChatServer(host='0.0.0.0', port=5555)
    try:
        server.start()
    except KeyboardInterrupt:
        print("Server shutdown requested...")
    finally:
        server.stop()