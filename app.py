from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_socketio import SocketIO, emit, disconnect
import os
import json
import bcrypt
import logging
import threading
import base64
from datetime import datetime
import time
from client import ChatClient
from flask_sqlalchemy import SQLAlchemy
from models import db, User, Message

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SecureChatFlask')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 30 * 1024 * 1024  # 30MB max upload size
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Allow all hosts
app.config['HOST'] = '0.0.0.0'
app.config['PORT'] = 8000

socketio = SocketIO(app, cors_allowed_origins="*")

db.init_app(app)

with app.app_context():
    db.create_all()

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Store active client connections
clients = {}
# Track online users by sid
online_users = {}  # sid -> username

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to chat
    if 'username' in session:
        return redirect(url_for('chat'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        logger.info(f"Login attempt for user: {username}")
        
        if not username or not password:
            flash('Please provide both username and password', 'danger')
            return render_template('login.html')
            
        user = User.query.filter_by(username=username).first()
        if user:
            if bcrypt.checkpw(password.encode('utf-8'), user.password):
                # Clear any existing session data
                session.clear()
                # Set new session data
                session['username'] = username
                session.permanent = True
                
                logger.info(f"Login successful for user: {username}")
                flash('Login successful!', 'success')
                return redirect(url_for('chat'))
            else:
                logger.warning(f"Invalid password for user: {username}")
                flash('Invalid password', 'danger')
        else:
            logger.warning(f"Username not found: {username}")
            flash('Username not found', 'danger')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match', 'danger')
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/chat')
def chat():
    if 'username' not in session:
        logger.warning("Access to chat page without session")
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    logger.info(f"Chat page accessed by user: {username}")
    
    try:
        # Fetch all broadcast messages and DMs for this user
        messages = Message.query.filter(
            (Message.type == 'broadcast') |
            ((Message.type == 'direct') & ((Message.sender == username) | (Message.recipient == username)))
        ).order_by(Message.timestamp.asc()).all()
        
        # Prepare messages for rendering
        messages_data = []
        for msg in messages:
            msg_dict = {
                'id': msg.id,
                'sender': msg.sender,
                'recipient': msg.recipient,
                'content': msg.content,
                'type': msg.type,
                'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'has_file': bool(msg.file_data),
                'file_name': msg.file_name,
                'file_mime': msg.file_mime,
                'file_data': base64.b64encode(msg.file_data).decode('utf-8') if msg.file_data else None
            }
            messages_data.append(msg_dict)
        
        return render_template('chat.html', username=username, messages=messages_data)
    except Exception as e:
        logger.error(f"Error loading chat page for {username}: {e}")
        flash('Error loading chat page. Please try again.', 'danger')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    username = session.get('username')
    if username:
        logger.info(f"Logout for user: {username}")
        # Disconnect from chat server if connected
        if username in clients:
            try:
                clients[username].disconnect()
            except Exception as e:
                logger.error(f"Error disconnecting client for {username}: {e}")
            finally:
                del clients[username]
    
    # Clear session
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@socketio.on('connect')
def handle_connect():
    if 'username' not in session:
        return False
    username = session['username']
    logger.info(f"WebSocket connection established for {username}")
    online_users[request.sid] = username
    emit('status', {'message': f'Welcome, {username}!'}, room=request.sid)
    broadcast_online_users()

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    username = online_users.get(sid)
    if username:
        if sid in clients:
            clients[sid].disconnect()
            del clients[sid]
        del online_users[sid]
        broadcast_online_users()

@socketio.on('connect_to_server')
def handle_connect_to_server(data):
    username = data.get('username')
    server_host = data.get('server_host', 'localhost')
    server_port = int(data.get('server_port', 5555))
    sid = request.sid
    if not username:
        emit('connection_error', {'message': 'Username required'})
        disconnect()
        return
    # Create a new chat client
    client = ChatClient(username, server_host, server_port)
    def message_callback(message):
        socketio.emit('message', message, room=sid)
    def status_callback(status):
        socketio.emit('status_update', status, room=sid)
    client.set_message_callback(message_callback)
    client.set_status_callback(status_callback)
    if client.connect():
        clients[sid] = client
        online_users[sid] = username
        emit('connection_success', {'message': f'Connected to chat server at {server_host}:{server_port}'})
        # Notify all clients about online users
        broadcast_online_users()
    else:
        emit('connection_error', {'message': f'Failed to connect to chat server at {server_host}:{server_port}'})
        disconnect()

@socketio.on('send_message')
def handle_send_message(data):
    sid = request.sid
    username = online_users.get(sid)
    if not username or sid not in clients:
        emit('error', {'message': 'Not connected to chat server'})
        return
    message_type = data.get('type', 'broadcast')
    content = data.get('content', '')
    recipient = data.get('recipient')
    file_data = data.get('file_data')
    file_path = None
    file_name = None
    file_mime = None
    file_bytes = None
    if file_data:
        try:
            file_bytes = base64.b64decode(file_data['data'])
            file_name = file_data['name']
            file_mime = file_data.get('type', None)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{int(time.time())}_{file_name}")
            with open(file_path, 'wb') as f:
                f.write(file_bytes)
        except Exception as e:
            logger.error(f"Error handling file upload: {e}")
            emit('error', {'message': f'Failed to process file: {str(e)}'})
            return
    # Save message to DB
    msg_db = Message(
        sender=username,
        recipient=recipient if message_type == 'direct' else None,
        content=content,
        type=message_type,
        file_name=file_name,
        file_data=file_bytes,
        file_mime=file_mime
    )
    db.session.add(msg_db)
    db.session.commit()
    # Send message based on type
    success = False
    if message_type == 'direct':
        success = clients[sid].send_direct_message(recipient, content, file_path)
    else:
        success = clients[sid].broadcast_message(content, file_path)
    if file_path and os.path.exists(file_path):
        os.remove(file_path)
    if success:
        emit('message_sent', {'content': content, 'recipient': recipient, 'type': message_type})
    else:
        emit('error', {'message': 'Failed to send message'})

def broadcast_online_users():
    # Send the list of online users to all connected clients
    all_users = User.query.all()
    users_data = [
        {
            'username': u.username,
            'online': u.username in online_users.values()
        }
        for u in all_users
    ]
    socketio.emit('status_update', {'type': 'user_list', 'users': users_data})

@app.route('/api/users')
def get_users():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    all_users = User.query.all()
    users_data = [
        {
            'username': u.username,
            'online': u.username in online_users.values()
        }
        for u in all_users
    ]
    return jsonify({'users': users_data})

@app.route('/api/messages')
def get_messages():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    username = session['username']
    chat_type = request.args.get('type', 'broadcast')
    recipient = request.args.get('recipient')
    if chat_type == 'broadcast':
        messages = Message.query.filter(Message.type == 'broadcast').order_by(Message.timestamp.asc()).all()
    elif chat_type == 'direct' and recipient:
        messages = Message.query.filter(
            (Message.type == 'direct') & (
                ((Message.sender == username) & (Message.recipient == recipient)) |
                ((Message.sender == recipient) & (Message.recipient == username))
            )
        ).order_by(Message.timestamp.asc()).all()
    else:
        return jsonify({'messages': []})
    messages_data = []
    for msg in messages:
        msg_dict = {
            'id': msg.id,
            'sender': msg.sender,
            'recipient': msg.recipient,
            'content': msg.content,
            'type': msg.type,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'has_file': bool(msg.file_data),
            'file_name': msg.file_name,
            'file_mime': msg.file_mime,
            'file_data': base64.b64encode(msg.file_data).decode('utf-8') if msg.file_data else None
        }
        messages_data.append(msg_dict)
    return jsonify({'messages': messages_data})

# Add a route to check session status
@app.route('/check_session')
def check_session():
    if 'username' in session:
        return jsonify({'logged_in': True, 'username': session['username']})
    return jsonify({'logged_in': False})

if __name__ == '__main__':
    # Get the local IP address
    import socket
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    print(f"\n=== Secure Chat Server ===")
    print(f"Local URL: http://localhost:8000")
    print(f"Network URL: http://{local_ip}:8000")
    print("========================\n")
    
    socketio.run(app, host=app.config['HOST'], port=app.config['PORT'], debug=True)