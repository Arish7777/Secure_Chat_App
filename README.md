# Secure Chat Application

A secure, real-time chat application with end-to-end encryption, built using Flask, Flask-SocketIO, and custom client/server architecture.

## Features

- End-to-end encryption for all messages
- Real-time messaging with WebSocket support
- File sharing (up to 30MB)
- Voice note support
- User authentication
- Online/offline status
- Typing indicators
- Message persistence
- Mobile-responsive design

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/secure-chat.git
cd secure-chat
```

2. Create and activate a virtual environment:

```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On Unix or MacOS
source venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the Application

1. Start the application using the provided batch file:

```bash
# On Windows
start_chat.bat

# On Unix or MacOS
./start_chat.sh
```

2. Access the application:

- Local: http://localhost:8000
- Network: http://<your-ip>:8000

## Usage

1. Register a new account or login with existing credentials
2. Connect to the chat server using the default settings (localhost:5555)
3. Start chatting!

## Security Features

- End-to-end encryption using RSA
- Secure key exchange
- Password hashing with bcrypt
- Session management
- File encryption

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Flask and Flask-SocketIO for the web framework
- SQLAlchemy for database management
- Tailwind CSS for styling
- Font Awesome for icons
