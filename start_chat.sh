#!/bin/bash

# Get local IP address
LOCAL_IP=$(hostname -I | awk '{print $1}')

# Start chat server in background
echo "Starting chat server..."
python server.py &
CHAT_SERVER_PID=$!

# Wait for chat server to start
sleep 2

# Start Flask app
echo "Starting Flask application..."
python app.py

# Cleanup on exit
trap "kill $CHAT_SERVER_PID" EXIT 