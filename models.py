from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Initialize SQLAlchemy (to be initialized with app in app.py)
db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80), nullable=False)
    recipient = db.Column(db.String(80), nullable=True)  # Null for broadcast
    content = db.Column(db.Text, nullable=True)
    type = db.Column(db.String(20), nullable=False)  # 'broadcast' or 'direct'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    file_name = db.Column(db.String(255), nullable=True)
    file_data = db.Column(db.LargeBinary, nullable=True)
    file_mime = db.Column(db.String(255), nullable=True) 