#!/usr/bin/env python3
"""users table User model"""

from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
import json

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    """User class for 'user' table"""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    roles = db.Column(db.Text, default='["user"]')


    reset_token = db.Column(db.String(32), unique=True, nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_otp_code = db.Column(db.String(6), nullable=True)
    mfa_otp_expiry = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    @property
    def roles_to_string(self):
        try:
            return json.loads(self.roles)
        except (json.JSONDecodeError, TypeError):
            return []

    def add_role(self, role_name):
        roles = self.roles_to_string
        if role_name not in roles:
            roles.append(role_name)
            self.roles = json.dumps(roles)

    def delete_role(self, role_name):
        roles = self.roles_to_string
        if role_name in roles:
            roles.remove(role_name)
            self.roles = json.dumps(roles)
