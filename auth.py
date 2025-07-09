#!/usr/bin/env python3
"""Implements authentication logic"""

from datetime import datetime, timedelta
import json
import random
import string
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity,
    create_refresh_token, get_jwt
)
from mail_service import send_email
from roles import roles_required
from user import db, User

auth_bp = Blueprint('auth', __name__)

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
            password:
              type: string
            roles:
              type: array
              items:
                type: string
    responses:
      201:
        description: User registered successfully
      400:
        description: Missing or invalid input
      409:
        description: User already exists
    """
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    roles = data.get('roles', ['user'])

    if not email:
        return jsonify({"message": "Email is required"}), 400

    if not password:
        return jsonify({"message": "Password is required"}), 400

    if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        return jsonify({"message": "Roles must be a list of strings"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "User with that email already exists"}), 409

    user = User(email=email)
    user.set_password(password)
    user.roles = json.dumps(roles)

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    User login
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
            password:
              type: string
    responses:
      200:
        description: Login successful, returns access and refresh tokens or MFA required
      400:
        description: Missing input
      401:
        description: Invalid credentials
    """
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email:
        return jsonify({"message": "Email is required"}), 400

    if not password:
        return jsonify({"message": "Password is required"}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"message": "Invalid email"}), 401

    if not user.check_password(password):
        return jsonify({"message": "Invalid password"}), 401

    if user.mfa_enabled:
        otp_code = generate_otp()
        user.mfa_otp_code = otp_code
        user.mfa_otp_expiry = datetime.utcnow() + timedelta(minutes=5)
        db.session.commit()

        send_email(user.email, "OTP", f"Your one-time verification code is: {otp_code}. The OTP is valid for 5 minutes.")
        return jsonify({"message": "Check your email for an OTP.", "mfa_pending": True, "user_id": user.id}), 200
    else:
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200

@auth_bp.route('/login/mfa-verify', methods=['POST'])
def login_mfa_verify():
    """
    Verify MFA code during login
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            user_id:
              type: integer
            otp_code:
              type: string
    responses:
      200:
        description: MFA verified, returns tokens
      400:
        description: Missing or invalid input
      401:
        description: Invalid or expired OTP
    """
    data = request.get_json()
    user_id = data.get('user_id')
    otp_code = data.get('otp_code')

    if not user_id:
        return jsonify({"message": "User ID required"}), 400
    if not otp_code:
        return jsonify({"message": "OTP code is required"}), 400

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"message": "User not found"}), 400
    if not user.mfa_enabled:
        return jsonify({"message": "MFA not enabled for this user"}), 400

    if user.mfa_otp_code != otp_code:
        return jsonify({"message": "Invalid OTP code"}), 401

    if datetime.utcnow() > user.mfa_otp_expiry:
        return jsonify({"message": "OTP code has expired"}), 401

    user.mfa_otp_code = None
    user.mfa_otp_expiry = None
    db.session.commit()

    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    return jsonify(access_token=access_token, refresh_token=refresh_token), 200


@auth_bp.route('/token/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh access token
    ---
    tags:
      - Authentication
    security:
      - Bearer Auth: []
    responses:
      200:
        description: New access token
    """
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id)
    return jsonify(access_token=new_access_token), 200

@auth_bp.route('/mfa/enable', methods=['POST'])
@jwt_required()
def enable_mfa():
    """
    Enable MFA for the current user
    ---
    tags:
      - MFA
    security:
      - Bearer Auth: []
    responses:
      200:
        description: OTP sent for MFA enabling
      400:
        description: MFA already enabled
      404:
        description: User not found
    """
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    if not user:
        return jsonify({"message": "User not found"}), 404

    if user.mfa_enabled:
        return jsonify({"message": "MFA is already enabled for this account"}), 400

    otp_code = generate_otp()
    user.mfa_otp_code = otp_code
    user.mfa_otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()

    send_email(user.email, "OTP- Multi-factor Authentication Verification", f"Your OTP code is: {otp_code}. The OTP is valid for 5 minutes.")
    return jsonify({"message": "OTP has been sent to your email. Please verify to enable MFA."}), 200

@auth_bp.route('/mfa/verify', methods=['POST'])
@jwt_required()
def verify_mfa():
    """
    Verify OTP to enable MFA
    ---
    tags:
      - MFA
    security:
      - Bearer Auth: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            otp_code:
              type: string
    responses:
      200:
        description: MFA enabled
      400:
        description: Invalid or expired OTP
      404:
        description: User not found
    """
    data = request.get_json()
    otp_code = data.get('otp_code')
    user_id = get_jwt_identity()

    if not otp_code:
        return jsonify({"message": "OTP code is required"}), 400

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    if user.mfa_enabled:
        return jsonify({"message": "MFA is already enabled for this account"}), 400

    if user.mfa_otp_code != otp_code:
        return jsonify({"message": "Invalid OTP code"}), 401

    if datetime.utcnow() > user.mfa_otp_expiry:
        return jsonify({"message": "OTP code has expired"}), 401

    user.mfa_enabled = True
    user.mfa_otp_code = None
    user.mfa_otp_expiry = None
    db.session.commit()

    return jsonify({"message": "MFA successfully enabled."}), 200

@auth_bp.route('/mfa/disable', methods=['POST'])
@jwt_required()
def disable_mfa():
    """
    Disable MFA for the current user
    ---
    tags:
      - MFA
    security:
      - Bearer Auth: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            password:
              type: string
    responses:
      200:
        description: MFA disabled
      400:
        description: MFA not enabled or invalid password
      401:
        description: Incorrect password
      404:
        description: User not found
    """
    data = request.get_json()
    password = data.get('password')
    user_id = get_jwt_identity()

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    if not user.mfa_enabled:
        return jsonify({"message": "MFA is not enabled for this account"}), 400

    if not password or not user.check_password(password):
        return jsonify({"message": "Incorrect password"}), 401

    user.mfa_enabled = False
    user.mfa_otp_code = None
    user.mfa_otp_expiry = None
    db.session.commit()

    return jsonify({"message": "MFA successfully disabled."}), 200

@auth_bp.route('/forgot_password', methods=['POST'])
def forgot_password():
    """
    Request a password reset link
    ---
    tags:
      - Password
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
    responses:
      200:
        description: Password reset link sent
    """
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "A password reset link has been sent."}), 200

    reset_token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    user.reset_token = reset_token
    user.reset_token_expiry = datetime.utcnow() + timedelta(minutes=20)
    db.session.commit()

    reset_link = f"http://localhost:5000/api/auth/reset_password/{reset_token}"
    send_email(user.email, "Password Reset Request", f"Click the link to reset your password: {reset_link}. This link is valid for 1 hour.")

    return jsonify({"message": f"A password reset link has been sent to {user.email}"}), 200

@auth_bp.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    """
    Reset password using token
    ---
    tags:
      - Password
    parameters:
      - in: path
        name: token
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            new_password:
              type: string
    responses:
      200:
        description: Password reset successful
      400:
        description: Invalid or expired token
    """
    data = request.get_json()
    new_password = data.get('new_password')

    if not new_password:
        return jsonify({"message": "New password is required"}), 400

    user = User.query.filter_by(reset_token=token).first()

    if not user:
        return jsonify({"message": "Invalid reset token"}), 400
    if datetime.utcnow() > user.reset_token_expiry:
        return jsonify({"message": "Expired reset token"}), 400


    user.set_password(new_password)
    user.reset_token = None
    user.reset_token_expiry = None
    db.session.commit()

    return jsonify({"message": "Password has been reset successfully."}), 200

@auth_bp.route('/manage_roles', methods=['POST'])
@jwt_required()
@roles_required('admin')
def manage_roles():
    """
    Manage user roles (admin only)
    ---
    tags:
      - Roles
    security:
      - Bearer Auth: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            user_id:
              type: integer
            action:
              type: string
              enum: [add, remove]
            role_name:
              type: string
    responses:
      200:
        description: Role updated
      400:
        description: Missing or invalid input
      404:
        description: User not found
    """
    data = request.get_json()
    user_id = data.get('user_id')
    action = data.get('action')
    role_name = data.get('role_name')

    if not user_id or not action or not role_name:
        return jsonify({"message": "User ID, action (add/remove), and role name are required"}), 400

    user_to_modify = db.session.get(User, user_id)
    if not user_to_modify:
        return jsonify({"message": "User not found"}), 404

    if action == 'add':
        user_to_modify.add_role(role_name)
        db.session.commit()
        return jsonify({"message": f"Role '{role_name}' added to user {user_id}", "user_roles": user_to_modify.roles_to_string}), 200
    elif action == 'remove':
        user_to_modify.delete_role(role_name)
        db.session.commit()
        return jsonify({"message": f"Role '{role_name}' removed from user {user_id}", "user_roles": user_to_modify.roles_to_string}), 200
    else:
        return jsonify({"message": "Invalid action. Must be 'add' or 'remove'"}), 400
