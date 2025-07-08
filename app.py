#!/usr/bin/env python3
"""Entry point of application"""

import json
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from auth import auth_bp
from config import Config
from user import db, bcrypt, User
from mail_service import mail

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    jwt = JWTManager(app)
    mail.init_app(app)

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.get(identity)

    @jwt.additional_claims_loader
    def add_claims_to_access_token(identity):
        user = User.query.get(identity)
        if user:
            return {"roles": user.parsed_roles}
        return {"roles": []}

    @jwt.unauthorized_loader
    def unauthorized_response(callback):
        return jsonify({"message": "Missing Authorization Header or Token is invalid"}), 401

    @jwt.invalid_token_loader
    def invalid_token_response(callback):
        return jsonify({"message": "Signature verification failed"}), 403

    @jwt.expired_token_loader
    def expired_token_response(jwt_header, jwt_data):
        return jsonify({"message": "Token has expired", "expired_at": jwt_data["exp"]}), 401

    @jwt.revoked_token_loader
    def revoked_token_response(jwt_header, jwt_data):
        return jsonify({"message": "Token has been revoked"}), 401

    @jwt.needs_fresh_token_loader
    def token_not_fresh_response(jwt_header, jwt_data):
        return jsonify({"message": "Fresh token required"}), 401

    app.register_blueprint(auth_bp, url_prefix='/api/auth')

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
        print("Database tables created/checked.")

    app.run(debug=True, port=5000)