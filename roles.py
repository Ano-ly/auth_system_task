#!/usr/bin/env python3
"""Contains decorator 'roles_required' for route functions"""

from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt, verify_jwt_in_request

def roles_required(roles):
    """
    Decorator to check if the current user has at least one of the specified roles.
    Args:
        roles (list or string): A single role string or a list of role strings.
    """
    if not isinstance(roles, list):
        roles = [roles]

    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            user_roles = claims.get("roles", [])

            if not any(role in user_roles for role in roles):
                return jsonify({"message": "Insufficient permissions"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper