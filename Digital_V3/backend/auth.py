"""JWT authentication, RBAC decorators, and password hashing."""
import jwt
import os
import sys
import bcrypt
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from functools import wraps
from datetime import datetime, timedelta
from flask import request, jsonify, g
from backend.config import config
import logging

logger = logging.getLogger(__name__)

VALID_ROLES = {'admin', 'investigator', 'analyst', 'guest'}

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


def create_token(user_id: int, role: str, username: str) -> str:
    payload = {
        'sub': str(user_id),
        'role': role,
        'username': username,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=config.JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm='HS256')

def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, config.JWT_SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_current_user():
    """Extract user from Authorization header."""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    token = auth[7:]
    decoded = decode_token(token)
    if decoded and 'sub' in decoded:
        decoded['sub'] = int(decoded['sub'])
    return decoded

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Authentication required', 'code': 'UNAUTHORIZED'}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return decorated

def roles_required(*allowed_roles):
    """Decorator: restrict to specific roles."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({'error': 'Authentication required', 'code': 'UNAUTHORIZED'}), 401
            if user.get('role') not in allowed_roles:
                return jsonify({
                    'error': f'Access denied. Required roles: {list(allowed_roles)}',
                    'code': 'FORBIDDEN'
                }), 403
            g.current_user = user
            return f(*args, **kwargs)
        return decorated
    return decorator

def admin_required(f):
    return roles_required('admin')(f)

def investigator_required(f):
    return roles_required('investigator', 'admin')(f)

def guest_or_login_required(f):
    """Decorator: allow guest or any authenticated user."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Authentication required. Please sign in as a guest or staff member.', 'code': 'UNAUTHORIZED'}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return decorated
