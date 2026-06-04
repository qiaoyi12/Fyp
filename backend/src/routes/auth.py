# for user registration and login
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from ..database.db import db, bcrypt
from ..database.models import User

auth_bp = Blueprint('auth', __name__)


# ── Register ──────────────────────────────────────────────────
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Validate required fields
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    required = ('username', 'email', 'password')
    missing = [f for f in required if f not in data or not data[f]]
    if missing:
        return jsonify({'error': f'Missing fields: {missing}'}), 400

    # Check for duplicates
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 409

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already taken'}), 409

    # Basic password length check
    if len(data['password']) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    # Hash password and save user
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(
        username=data['username'],
        email=data['email'],
        password=hashed_pw
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


# ── Login ─────────────────────────────────────────────────────
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    required = ('email', 'password')
    missing = [f for f in required if f not in data or not data[f]]
    if missing:
        return jsonify({'error': f'Missing fields: {missing}'}), 400

    # Find user by email
    user = User.query.filter_by(email=data['email']).first()

    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Invalid email or password'}), 401

    # Create JWT token — identity is the user's id as string
    token = create_access_token(identity=str(user.id))

    return jsonify({
        'message':      'Login successful',
        'access_token': token,
        'user':         user.to_dict()
    }), 200


# ── Get current user (protected) ──────────────────────────────
@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def me():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({'user': user.to_dict()}), 200
