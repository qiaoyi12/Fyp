# from flask import Flask, request, jsonify, send_from_directory
# from flask_sqlalchemy import SQLAlchemy
# from flask_bcrypt import Bcrypt
# from flask_jwt_extended import JWTManager

# app = Flask(__name__)

# # config
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids.db'
# app.config['JWT_SECRET_KEY'] = 'change-this-secret'
# app.config['UPLOAD_FOLDER'] = 'uploadCsvStorage'

# # extensions
# db = SQLAlchemy(app)
# bcrypt = Bcrypt(app)
# jwt = JWTManager(app)

# # routes

# @app.route('/api/auth/login', methods=['POST'])
# def login():
#     data = request.json
#     return jsonify({"msg": "login route", "data": data})


# @app.route('/api/auth/register', methods=['POST'])
# def register():
#     data = request.json
#     return jsonify({"msg": "register route"})

# @app.route('/api/profile/<username>')
# def profile(username):
#     return f"{username}'s Page"


# @app.route('/api/upload', methods=['POST'])
# def upload():
#     return jsonify({"msg": "upload route"})


# @app.route('/api/analyze', methods=['POST'])
# def analyze():
#     return jsonify({"msg": "analysis route"})


# # frontend
# @app.route('/')
# def serve_login():
#     return send_from_directory('frontend', 'login.html')


# # to create database tables
# with app.app_context():
#     db.create_all()


# # run server
# if __name__ == '__main__':
#     app.run(debug=True)

import os
from flask import Flask
from dotenv import load_dotenv
from backend.src.database.db import db, bcrypt, jwt
from backend.src.routes.auth import auth_bp
from backend.src.routes.upload import upload_bp
from backend.src.routes.analysis import analysis_bp
from backend.src.routes.pages import pages_bp

load_dotenv()

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), 'frontend'),
    static_folder=os.path.join(os.path.dirname(__file__), 'frontend'),
    static_url_path='/frontend'
)

# Config
app.secret_key        = os.getenv('SECRET_KEY', 'session-secret-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids.db'
app.config['JWT_SECRET_KEY']  = os.getenv('JWT_SECRET_KEY', 'change-this')
app.config['UPLOAD_FOLDER']   = os.getenv('UPLOAD_FOLDER', 'uploadCsvStorage')

# Init extensions
db.init_app(app)
bcrypt.init_app(app)
jwt.init_app(app)

# Register blueprints
app.register_blueprint(pages_bp)
app.register_blueprint(auth_bp,     url_prefix='/api/auth')
app.register_blueprint(upload_bp,   url_prefix='/api')
app.register_blueprint(analysis_bp, url_prefix='/api')

# Create DB tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)