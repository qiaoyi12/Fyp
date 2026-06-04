from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager

app = Flask(__name__)

# config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids.db'
app.config['JWT_SECRET_KEY'] = 'change-this-secret'
app.config['UPLOAD_FOLDER'] = 'uploadCsvStorage'

# extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# routes

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    return jsonify({"msg": "login route", "data": data})


@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    return jsonify({"msg": "register route"})


@app.route('/api/upload', methods=['POST'])
def upload():
    return jsonify({"msg": "upload route"})


@app.route('/api/analyze', methods=['POST'])
def analyze():
    return jsonify({"msg": "analysis route"})


# frontend
@app.route('/')
def serve_login():
    return send_from_directory('frontend', 'login.html')


# to create database tables
with app.app_context():
    db.create_all()


# run server
if __name__ == '__main__':
    app.run(debug=True)