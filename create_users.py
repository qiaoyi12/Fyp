import sys
sys.path.insert(0, r"C:\FYP\test\backend\src\database")

from app import app, db
from backend.src.database.models import User

users = [
    {"username": "admin",   "email": "admin1@spboost.com",   "password": "admin@123",   "role": "admin",   "level": "junior"},
    {"username": "manager", "email": "manager1@spboost.com", "password": "manager@123", "role": "manager", "level": "junior"},
    {"username": "user1",    "email": "user1@spboost.com",    "password": "user1@123",   "role": "analyst", "level": "junior"},
    {"username": "user2",    "email": "user2@spboost.com",    "password": "user2@123",   "role": "analyst", "level": "senior"},
]

with app.app_context():
    for u in users:
        existing = User.query.filter_by(username=u["username"]).first()
        if existing:
            print(f"{u['username']} already exists, skipping")
            continue
        new_user = User(
            username=u["username"],
            email=u["email"],
            role=u["role"],
            level=u["level"],
        )
        new_user.set_password(u["password"])
        db.session.add(new_user)
    db.session.commit()
    print("Done creating 4 users.")