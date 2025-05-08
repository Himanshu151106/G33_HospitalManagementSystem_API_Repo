from flask_restful import Resource
from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token

from models import User
from extensions import db
import re

class RegisterAPI(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            return {"message": "No input data provided"}, 400

        full_name = data.get("full_name")
        email = data.get("email")
        password = data.get("password")
        dob = data.get("dob")
        gender = data.get("gender")

        if not all([full_name, email, password, dob, gender]):
            return {"message": "Missing required fields"}, 400
        
        if User.query.filter_by(email=email).first():
            return {"message": "Email already registered."}, 400

        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            return {"message": "Invalid email format"}, 400

        if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password):
            return {"message": "Weak password"}, 400

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(full_name=full_name, email=email, password=hashed_password, dob=dob, gender=gender)

        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {"message": f"Error: {str(e)}"}, 500

        return {"message": "Signup successful."}, 201


class LoginAPI(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            return {"message": "No input data provided"}, 400
            
        email = data.get("email")
        password = data.get("password")
        
        if not email or not password:
            return {"message": "Email and password are required"}, 400
            
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password, password):
            return {"message": "Invalid email or password"}, 401
            
        access_token = create_access_token(identity=user.id)
        
        return {
            "message": "Login successful",
            "access_token": access_token,
            "user": {
                "id": user.id,
                "full_name": user.full_name,
                "email": user.email
            }
        }, 200
    
