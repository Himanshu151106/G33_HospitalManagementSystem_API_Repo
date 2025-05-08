import re
import json
import os
from datetime import datetime, date
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify 
from flask_restful import Api
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource
from flask_cors import CORS

from extensions import db, jwt, login_manager

if not os.path.exists('resource'):
    os.makedirs('resource')


app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "default_secret_key")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "default_jwt_key")

db.init_app(app)
api = Api(app)
jwt.init_app(app)
login_manager.init_app(app)
login_manager.login_view = "login"

from models import User
from resource.app_resource import LoginAPI, RegisterAPI

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

APPOINTMENTS_FILE = "appointments.json"

if not os.path.exists(APPOINTMENTS_FILE):
    with open(APPOINTMENTS_FILE, "w") as f:
        json.dump([], f)

class AppointmentListAPI(Resource):
    @jwt_required()
    def get(self):
        """Get all appointments"""
        try:
            with open(APPOINTMENTS_FILE, "r") as f:
                appointments = json.load(f)
            return appointments, 200
        except Exception as e:
            return {"message": f"Error: {str(e)}"}, 500
    @jwt_required()
    def post(self):
        """Create a new appointment"""
        try:
            data = request.get_json()
            if not data:
                return {"message": "No input data provided"}, 400
                
            required_fields = ["name", "email", "phone", "date", "time", "reason", "payment_method"]
            if not all(field in data for field in required_fields):
                return {"message": "Missing required fields"}, 400
                
            with open(APPOINTMENTS_FILE, "r") as f:
                appointments = json.load(f)
                
            new_appointment = {
                "id": len(appointments) + 1,
                "name": data["name"],
                "email": data["email"],
                "phone": data["phone"],
                "date": data["date"],
                "time": data["time"],
                "reason": data["reason"],
                "payment_method": data["payment_method"]
            }
            
            appointments.append(new_appointment)
            
            with open(APPOINTMENTS_FILE, "w") as f:
                json.dump(appointments, f, indent=4)
                
            return new_appointment, 201
        except Exception as e:
            return {"message": f"Error: {str(e)}"}, 500
        
    @jwt_required()
    def delete(self, appointment_id):
        """Cancel/delete an appointment"""
        try:
            current_user_id = get_jwt_identity()
            user = db.session.get(User, int(current_user_id))
            
            with open(APPOINTMENTS_FILE, "r") as f:
                appointments = json.load(f)
                
            filtered_appointments = [
                appt for appt in appointments 
                if not (appt["id"] == appointment_id and appt["email"] == user.email)
            ]
            
            if len(filtered_appointments) == len(appointments):
                return {"message": "Appointment not found or you don't have permission"}, 404
                
            with open(APPOINTMENTS_FILE, "w") as f:
                json.dump(filtered_appointments, f, indent=4)
                
            return {"message": "Appointment cancelled successfully"}, 200
        except Exception as e:
            return {"message": f"Error: {str(e)}"}, 500

api.add_resource(RegisterAPI, '/api/register')
api.add_resource(LoginAPI, '/api/login')
api.add_resource(AppointmentListAPI, '/api/appointments')

class AppointmentDetailAPI(Resource):
    @jwt_required()
    def get(self, appointment_id):
        """Get details of a specific appointment"""
        try:
            with open(APPOINTMENTS_FILE, "r") as f:
                appointments = json.load(f)
            
            appointment = next((appt for appt in appointments if appt["id"] == appointment_id), None)
            if not appointment:
                return {"message": "Appointment not found"}, 404
            
            return appointment, 200
        except Exception as e:
            return {"message": f"Error: {str(e)}"}, 500

api.add_resource(AppointmentDetailAPI, '/api/appointments/<int:appointment_id>')

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@app.route("/blog")
def blog():
    return render_template("blog.html")

@app.route("/appointment_form", methods=["GET", "POST"])
@login_required
def book():
    if request.method == "POST":
        data = request.form
        session["appointment_name"] = data["name"]
        session["appointment_phone"] = data["phone"]
        session["appointment_date"] = data["date"]
        session["appointment_time"] = data["time"]
        session["appointment_reason"] = data["reason"]
        session["appointment_booked"] = True
        return redirect(url_for("payment"))  
    return render_template("appointment_form.html")

@app.route("/payment", methods=["GET", "POST"])
@login_required
def payment():
    if "appointment_booked" not in session:
        flash("You must book an appointment before proceeding to payment.", "danger")
        return redirect(url_for("book"))  

    if request.method == "POST":
        payment_method = request.form["payment_method"]
        if payment_method == "cash":
            flash("You have selected to pay in cash during your appointment.", "success")
        else:
            card_number = request.form.get("card_number")
            expiry = request.form.get("expiry")
            cvv = request.form.get("cvv")
            
            if not card_number or not expiry or not cvv:
                flash("Payment details are required!", "danger")
                return redirect(url_for("payment"))
            
            if len(card_number) != 16 or not card_number.isdigit():
                flash("Card number must be 16 digits!", "danger")
                return redirect(url_for("payment"))
           
            if len(cvv) != 3 or not cvv.isdigit():
                flash("CVV must be 3 digits!", "danger")
                return redirect(url_for("payment"))
            
            if not re.match(r'^(0[1-9]|1[0-2])\/\d{2}$', expiry):
                flash("Expiry date must be in MM/YY format!", "danger")
                return redirect(url_for("payment"))
        
        with open(APPOINTMENTS_FILE, "r") as f:
            appointments = json.load(f)
        
        new_appointment = {
            "id": len(appointments) + 1,
            "name": session.get("appointment_name"),
            "email": current_user.email,
            "phone": session.get("appointment_phone"),
            "date": session.get("appointment_date"),
            "time": session.get("appointment_time"),
            "reason": session.get("appointment_reason"),
            "payment_method": payment_method 
        }
        appointments.append(new_appointment)
       
        with open(APPOINTMENTS_FILE, "w") as f:
            json.dump(appointments, f, indent=4)
       
        session.pop("appointment_booked", None)
        
        flash("Payment successful! Your appointment is confirmed.", "success")
        return redirect(url_for("success", email=current_user.email, date=new_appointment["date"], time=new_appointment["time"], name=new_appointment["name"], phone=new_appointment["phone"]))
    
    return render_template("payment.html") 

@app.route("/myappointments")
@login_required
def my_appointments():
    with open(APPOINTMENTS_FILE, "r") as f:
        appointments = json.load(f)
    user_appointments = [appt for appt in appointments if appt["email"] == current_user.email]
    return render_template("myappointments.html", appointments=user_appointments)

@app.route("/cancel_appointment/<int:appointment_id>", methods=["POST"])
@login_required
def cancel_appointment(appointment_id):
    with open(APPOINTMENTS_FILE, "r") as f:
        appointments = json.load(f)
    appointments = [appt for appt in appointments if not (appt["id"] == appointment_id and appt["email"] == current_user.email)]
    with open(APPOINTMENTS_FILE, "w") as f:
        json.dump(appointments, f, indent=4)
    flash("Appointment cancelled successfully.", "success")
    return redirect(url_for("my_appointments"))

@app.route("/contact")
def contact():
    return render_template("contact.html")

doctors_data = {
    "Neelam Hospital": [
        {"id": 1, "name": "Dr. Anjali Sharma", "specialty": "Cardiologist", "experience": 12, "fees": 800},
        {"id": 2, "name": "Dr. Rohit Mehta", "specialty": "Neurologist", "experience": 10, "fees": 1000},
    ],
    "Poly Clinic Classical Homeopathy": [
        {"id": 3, "name": "Dr. Priya Kapoor", "specialty": "Homeopathy", "experience": 8, "fees": 500},
        {"id": 4, "name": "Dr. Rajiv Singh", "specialty": "General Medicine", "experience": 15, "fees": 600},
    ],
    "Max Super Speciality Hospital": [
        {"id": 5, "name": "Dr. Alok Verma", "specialty": "Orthopedist", "experience": 14, "fees": 900},
        {"id": 6, "name": "Dr. Sunita Rao", "specialty": "Dermatologist", "experience": 11, "fees": 700},
    ],
    "Healing Hospital": [
        {"id": 7, "name": "Dr. Kiran Gupta", "specialty": "Neurologist", "experience": 9, "fees": 850},
        {"id": 8, "name": "Dr. Sandeep Malhotra", "specialty": "Cardiologist", "experience": 13, "fees": 950},
    ]
}

@app.route("/doctors/<hospital_name>")
def doctor_list(hospital_name):
    hospital_name = hospital_name.replace("-", " ")  
    doctors = doctors_data.get(hospital_name, [])  
    return render_template("doctor_list.html", hospital_name=hospital_name, doctors=doctors)

@app.route("/forgotpassword", methods=["GET", "POST"])
def forgot_password():
    return render_template("forgotpassword.html")

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        full_name = request.form.get("full_name")
        email = request.form.get("email")
        dob = request.form.get("dob")
        gender = request.form.get("gender")
        current_user.full_name = full_name
        current_user.email = email
        current_user.dob = dob
        current_user.gender = gender
        db.session.commit()  
        flash("Settings updated successfully!")  
        return redirect(url_for("settings"))  
    return render_template("settings.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("patient"))
        flash("Invalid email or password", "danger")
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        full_name = request.form.get("full_name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        dob = request.form.get("dob")
        gender = request.form.get("gender")

        password_pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(password_pattern, password):
            flash("Password must be at least 8 characters long, with 1 uppercase, 1 lowercase, 1 digit, and 1 special character (@$!%*?&).", "danger")
            return redirect(url_for("signup"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("signup"))

        try:
            dob_date = datetime.strptime(dob, "%Y-%m-%d").date()
            today = date.today()
            age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))
            if age < 16:
                flash("You must be at least 16 years old to register.", "danger")
                return redirect(url_for("signup"))
        except ValueError:
            flash("Invalid date of birth format.", "danger")
            return redirect(url_for("signup"))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for("login"))

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(full_name=full_name, email=email, password=hashed_password, dob=dob, gender=gender) 
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/patient")
@login_required
def patient():
    return render_template("patient.html")

@app.route("/logout")
@login_required
def logout():
    logout_user() 
    flash("Logged out successfully.", "success")
    return redirect(url_for("login")) 

@app.route('/update_profile', methods=['POST'])
def update_profile():
    return 'Profile updated successfully!'

@app.route("/medical_records")
@login_required
def medical_records():
    with open(APPOINTMENTS_FILE, "r") as f:
        appointments = json.load(f)
    user_appointments = [appt for appt in appointments if appt["email"] == current_user.email]
    medical_history = [
        {"date": "2024-01-15", "condition": "Flu", "treatment": "Rest and hydration"},
        {"date": "2024-05-20", "condition": "Allergy", "treatment": "Antihistamines"},
    ]
    return render_template("medical_records.html", appointments=user_appointments, medical_history=medical_history)

@app.route("/success")
@login_required
def success():
    email = request.args.get("email")
    date = request.args.get("date")
    time = request.args.get("time")
    name = request.args.get("name")
    phone = request.args.get("phone")
    return render_template("success.html", email=email, date=date, time=time, name=name, phone=phone)

@app.route("/about")
def about():
    return render_template("about.html")

CORS(app, supports_credentials=True, origins=["http://127.0.0.1:8000"])  # Django default port

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  
    app.run(debug=True)