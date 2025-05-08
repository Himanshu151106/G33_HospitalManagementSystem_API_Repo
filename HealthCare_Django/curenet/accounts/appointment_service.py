import requests
import json
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings

from .appointment_service import AppointmentService
appointment_service = AppointmentService(base_url=settings.FLASK_API_URL)

class AppointmentService:
    """Service to interact with Flask API appointments"""
    
    def __init__(self, base_url='http://localhost:5000'):
        self.base_url = base_url
        
    def get_user_appointments(self, auth_token, email):
        """Get appointments for a specific user"""
        headers = {'Authorization': f'Bearer {auth_token}'}
        response = requests.get(f"{self.base_url}/api/appointments", headers=headers)
        
        if response.status_code == 200:
            all_appointments = response.json()
            user_appointments = [appt for appt in all_appointments if appt.get('email') == email]
            return user_appointments, 200
        else:
            return [], response.status_code
    
    
@login_required
def book_appointment(request):
    if request.method == "POST":
        
        appointment_data = {
            "name": request.POST.get("name"),
            "email": request.session.get('user_data', {}).get('email'),
            "phone": request.POST.get("phone"),
            "date": request.POST.get("date"),
            "time": request.POST.get("time"),
            "reason": request.POST.get("reason")
        }
        
        
        request.session["appointment_data"] = appointment_data
        
        return redirect('payment')
        
    return render(request, "appointment_form.html")

@login_required
def payment(request):

    if "appointment_data" not in request.session:
        messages.error(request, "You must book an appointment before proceeding to payment.")
        return redirect('book_appointment')
        
    if request.method == "POST":
        payment_method = request.POST.get("payment_method")
        
        
        appointment_data = request.session.get("appointment_data")
        appointment_data["payment_method"] = payment_method
        
        
        if payment_method != "cash":
            card_number = request.POST.get("card_number")
            expiry = request.POST.get("expiry")
            cvv = request.POST.get("cvv")
            
            
            if not all([card_number, expiry, cvv]):
                messages.error(request, "Payment details are required!")
                return redirect('payment')
                
            if len(card_number) != 16 or not card_number.isdigit():
                messages.error(request, "Card number must be 16 digits!")
                return redirect('payment')
                
            if len(cvv) != 3 or not cvv.isdigit():
                messages.error(request, "CVV must be 3 digits!")
                return redirect('payment')
        
        
        auth_token = request.session.get('auth_token')
        response, status_code = appointment_service.book_appointment(auth_token, appointment_data)
        
        if status_code == 201:
            
            del request.session["appointment_data"]
            
            messages.success(request, "Payment successful! Your appointment is confirmed.")
            return redirect('success', 
                           email=appointment_data.get('email'),
                           date=appointment_data.get('date'),
                           time=appointment_data.get('time'),
                           name=appointment_data.get('name'),
                           phone=appointment_data.get('phone'))
        else:
            messages.error(request, f"Booking failed: {response.get('message', 'Unknown error')}")
            
    return render(request, "payment.html")

@login_required
def my_appointments(request):
    auth_token = request.session.get('auth_token')
    email = request.session.get('user_data', {}).get('email')
    
    appointments, status_code = appointment_service.get_user_appointments(auth_token, email)
    
    if status_code != 200:
        messages.error(request, "Failed to retrieve your appointments. Please try again later.")
        
    return render(request, "myappointments.html", {"appointments": appointments})

@login_required
def cancel_appointment(request, appointment_id):
    if request.method == "POST":
        auth_token = request.session.get('auth_token')
        
        if appointment_service.cancel_appointment(auth_token, appointment_id):
            messages.success(request, "Appointment cancelled successfully.")
        else:
            messages.error(request, "Failed to cancel appointment.")
            
    return redirect('my_appointments')