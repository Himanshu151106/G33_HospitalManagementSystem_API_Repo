from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from django.db import IntegrityError
from django.contrib.auth import get_user_model
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from datetime import datetime
import re
import json

from .forms import ProfileForm, HealthForm
from .models import Profile
from .api_service import FlaskAPIService

User = get_user_model()
flask_api = FlaskAPIService()

def signup(request):
    if request.method == 'POST':
        full_name = request.POST.get('full_name')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        dob = request.POST.get('dob')
        gender = request.POST.get('gender') 
        
        if not dob:
            messages.error(request, "Date of birth is required.")
            return render(request, 'signup.html')
        if not gender:
            messages.error(request, "Gender is required.")
            return render(request, 'signup.html')

        try:
            dob_obj = datetime.strptime(dob, '%Y-%m-%d').date()
            today = datetime.today().date()
            age = (today - dob_obj).days // 365
            if age < 16:
                messages.error(request, "You must be at least 16 years old to sign up.")
                return render(request, 'signup.html')
        except ValueError:
            messages.error(request, "Invalid date format for DOB.")
            return render(request, 'signup.html')

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return render(request, 'signup.html')

        user_data = {
            "full_name": full_name,
            "email": email,
            "password": password1,
            "dob": dob,
            "gender": gender  
        }
        
        response, status_code = flask_api.register_user(user_data)
        
        if status_code == 201:
            messages.success(request, "Signup successful! Please log in.")
            return redirect('login')
        else:
            messages.error(request, f"Signup failed: {response.get('message', 'Unknown error')}")
            
    return render(request, 'signup.html')


def user_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        credentials = {
            "email": email,
            "password": password
        }
        
        response, status_code = flask_api.login_user(credentials)
        
        if status_code == 200:

            request.session['auth_token'] = response.get('access_token')
            request.session['user_data'] = response.get('user')
            

            user_data = response.get('user', {})
            full_name = user_data.get('full_name', 'Unknown User')

            try:

                user = User.objects.get(email=email)
            except User.DoesNotExist:

                try:
                    user = User.objects.create_user(
                        email=email,
                        password=password,
                        full_name=full_name
                    )
                except Exception as e:
                    messages.error(request, f"Error creating user session: {str(e)}")
                    return render(request, 'login.html')
            
            login(request, user)
            
            messages.success(request, f"Welcome back, {full_name}!")
            return redirect('patient_dashboard') 
        else:
            messages.error(request, f"Login failed: {response.get('message', 'Invalid email or password.')}")
    
    return render(request, 'login.html')

@login_required
def profile(request):

    if 'auth_token' not in request.session:
        messages.error(request, "Your session has expired. Please log in again.")
        return redirect('login')
    
    user_data = request.session.get('user_data', {})
    
    
    context = {
        'user': user_data,

    }
    return render(request, 'profile.html', context)


@login_required
def logout_view(request):

    if 'auth_token' in request.session:
        del request.session['auth_token']
    if 'user_data' in request.session:
        del request.session['user_data']
    
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('login')

@login_required
def settings(request):

    return render(request, 'settings.html')

def fake_forgot_password(request):

    return render(request, 'forgot_password.html')