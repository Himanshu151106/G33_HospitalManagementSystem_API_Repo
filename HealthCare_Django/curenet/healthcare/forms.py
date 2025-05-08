import re
from django import forms
from .models import Appointment, Hospital, Doctor, MedicalRecord,Medicine
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import datetime, timedelta

class AppointmentForm(forms.ModelForm):
    name = forms.CharField(widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Full Name'
    }))
    phone = forms.CharField(widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Phone Number'
    }))
    date = forms.DateField(widget=forms.DateInput(attrs={
        'class': 'form-control',
        'type': 'date'
    }))
    time = forms.TimeField(widget=forms.TimeInput(attrs={
        'class': 'form-control',
        'type': 'time'
    }))
    reason = forms.CharField(widget=forms.Textarea(attrs={
        'class': 'form-control',
        'placeholder': 'Reason for appointment',
        'rows': 3
    }))
    
    class Meta:
        model = Appointment
        fields = ['name', 'phone', 'date', 'time', 'reason']
    
    def clean_date(self):
        date = self.cleaned_data.get('date')
        today = timezone.now().date()
        if date <= today:
            raise forms.ValidationError("Appointment date must be in the future.")
        return date
    
    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        if not re.match(r'^\d{10}$', phone):
            raise ValidationError("Phone number must be exactly 10 digits.")
        return phone

class RescheduleAppointmentForm(forms.ModelForm):
    name = forms.CharField(widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Full Name'
    }))
    phone = forms.CharField(widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Phone Number'
    }))
    date = forms.DateField(widget=forms.DateInput(attrs={
        'class': 'form-control',
        'type': 'date'
    }))
    time = forms.TimeField(widget=forms.TimeInput(attrs={
        'class': 'form-control',
        'type': 'time'
    }))
    reason = forms.CharField(widget=forms.Textarea(attrs={
        'class': 'form-control',
        'placeholder': 'Reason for appointment',
        'rows': 3
    }))
    
    class Meta:
        model = Appointment
        fields = ['name', 'phone', 'date', 'time', 'reason']
        
    def clean_date(self):
        date = self.cleaned_data.get('date')
        today = timezone.now().date()
        if date <= today:
            raise forms.ValidationError("Rescheduled appointment must be in the future.")
        return date
    
    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        if not re.match(r'^\d{10}$', phone):
            raise ValidationError("Phone number must be exactly 10 digits.")
        return phone

class PaymentForm(forms.Form):
    PAYMENT_CHOICES = (
        ('credit-card', 'Credit/Debit Card'),
        ('paypal', 'PayPal'),
        ('bank-transfer', 'Bank Transfer'),
        ('cash', 'Cash on Meeting'),
    )
    
    payment_method = forms.ChoiceField(choices=PAYMENT_CHOICES, required=True, widget=forms.HiddenInput())
    card_number = forms.CharField(required=False, widget=forms.TextInput(attrs={
        'class': 'form-control',
        'pattern': r'\d{16}',
        'title': 'Card number must be 16 digits'
    }))
    expiry = forms.CharField(required=False, widget=forms.TextInput(attrs={
        'class': 'form-control',
        'pattern': r'(0[1-9]|1[0-2])\/\d{2}',
        'title': 'Expiry date must be in MM/YY format'
    }))
    cvv = forms.CharField(required=False, widget=forms.TextInput(attrs={
        'class': 'form-control',
        'pattern': r'\d{3}',
        'title': 'CVV must be 3 digits'
    }))

class HospitalForm(forms.ModelForm):
    class Meta:
        model = Hospital
        fields = ['name', 'address', 'city', 'state', 'fees_range']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'address': forms.TextInput(attrs={'class': 'form-control'}),
            'city': forms.TextInput(attrs={'class': 'form-control'}),
            'state': forms.TextInput(attrs={'class': 'form-control'}),
            'fees_range': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g., ₹400-₹1000'}),
        }

class DoctorForm(forms.ModelForm):
    class Meta:
        model = Doctor
        fields = ['name', 'specialty', 'experience', 'fees', 'hospital']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'specialty': forms.TextInput(attrs={'class': 'form-control'}),
            'experience': forms.NumberInput(attrs={'class': 'form-control'}),
            'fees': forms.NumberInput(attrs={'class': 'form-control'}),
            'hospital': forms.Select(attrs={'class': 'form-control'}),
        }
    
    def clean_experience(self):
        experience = self.cleaned_data.get('experience')
        if experience < 0:
            raise forms.ValidationError("Experience cannot be negative.")
        return experience
    
    def clean_fees(self):
        fees = self.cleaned_data.get('fees')
        if fees <= 0:
            raise forms.ValidationError("Fees must be greater than zero.")
        return fees

class MedicalRecordForm(forms.ModelForm):
    class Meta:
        model = MedicalRecord
        fields = ['date', 'condition', 'treatment']
        widgets = {
            'date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'condition': forms.TextInput(attrs={'class': 'form-control'}),
            'treatment': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }

from django import forms
from .models import MedicineOrder

class MedicineOrderForm(forms.ModelForm):
    class Meta:
        model = MedicineOrder
        fields = ['medicine', 'quantity']

class MedicineForm(forms.ModelForm):
    class Meta:
        model = Medicine
        fields = ['name', 'description', 'price', 'stock']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'price': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'stock': forms.NumberInput(attrs={'class': 'form-control'}),
        }
    
    def clean_price(self):
        price = self.cleaned_data.get('price')
        if price <= 0:
            raise forms.ValidationError("Price must be greater than zero.")
        return price
    
    def clean_stock(self):
        stock = self.cleaned_data.get('stock')
        if stock < 0:
            raise forms.ValidationError("Stock cannot be negative.")
        return stock