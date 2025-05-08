from django import forms
from .models import Profile


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = [
            'phone_number',
            'date_of_birth',
            'gender',
            'blood_group',
            'address',
        ]
        widgets = {
            'phone_number': forms.TextInput(attrs={'class': 'form-control'}),
            'date_of_birth': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'gender': forms.Select(attrs={'class': 'form-select'}),
            'blood_group': forms.Select(attrs={'class': 'form-select'}),
            'address': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }


class HealthForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = [
            'height',
            'weight',
            'allergies',
            'medical_conditions',
            'current_medications',
        ]
        widgets = {
            'height': forms.NumberInput(attrs={'class': 'form-control'}),
            'weight': forms.NumberInput(attrs={'class': 'form-control'}),
            'allergies': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
            'medical_conditions': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
            'current_medications': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
        }
