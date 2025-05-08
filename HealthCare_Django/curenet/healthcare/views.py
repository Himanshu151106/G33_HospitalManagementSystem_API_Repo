from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from .models import Hospital, Doctor, Appointment, MedicalRecord, AdminUser, Medicine, MedicineOrder, CartItem
from .forms import (
    AppointmentForm, PaymentForm, HospitalForm,
    DoctorForm, MedicalRecordForm, RescheduleAppointmentForm,
    MedicineOrderForm, MedicineForm
)
from django.contrib.auth import get_user_model
from django.contrib.admin.views.decorators import staff_member_required
from django.utils import timezone
from django.http import HttpResponseRedirect
from django.contrib.auth import logout
from .add_external_medicine import fetch_external_medicines  # Import the function

User = get_user_model()

# --- Authentication ---
def logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('login')

# --- Static Pages ---
def index(request):
    if request.user.is_authenticated and 'auth_token' in request.session:
        return redirect('patient_dashboard')
    hospitals = Hospital.objects.all()
    return render(request, 'index.html', {'hospitals': hospitals})

def about(request):
    return render(request, 'about.html')

def contact(request):
    return render(request, 'contact.html')

def blog(request):
    return render(request, 'blog.html')

# --- Patient Dashboard ---
@login_required
def patient_dashboard(request):
    if 'auth_token' not in request.session:
        messages.warning(request, "Please log in to access your dashboard.")
        logout(request)
        return redirect('login')
    
    upcoming_appointments = Appointment.objects.filter(
        patient=request.user,
        date__gte=timezone.now().date()
    ).order_by('date', 'time')
    
    past_appointments = Appointment.objects.filter(
        patient=request.user,
        date__lt=timezone.now().date()
    ).order_by('-date', '-time')
    
    hospitals = Hospital.objects.all()
    
    return render(request, 'patient_dashboard.html', {
        'upcoming_appointments': upcoming_appointments,
        'past_appointments': past_appointments,
        'hospitals': hospitals
    })

# --- Doctor Views ---
def doctor_list(request, hospital_name):
    hospital = get_object_or_404(Hospital, name=hospital_name)
    doctors = Doctor.objects.filter(hospital=hospital)
    message = request.session.pop('doctor_message', None)
    if message:
        messages.success(request, message)
    return render(request, 'doctor_list.html', {
        'hospital': hospital,
        'doctors': doctors
    })

def doctor_profile(request, doctor_id):
    doctor = get_object_or_404(Doctor, id=doctor_id)
    return render(request, 'doctor_profile.html', {'doctor': doctor})

# --- Appointment Views ---
@login_required
def my_appointments(request):
    if request.user.is_staff:
        upcoming_appointments = Appointment.objects.filter(date__gte=timezone.now().date()).order_by('date', 'time')
        past_appointments = Appointment.objects.filter(date__lt=timezone.now().date()).order_by('-date', '-time')
        is_admin = True
    else:
        upcoming_appointments = Appointment.objects.filter(patient=request.user, date__gte=timezone.now().date()).order_by('date', 'time')
        past_appointments = Appointment.objects.filter(patient=request.user, date__lt=timezone.now().date()).order_by('-date', '-time')
        is_admin = False

    return render(request, 'my_appointments.html', {
        'upcoming_appointments': upcoming_appointments,
        'past_appointments': past_appointments,
        'is_admin': is_admin
    })

@login_required
def appointment_form(request, doctor_id=None):
    doctor = get_object_or_404(Doctor, id=doctor_id) if doctor_id else None
    hospital = doctor.hospital if doctor else None

    if request.method == 'POST':
        form = AppointmentForm(request.POST)
        if form.is_valid():
            appointment = form.save(commit=False)
            appointment.patient = request.user
            appointment.doctor = doctor
            appointment.hospital = hospital
            appointment.save()
            request.session['appointment_id'] = appointment.id
            return redirect('payment')
    else:
        initial = {'name': request.user.full_name} if request.user.is_authenticated else {}
        form = AppointmentForm(initial=initial)

    return render(request, 'appointment_form.html', {
        'form': form,
        'doctor': doctor,
        'hospital': hospital
    })

@login_required
def payment(request):
    appointment_id = request.session.get('appointment_id')
    if not appointment_id:
        return redirect('patient_dashboard')
    
    appointment = get_object_or_404(Appointment, id=appointment_id)
    if request.method == 'POST':
        form = PaymentForm(request.POST)
        if form.is_valid():
            payment_method = form.cleaned_data.get('payment_method')
            appointment.payment_method = payment_method
            appointment.is_paid = payment_method != 'cash'
            appointment.save()
            del request.session['appointment_id']
            return redirect('appointment_success', appointment_id=appointment.id)
    else:
        form = PaymentForm(initial={'payment_method': 'credit-card'})

    return render(request, 'payment.html', {'form': form, 'appointment': appointment})

@login_required
def success(request, appointment_id):
    appointment = get_object_or_404(Appointment, id=appointment_id, patient=request.user)
    return render(request, 'success.html', {'appointment': appointment})

@login_required
def cancel_appointment(request, appointment_id):
    appointment = get_object_or_404(Appointment, id=appointment_id, patient=request.user)
    if request.method == 'POST':
        appointment.delete()
        messages.success(request, 'Your appointment has been cancelled successfully.')
        return redirect('my_appointments')
    return render(request, 'cancel_appointment.html', {'appointment': appointment})

@login_required
def reschedule_appointment(request, appointment_id):
    appointment = get_object_or_404(Appointment, id=appointment_id, patient=request.user)
    if request.method == 'POST':
        form = RescheduleAppointmentForm(request.POST, instance=appointment)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your appointment has been rescheduled successfully.')
            return redirect('my_appointments')
    else:
        form = RescheduleAppointmentForm(instance=appointment)
    return render(request, 'reschedule_appointment.html', {'form': form, 'appointment': appointment})

# --- Medical Records ---
@login_required
def medical_records(request):
    records = MedicalRecord.objects.filter(patient=request.user).order_by('-date')
    return render(request, 'medical_records.html', {'records': records})

# --- Admin: Hospitals ---
@staff_member_required
def admin_hospital_list(request):
    return render(request, 'admin/hospital_list.html', {'hospitals': Hospital.objects.all()})

@staff_member_required
def admin_hospital_create(request):
    form = HospitalForm(request.POST or None)
    if form.is_valid():
        form.save()
        return redirect('admin_hospital_list')
    return render(request, 'admin/hospital_form.html', {'form': form})

@staff_member_required
def admin_hospital_update(request, pk):
    hospital = get_object_or_404(Hospital, pk=pk)
    form = HospitalForm(request.POST or None, instance=hospital)
    if form.is_valid():
        form.save()
        return redirect('admin_hospital_list')
    return render(request, 'admin/hospital_form.html', {'form': form})

@staff_member_required
def admin_hospital_delete(request, pk):
    hospital = get_object_or_404(Hospital, pk=pk)
    if request.method == 'POST':
        hospital.delete()
        return redirect('admin_hospital_list')
    return render(request, 'admin/hospital_confirm_delete.html', {'hospital': hospital})

# --- Admin: Doctors ---
@staff_member_required
def admin_doctor_list(request):
    return render(request, 'admin/doctor_list.html', {'doctors': Doctor.objects.all()})

@staff_member_required
def admin_doctor_create(request):
    form = DoctorForm(request.POST or None)
    if form.is_valid():
        form.save()
        return redirect('admin_doctor_list')
    return render(request, 'admin/doctor_form.html', {'form': form})

@staff_member_required
def admin_doctor_update(request, pk):
    doctor = get_object_or_404(Doctor, pk=pk)
    form = DoctorForm(request.POST or None, instance=doctor)
    if form.is_valid():
        form.save()
        return redirect('admin_doctor_list')
    return render(request, 'admin/doctor_form.html', {'form': form})

@staff_member_required
def admin_doctor_delete(request, pk):
    doctor = get_object_or_404(Doctor, pk=pk)
    if request.method == 'POST':
        doctor.delete()
        return redirect('admin_doctor_list')
    return render(request, 'admin/doctor_confirm_delete.html', {'doctor': doctor})

# --- Admin: Appointments ---
@staff_member_required
def admin_appointment_list(request):
    return render(request, 'admin/appointment_list.html', {'appointments': Appointment.objects.all()})

@staff_member_required
def admin_appointment_update(request, pk):
    appointment = get_object_or_404(Appointment, pk=pk)
    form = AppointmentForm(request.POST or None, instance=appointment)
    if form.is_valid():
        form.save()
        return redirect('admin_appointment_list')
    return render(request, 'admin/appointment_form.html', {'form': form})

@staff_member_required
def admin_appointment_delete(request, pk):
    appointment = get_object_or_404(Appointment, pk=pk)
    if request.method == 'POST':
        appointment.delete()
        return redirect('admin_appointment_list')
    return render(request, 'admin/appointment_confirm_delete.html', {'appointment': appointment})

# --- Medicine Views ---
@login_required
def medicine_list(request):
    query = request.GET.get('q', '')
    medicine_id = request.GET.get('edit_id')
    
    if request.method == 'POST':
        if 'edit_medicine' in request.POST:
            medicine = get_object_or_404(Medicine, id=request.POST.get('medicine_id'))
            form = MedicineForm(request.POST, instance=medicine)
            if form.is_valid():
                form.save()
                messages.success(request, f"{medicine.name} has been updated successfully!")
                return redirect('medicine_list')
        elif 'add_medicine' in request.POST:
            form = MedicineForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, "New medicine has been added successfully!")
                return redirect('medicine_list')
    else:
        if medicine_id:
            medicine = get_object_or_404(Medicine, id=medicine_id)
            form = MedicineForm(instance=medicine)
        else:
            form = MedicineForm()
    
    if query:
        medicines = Medicine.objects.filter(name__icontains=query)
    else:
        medicines = Medicine.objects.all()
    
    return render(request, 'medicine/medicine_list.html', {
        'medicines': medicines,
        'query': query,
        'form': form,
        'edit_id': medicine_id
    })

@staff_member_required
def delete_medicine(request, medicine_id):
    medicine = get_object_or_404(Medicine, id=medicine_id)
    if request.method == 'POST':
        medicine_name = medicine.name
        medicine.delete()
        messages.success(request, f"{medicine_name} has been deleted successfully!")
    return redirect('medicine_list')

@login_required
def order_medicine(request):
    if request.method == 'POST':
        form = MedicineOrderForm(request.POST)
        if form.is_valid():
            order = form.save(commit=False)
            order.patient = request.user
            order.save()
            return redirect('medicine_order_success')
    else:
        form = MedicineOrderForm()
    return render(request, 'medicine/cart.html', {'form': form})

@login_required
def medicine_order_success(request):
    return render(request, 'medicine/order_success.html')

@login_required
def my_medicine_orders(request):
    orders = MedicineOrder.objects.filter(patient=request.user)
    return render(request, 'medicine/my_orders.html', {'orders': orders})

# --- Additional Admin Utilities ---
@staff_member_required
def dashboard_add_hospital(request):
    form = HospitalForm(request.POST or None)
    if form.is_valid():
        form.save()
        messages.success(request, 'Hospital added successfully!')
        return redirect('patient_dashboard')
    return render(request, 'dashboard_add_hospital.html', {'form': form})

@staff_member_required
def add_doctor_for_hospital(request, hospital_id):
    hospital = get_object_or_404(Hospital, id=hospital_id)
    if request.method == 'POST':
        form = DoctorForm(request.POST)
        if form.is_valid():
            doctor = form.save(commit=False)
            doctor.hospital = hospital
            doctor.save()
            request.session['doctor_message'] = f"Dr. {doctor.name} has been added to {hospital.name} successfully!"
            return redirect('doctor_list', hospital_name=hospital.name)
    else:
        form = DoctorForm()
    
    return render(request, 'doctor_form_for_hospital.html', {
        'form': form,
        'hospital': hospital
    })

@staff_member_required
def delete_doctor_from_list(request, doctor_id, hospital_name):
    doctor = get_object_or_404(Doctor, id=doctor_id)
    if request.method == 'POST':
        doctor.delete()
        messages.success(request, f"Dr. {doctor.name} has been removed successfully.")
    return redirect('doctor_list', hospital_name=hospital_name)

@login_required
def add_to_cart(request, medicine_id):
    medicine = get_object_or_404(Medicine, id=medicine_id)
    
    if request.method == 'POST':
        quantity = int(request.POST.get('quantity', 1))
        
        cart_item, created = CartItem.objects.get_or_create(
            patient=request.user,
            medicine=medicine,
            defaults={'quantity': quantity}
        )
        
        if not created:
            cart_item.quantity += quantity
            cart_item.save()
        
        messages.success(request, f"{medicine.name} added to your cart!")
        return redirect('medicine_list')
    
    return redirect('medicine_list')

@login_required
def view_cart(request):
    cart_items = CartItem.objects.filter(patient=request.user)
    total_amount = sum(item.total_price for item in cart_items)
    
    return render(request, 'medicine/cart.html', {
        'cart_items': cart_items,
        'total_amount': total_amount
    })

@login_required
def remove_from_cart(request, medicine_id):
    cart_item = get_object_or_404(CartItem, patient=request.user, medicine_id=medicine_id)
    cart_item.delete()
    messages.success(request, f"{cart_item.medicine.name} removed from your cart!")
    return redirect('view_cart')

@login_required
def checkout(request):
    cart_items = CartItem.objects.filter(patient=request.user)
    
    if not cart_items:
        messages.warning(request, "Your cart is empty!")
        return redirect('view_cart')
    
    for item in cart_items:
        if item.medicine.stock < item.quantity:
            messages.error(request, f"Not enough stock for {item.medicine.name}. Available: {item.medicine.stock}")
            return redirect('view_cart')
        
        order = MedicineOrder(
            patient=request.user,
            medicine=item.medicine,
            quantity=item.quantity
        )
        order.save()
        
        item.medicine.stock -= item.quantity
        item.medicine.save()
    
    cart_items.delete()
    
    messages.success(request, "Your order has been placed successfully!")
    return redirect('medicine_order_success')