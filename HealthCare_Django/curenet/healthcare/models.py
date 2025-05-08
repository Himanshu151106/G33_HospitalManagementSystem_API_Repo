import re
from django.core.exceptions import ValidationError
from django.db import models
from django.conf import settings

User = settings.AUTH_USER_MODEL

class Hospital(models.Model):
    name = models.CharField(max_length=255)
    address = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    fees_range = models.CharField(max_length=50)
    
    def __str__(self):
        return self.name

class Doctor(models.Model):
    name = models.CharField(max_length=255)
    specialty = models.CharField(max_length=255)
    experience = models.IntegerField()
    fees = models.DecimalField(max_digits=10, decimal_places=2)
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='doctors')
    
    def __str__(self):
        return self.name

class Appointment(models.Model):
    PAYMENT_CHOICES = (
        ('credit-card', 'Credit/Debit Card'),
        ('paypal', 'PayPal'),
        ('bank-transfer', 'Bank Transfer'),
        ('cash', 'Cash on Meeting'),
    )
    
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='appointments')
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE, related_name='appointments', null=True, blank=True)
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='appointments', null=True, blank=True)
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=15)
    date = models.DateField()
    time = models.TimeField()
    reason = models.TextField()
    payment_method = models.CharField(max_length=20, choices=PAYMENT_CHOICES, default='cash')
    is_paid = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.name} - {self.doctor} - {self.date}"
    
    def clean(self):
        phone = self.phone
        phone = re.sub(r'\D', '', phone)
        
        if len(phone) != 10:
            raise ValidationError("Phone number must be exactly 10 digits.")
        
        return super().clean()

class MedicalRecord(models.Model):
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='medical_records')
    date = models.DateField()
    condition = models.CharField(max_length=255)
    treatment = models.TextField()
    
    def __str__(self):
        return f"{self.patient} - {self.condition} - {self.date}"

class AdminUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='admin_profile')
    position = models.CharField(max_length=100)
    
    def __str__(self):
        return self.user.email
    
class Medicine(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.PositiveIntegerField()
    
    def __str__(self):
        return self.name


class MedicineOrder(models.Model):
    ORDER_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]

    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='medicine_orders')
    medicine = models.ForeignKey(Medicine, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    total_price = models.DecimalField(max_digits=10, decimal_places=2, blank=True)
    status = models.CharField(max_length=20, choices=ORDER_STATUS_CHOICES, default='pending')
    ordered_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        self.total_price = self.medicine.price * self.quantity
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.patient} - {self.medicine.name} - {self.status}"


class CartItem(models.Model):
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='cart_items')
    medicine = models.ForeignKey(Medicine, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    added_at = models.DateTimeField(auto_now_add=True)
    
    @property
    def total_price(self):
        return self.medicine.price * self.quantity
    
    def __str__(self):
        return f"{self.patient.username} - {self.medicine.name} ({self.quantity})"


