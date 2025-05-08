from django.contrib import admin
from .models import (
    Hospital, Doctor, Appointment, MedicalRecord, AdminUser,
    Medicine, MedicineOrder
)


@admin.register(Hospital)
class HospitalAdmin(admin.ModelAdmin):
    list_display = ('name', 'city', 'state', 'fees_range')
    search_fields = ('name', 'city', 'state')


@admin.register(Doctor)
class DoctorAdmin(admin.ModelAdmin):
    list_display = ('name', 'specialty', 'experience', 'fees', 'hospital')
    list_filter = ('specialty', 'hospital')
    search_fields = ('name', 'specialty')


@admin.register(Appointment)
class AppointmentAdmin(admin.ModelAdmin):
    list_display = ('name', 'patient', 'doctor', 'hospital', 'date', 'time', 'payment_method', 'is_paid')
    list_filter = ('is_paid', 'payment_method', 'date')
    search_fields = ('name', 'patient__email', 'doctor__name')


@admin.register(MedicalRecord)
class MedicalRecordAdmin(admin.ModelAdmin):
    list_display = ('patient', 'date', 'condition')
    list_filter = ('date',)
    search_fields = ('patient__email', 'condition')


@admin.register(AdminUser)
class AdminUserAdmin(admin.ModelAdmin):
    list_display = ('user', 'position')
    search_fields = ('user__email', 'user__full_name')


@admin.register(Medicine)
class MedicineAdmin(admin.ModelAdmin):
    list_display = ('name', 'price', 'stock')
    search_fields = ('name',)


@admin.register(MedicineOrder)
class MedicineOrderAdmin(admin.ModelAdmin):
    list_display = ('patient', 'medicine', 'quantity', 'total_price', 'status', 'ordered_at')
    list_filter = ('status',)
    search_fields = ('patient__email', 'medicine__name')
