import random
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from healthcare.models import Hospital, Doctor, Appointment, MedicalRecord, AdminUser

User = get_user_model()

class Command(BaseCommand):
    help = 'Creates demo data for the CureNet application'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Creating demo data...'))
        
        # Create admin user if not exists
        if not User.objects.filter(email='admin@curenet.com').exists():
            admin_user = User.objects.create_superuser(
                email='admin@curenet.com',
                full_name='Admin User',
                password='admin'
            )
            AdminUser.objects.create(
                user=admin_user,
                position='System Administrator'
            )
            self.stdout.write(self.style.SUCCESS('Admin user created'))
        
        # Create demo patients
        patients = []
        patient_data = [
            {'email': 'patient1@example.com', 'full_name': 'Rahul Sharma', 'password': 'Patient@123'},
            {'email': 'patient2@example.com', 'full_name': 'Priya Patel', 'password': 'Patient@123'},
            {'email': 'patient3@example.com', 'full_name': 'Amit Singh', 'password': 'Patient@123'},
        ]
        
        for data in patient_data:
            if not User.objects.filter(email=data['email']).exists():
                user = User.objects.create_user(
                    email=data['email'],
                    full_name=data['full_name'],
                    password=data['password']
                )
                patients.append(user)
                self.stdout.write(self.style.SUCCESS(f"Created patient: {data['full_name']}"))
        
        # Create hospitals
        hospitals = []
        hospital_data = [
            {
                'name': 'City General Hospital',
                'address': '123 Healthcare Avenue',
                'city': 'Mumbai',
                'state': 'Maharashtra',
                'fees_range': '₹500-₹1500'
            },
            {
                'name': 'Apollo Hospitals',
                'address': '456 Wellness Street',
                'city': 'Delhi',
                'state': 'Delhi',
                'fees_range': '₹700-₹2000'
            },
            {
                'name': 'Fortis Healthcare',
                'address': '789 Medical Road',
                'city': 'Bangalore',
                'state': 'Karnataka',
                'fees_range': '₹600-₹1800'
            },
            {
                'name': 'Max Super Speciality Hospital',
                'address': '101 Health Park',
                'city': 'Chennai',
                'state': 'Tamil Nadu',
                'fees_range': '₹550-₹1700'
            }
        ]
        
        for data in hospital_data:
            hospital, created = Hospital.objects.get_or_create(
                name=data['name'],
                defaults={
                    'address': data['address'],
                    'city': data['city'],
                    'state': data['state'],
                    'fees_range': data['fees_range']
                }
            )
            hospitals.append(hospital)
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created hospital: {data['name']}"))
        
        # Create doctors
        doctors = []
        doctor_data = [
            {
                'name': 'Dr. Vikas Mehta',
                'specialty': 'Cardiology',
                'experience': 15,
                'fees': 1200,
                'hospital': hospitals[0]
            },
            {
                'name': 'Dr. Sunita Gupta',
                'specialty': 'Neurology',
                'experience': 12,
                'fees': 1500,
                'hospital': hospitals[0]
            },
            {
                'name': 'Dr. Rajesh Kumar',
                'specialty': 'Orthopedics',
                'experience': 10,
                'fees': 1000,
                'hospital': hospitals[1]
            },
            {
                'name': 'Dr. Priya Singh',
                'specialty': 'Gynecology',
                'experience': 8,
                'fees': 900,
                'hospital': hospitals[1]
            },
            {
                'name': 'Dr. Anand Verma',
                'specialty': 'Dermatology',
                'experience': 7,
                'fees': 800,
                'hospital': hospitals[2]
            },
            {
                'name': 'Dr. Neha Shah',
                'specialty': 'Pediatrics',
                'experience': 9,
                'fees': 850,
                'hospital': hospitals[2]
            },
            {
                'name': 'Dr. Suresh Patel',
                'specialty': 'Internal Medicine',
                'experience': 14,
                'fees': 1100,
                'hospital': hospitals[3]
            },
            {
                'name': 'Dr. Meera Joshi',
                'specialty': 'Ophthalmology',
                'experience': 11,
                'fees': 950,
                'hospital': hospitals[3]
            }
        ]
        
        for data in doctor_data:
            doctor, created = Doctor.objects.get_or_create(
                name=data['name'],
                defaults={
                    'specialty': data['specialty'],
                    'experience': data['experience'],
                    'fees': data['fees'],
                    'hospital': data['hospital']
                }
            )
            doctors.append(doctor)
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created doctor: {data['name']}"))
        
        # Create appointments
        if len(patients) > 0:
            appointment_data = []
            
            # Past appointments
            for i in range(5):
                days_ago = random.randint(1, 30)
                appointment_date = timezone.now().date() - timedelta(days=days_ago)
                appointment_time = datetime.strptime(f"{random.randint(9, 16)}:00", "%H:%M").time()
                
                patient = random.choice(patients)
                doctor = random.choice(doctors)
                
                appointment_data.append({
                    'patient': patient,
                    'doctor': doctor,
                    'hospital': doctor.hospital,
                    'name': patient.full_name,
                    'phone': f"+91 98765{random.randint(10000, 99999)}",
                    'date': appointment_date,
                    'time': appointment_time,
                    'reason': random.choice([
                        'Regular checkup',
                        'Fever and cold symptoms',
                        'Headache and dizziness',
                        'Follow-up consultation',
                        'Skin rash and itching'
                    ]),
                    'payment_method': random.choice([
                        'credit-card',
                        'paypal',
                        'bank-transfer',
                        'cash'
                    ]),
                    'is_paid': True,
                    'created_at': timezone.now() - timedelta(days=days_ago + random.randint(1, 5))
                })
            
            # Upcoming appointments
            for i in range(5):
                days_ahead = random.randint(1, 14)
                appointment_date = timezone.now().date() + timedelta(days=days_ahead)
                appointment_time = datetime.strptime(f"{random.randint(9, 16)}:00", "%H:%M").time()
                
                patient = random.choice(patients)
                doctor = random.choice(doctors)
                
                is_paid = random.choice([True, False])
                payment_method = 'cash' if not is_paid else random.choice([
                    'credit-card',
                    'paypal',
                    'bank-transfer',
                    'cash'
                ])
                
                appointment_data.append({
                    'patient': patient,
                    'doctor': doctor,
                    'hospital': doctor.hospital,
                    'name': patient.full_name,
                    'phone': f"+91 98765{random.randint(10000, 99999)}",
                    'date': appointment_date,
                    'time': appointment_time,
                    'reason': random.choice([
                        'Annual physical examination',
                        'Chronic pain consultation',
                        'Allergic reactions',
                        'Stomach pain and nausea',
                        'Respiratory issues'
                    ]),
                    'payment_method': payment_method,
                    'is_paid': is_paid,
                    'created_at': timezone.now() - timedelta(days=random.randint(1, 5))
                })
            
            # Create appointments
            for data in appointment_data:
                appointment, created = Appointment.objects.get_or_create(
                    patient=data['patient'],
                    date=data['date'],
                    time=data['time'],
                    defaults={
                        'doctor': data['doctor'],
                        'hospital': data['hospital'],
                        'name': data['name'],
                        'phone': data['phone'],
                        'reason': data['reason'],
                        'payment_method': data['payment_method'],
                        'is_paid': data['is_paid'],
                        'created_at': data['created_at']
                    }
                )
                if created:
                    self.stdout.write(self.style.SUCCESS(f"Created appointment for {data['name']} on {data['date']}"))
            
            # Create medical records
            for patient in patients:
                for i in range(random.randint(1, 3)):
                    days_ago = random.randint(30, 365)
                    record_date = timezone.now().date() - timedelta(days=days_ago)
                    
                    conditions = [
                        'Common Cold',
                        'Seasonal Flu',
                        'Hypertension',
                        'Diabetes Type 2',
                        'Allergic Rhinitis',
                        'Migraine',
                        'Lower Back Pain',
                        'Gastritis',
                        'Vitamin D Deficiency',
                        'Anemia'
                    ]
                    
                    treatments = [
                        'Prescribed antibiotics for 5 days',
                        'Rest and hydration recommended',
                        'Regular monitoring and lifestyle changes advised',
                        'Prescribed pain relievers and physical therapy',
                        'Dietary modifications and supplements prescribed',
                        'Referred to specialist for further evaluation',
                        'Vaccination administered',
                        'Prescribed medication with follow-up in 2 weeks',
                        'Diagnostic tests ordered',
                        'Counseling and stress management techniques suggested'
                    ]
                    
                    record, created = MedicalRecord.objects.get_or_create(
                        patient=patient,
                        date=record_date,
                        defaults={
                            'condition': random.choice(conditions),
                            'treatment': random.choice(treatments)
                        }
                    )
                    if created:
                        self.stdout.write(self.style.SUCCESS(f"Created medical record for {patient.full_name} on {record_date}"))
        
        self.stdout.write(self.style.SUCCESS('Demo data creation completed!'))