import requests
from django.core.management.base import BaseCommand
from django.contrib import messages
from django.shortcuts import redirect, render
from .models import Medicine
from .forms import MedicineForm
from django.contrib.admin.views.decorators import staff_member_required

class Command(BaseCommand):
    help = 'Fetch medicines from DailyMed API and add to database'

    def handle(self, *args, **kwargs):
        api_url = "https://dailymed.nlm.nih.gov/dailymed/services/v2/spls.json"
        params = {"drug_name": "aspirin"}  # Example search for aspirin; can be modified
        try:
            response = requests.get(api_url, params=params)
            response.raise_for_status()
            data = response.json()
            medicines = data.get('data', [])

            for medicine_data in medicines:
                name = medicine_data.get('title', '').split(' - ')[0]  # Extract medicine name
                if not Medicine.objects.filter(name=name).exists():
                    Medicine.objects.create(
                        name=name,
                        description=medicine_data.get('description', 'No description available'),
                        price=10.00,  # Placeholder; DailyMed doesn't provide price
                        stock=100     # Placeholder; DailyMed doesn't provide stock
                    )
            self.stdout.write(self.style.SUCCESS('Successfully fetched and added medicines from DailyMed API'))
        except requests.RequestException as e:
            self.stdout.write(self.style.ERROR(f'Error fetching medicines: {str(e)}'))

@staff_member_required
def fetch_external_medicines(request):
    if request.method == 'POST':
        api_url = "https://dailymed.nlm.nih.gov/dailymed/services/v2/spls.json"
        params = {"drug_name": request.POST.get('drug_name', 'aspirin')}  # Allow user input for search
        try:
            response = requests.get(api_url, params=params)
            response.raise_for_status()
            data = response.json()
            medicines = data.get('data', [])

            for medicine_data in medicines:
                name = medicine_data.get('title', '').split(' - ')[0]
                if not Medicine.objects.filter(name=name).exists():
                    Medicine.objects.create(
                        name=name,
                        description=medicine_data.get('description', 'No description available'),
                        price=10.00,  # Placeholder
                        stock=100     # Placeholder
                    )
            messages.success(request, "Successfully fetched and added medicines from DailyMed API")
        except requests.RequestException as e:
            messages.error(request, f"Error fetching medicines: {str(e)}")
        return redirect('medicine_list')
    
    return render(request, 'medicine/fetch_external.html', {})