import requests
import json

class FlaskAPIService:
    """Service to interact with Flask API endpoints"""
    
    def __init__(self, base_url='http://127.0.0.1:5000/api'):
        self.base_url = base_url
        
    def register_user(self, user_data):
        """Register a new user via Flask API"""
        url = f"{self.base_url}/register"
        try:
            response = requests.post(
                url, 
                json=user_data,
                headers={'Content-Type': 'application/json'}
            )
            return response.json(), response.status_code
        except Exception as e:
            return {'message': f'API Error: {str(e)}'}, 500
            
    def login_user(self, credentials):
        """Login user via Flask API"""
        url = f"{self.base_url}/login"
        try:
            response = requests.post(
                url, 
                json=credentials,
                headers={'Content-Type': 'application/json'}
            )
            return response.json(), response.status_code
        except Exception as e:
            return {'message': f'API Error: {str(e)}'}, 500
            
    def get_user_profile(self, token):
        """Get user profile data"""
        url = f"{self.base_url}/profile"
        try:
            response = requests.get(
                url,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {token}'
                }
            )
            return response.json(), response.status_code
        except Exception as e:
            return {'message': f'API Error: {str(e)}'}, 500
            
    def get_appointments(self, token):
        """Get user appointments"""
        url = f"{self.base_url}/appointments"
        try:
            response = requests.get(
                url,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {token}'
                }
            )
            return response.json(), response.status_code
        except Exception as e:
            return {'message': f'API Error: {str(e)}'}, 500