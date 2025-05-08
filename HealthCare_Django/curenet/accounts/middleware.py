from django.shortcuts import redirect
from django.contrib import messages
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin

class FlaskAuthMiddleware(MiddlewareMixin):
    """Middleware to check Flask API authentication token"""
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        exempt_urls = [
            reverse('login'),
            reverse('logout'),
            reverse('signup'),
            reverse('index'),
            reverse('about'),
            reverse('contact'),
            reverse('blog'),
            reverse('forgot_password'),
        ]
        
        if request.path in exempt_urls or request.path.startswith('/static/'):
            return None
            
        if 'auth_token' not in request.session and hasattr(view_func, 'login_required'):
            messages.error(request, "Please log in to access this page.")
            return redirect('login')
            
        return None