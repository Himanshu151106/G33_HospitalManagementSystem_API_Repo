
from django import template
from django.utils.safestring import mark_safe

register = template.Library()

@register.simple_tag(takes_context=True)
def is_flask_authenticated(context):
    """Check if a user is authenticated with the Flask API"""
    request = context['request']
    return 'auth_token' in request.session

@register.simple_tag(takes_context=True)
def get_flask_user(context):
    """Get the current Flask API user data"""
    request = context['request']
    return request.session.get('user_data', {})

@register.simple_tag
def get_flask_user_field(request, field_name):
    user_data = request.session.get('user_data', {})
    return user_data.get(field_name, 'Guest')