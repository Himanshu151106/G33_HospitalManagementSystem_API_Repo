"""
WSGI config for curenet project.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'curenet.settings')

application = get_wsgi_application()