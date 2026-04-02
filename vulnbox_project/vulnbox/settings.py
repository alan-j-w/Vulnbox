import os
from pathlib import Path
from decouple import config, Csv
import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent

# ============================================================
# SECURITY SETTINGS
# For production: set these as environment variables and
# do NOT hardcode secrets here.
# ============================================================

# SECURITY WARNING: Generate a new key and keep it secret in production!
SECRET_KEY = config('SECRET_KEY', default='django-insecure-replace_this_with_real_secret_key')

# SECURITY WARNING: Set to False in production!
DEBUG = config('DEBUG', default=True, cast=bool)

# Allowed hosts (comma-separated in .env)
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='*', cast=Csv())

# ============================================================
# APPS
# ============================================================
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'core',
    'authapp',
    'curriculum',
    'certification',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'vulnbox.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'vulnbox.wsgi.application'

# Default: SQLite (for local dev)
# For production: set DATABASE_URL or individual DB_* env vars
# and switch to PostgreSQL
DATABASE_URL = config('DATABASE_URL', default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}")
DATABASES = {
    'default': dj_database_url.config(default=DATABASE_URL)
}

# Only apply these settings to professional databases (PostgreSQL/MySQL)
if 'sqlite' not in DATABASES['default']['ENGINE']:
    DATABASES['default']['conn_max_age'] = 600
    DATABASES['default']['ssl_require'] = not DEBUG

# ============================================================
# AUTH
# ============================================================
AUTH_USER_MODEL = 'authapp.CustomUser'
LOGIN_URL = 'authapp:login'
LOGIN_REDIRECT_URL = 'core:dashboard'
LOGOUT_REDIRECT_URL = 'core:home'

# ============================================================
# STATIC & MEDIA FILES
# ============================================================
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# ============================================================
# SESSION
# ============================================================
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_COOKIE_HTTPONLY = True  # Prevent JS access to session cookie
SESSION_COOKIE_SAMESITE = 'Lax'

# ============================================================
# SECURITY HEADERS (active when DEBUG=False)
# ============================================================
if not DEBUG:
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

# ============================================================
# AI ASSISTANT — Gemini API KEY
# In production: export GEMINI_API_KEY="your-key-here"
# ============================================================
GEMINI_API_KEY = config('GEMINI_API_KEY', default=None)

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
