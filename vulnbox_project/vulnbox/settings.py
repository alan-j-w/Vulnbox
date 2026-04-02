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
    # Local Apps
    'core',
    'authapp',
    'curriculum',
    'certification',
    # Django Allauth
    'django.contrib.sites',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'cloudinary',
    'cloudinary_storage',
]

SITE_ID = 1

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
]

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
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

# Cloudinary Configuration
CLOUDINARY_URL = config('CLOUDINARY_URL', default=None)

if CLOUDINARY_URL:
    # Option 1: Let the cloudinary library pick it up from the environment
    import os
    os.environ["CLOUDINARY_URL"] = CLOUDINARY_URL
    
    # Option 2: Manually populate CLOUDINARY_STORAGE for django-cloudinary-storage
    import re
    try:
        # Regex to parse cloudinary://api_key:api_secret@cloud_name
        pattern = r"cloudinary://(?P<api_key>[^:]+):(?P<api_secret>[^@]+)@(?P<cloud_name>.+)"
        match = re.match(pattern, CLOUDINARY_URL)
        if match:
            CLOUDINARY_STORAGE = {
                'CLOUD_NAME': match.group('cloud_name'),
                'API_KEY': match.group('api_key'),
                'API_SECRET': match.group('api_secret'),
            }
        else:
            # Fallback if regex fails but URL exists
            CLOUDINARY_STORAGE = {
                'CLOUD_NAME': config('CLOUDINARY_CLOUD_NAME', default=''),
                'API_KEY': config('CLOUDINARY_API_KEY', default=''),
                'API_SECRET': config('CLOUDINARY_API_SECRET', default=''),
            }
    except Exception:
        CLOUDINARY_STORAGE = {}
else:
    CLOUDINARY_STORAGE = {
        'CLOUD_NAME': config('CLOUDINARY_CLOUD_NAME', default=''),
        'API_KEY': config('CLOUDINARY_API_KEY', default=''),
        'API_SECRET': config('CLOUDINARY_API_SECRET', default=''),
    }

DEFAULT_FILE_STORAGE = 'cloudinary_storage.storage.MediaCloudinaryStorage'

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

# ============================================================
# GOOGLE OAUTH (django-allauth)
# ============================================================
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': ['profile', 'email'],
        'AUTH_PARAMS': {'access_type': 'online'},
        # Credentials are managed via Django Admin:
        # /admin/socialaccount/socialapp/
    }
}

# Allauth settings
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = True
ACCOUNT_AUTHENTICATION_METHOD = 'email'
ACCOUNT_EMAIL_VERIFICATION = 'none'  # Set to 'mandatory' if you add email backend
SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_ADAPTER = 'authapp.adapters.CustomSocialAccountAdapter'
LOGIN_REDIRECT_URL = 'core:dashboard'
ACCOUNT_LOGOUT_REDIRECT_URL = 'core:home'
