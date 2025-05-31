from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent





SECRET_KEY = 'django-insecure-a&!t159&x^g@at16%6th@m%c9w=s@y73g(a62^^u4*xdg7#(os'


DEBUG = True

ALLOWED_HOSTS = []


CSRF_TRUSTED_ORIGINS = [
    "http://127.0.0.1:8000",  
    "http://localhost:8000",
]



INSTALLED_APPS = [
    # Default Django apps
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',  

    # Third-party apps
    'rest_framework',  # For API
    'rest_framework.authtoken',  # Token-based authentication
    'corsheaders',  # For frontend access
    'dj_rest_auth',
    'dj_rest_auth.registration',
    
    # django-allauth for authentication
    'allauth',
    'allauth.account',
    'allauth.socialaccount',  # Optional for social login

    # Your custom apps
    'accounts',  # Ensure your app is included
     
]
SITE_ID = 1
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware', # CORS Middleware
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',  # CSRF protection enabled
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    "accounts.middleware.ForcePasswordChangeMiddleware",


    
]

ROOT_URLCONF = 'Backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
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

WSGI_APPLICATION = 'Backend.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'finance_tracking_new',                       
        'USER': 'root',
        'PASSWORD': '1234',
        'HOST': 'localhost',  # Change if using a remote DB
        'PORT': '3306',       # Default MySQL port
        'OPTIONS': {
            'charset': 'utf8mb4',  # Supports full Unicode
        },
    }
}

# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
}


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

SILENCED_SYSTEM_CHECKS = ["models.W036"]


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Custom user model
AUTH_USER_MODEL = 'accounts.CustomUser'

# CORS Configuration (allowing frontend to make requests)
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",  # Update with the port where your frontend runs
]
AUTH_PASSWORD_VALIDATORS = []

CORS_ALLOW_ALL_ORIGINS = True


# Email Configuration (ensure you use app password if using Gmail)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False 
EMAIL_HOST_USER = 'birukspace0900@gmail.com'  # Your Gmail address
EMAIL_HOST_PASSWORD = 'pgfb lunj lqic fjcw'  # Use an App Password, NOT your real Gmail password!
DEFAULT_FROM_EMAIL = 'birukspace0900@gmail.com'

EMAIL_TIMEOUT = 30  # Reduces wait time in case of failure
EMAIL_USE_LOCALTIME = True

DJOSER = {
    'PASSWORD_RESET_CONFIRM_SERIALIZER': 'accounts.serializers.CustomPasswordResetConfirmSerializer',
}

