"""
URL configuration for Backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from accounts.views import RegisterAccountsView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from accounts.views import EnforcePasswordChangeView, AdminDashboardView, CustomTokenObtainPairView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/accounts/', include('accounts.urls')),  # Includes all accounts-related URLs
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),  # Custom login with password change enforcement
    path('change-password/', EnforcePasswordChangeView.as_view(), name='change_password'),  # Password change page
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('/', AdminDashboardView.as_view(), name='admin_dashboard'),  # Admin dashboard
]