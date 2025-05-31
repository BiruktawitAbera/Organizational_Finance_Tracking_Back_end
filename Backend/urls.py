# Backend/urls.py
from django.contrib import admin
from django.urls import path, include
from accounts.views import (
    CustomTokenObtainPairView,
    EnforcePasswordChangeView,
    AdminDashboardView,
    RequestPasswordResetView,
    PasswordResetConfirmView,
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),

    # API URLs for accounts
    path('api/accounts/', include('accounts.urls')),  

    # JWT Authentication
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),


    # Password management
    path('change-password/', EnforcePasswordChangeView.as_view(), name='change_password'),
    path('admin-dashboard/', AdminDashboardView.as_view(), name='admin_dashboard'),

    # Password reset
    path('api/accounts/request-password-reset/', RequestPasswordResetView.as_view(), name='request-password-reset'),
    path('api/accounts/reset-password/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='reset-password-confirm'),

        # API URLs for finance management
    path('api/finance/', include([
        path('incomes/', include('accounts.urls')),  # All income URLs
        path('expenses/', include('accounts.urls')),  # All expense URLs
        path('reports/', include('accounts.urls')),   # All report URLs
        path('alerts/', include('accounts.urls')),    # All alert URLs
        path('dashboard/', include('accounts.urls')), # All dashboard URLs
    ])),

]

