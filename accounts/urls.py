from django.urls import path
from .views import RegisterAccountsView, UserRoleView, AdminDashboardView, EnforcePasswordChangeView

urlpatterns = [
    path('register/', RegisterAccountsView.as_view(), name='register'),
    path('dashboard/admin/', AdminDashboardView.as_view(), name='admin_dashboard'), 
    path('change-password/', EnforcePasswordChangeView.as_view(), name='change_password'),
    path('user-role/', UserRoleView.as_view(), name="user_role"),
# Enforce page
]