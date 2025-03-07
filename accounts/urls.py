# accounts/urls.py
from django.urls import path
from django.urls import path, include
from djoser.views import UserViewSet
from .views import (
    RegisterAccountsView, 
    UserRoleView, 
    AdminDashboardView, 
    EnforcePasswordChangeView, 
    RequestPasswordResetView, 
    PasswordResetConfirmView,
    BudgetCreateView, 
    BudgetListView,
    BudgetDetailView, 
    BudgetUpdateView, 
    BudgetDeleteView

)

urlpatterns = [
    path('register/', RegisterAccountsView.as_view(), name='register'),
    path('dashboard/admin/', AdminDashboardView.as_view(), name='admin_dashboard'), 
    path('change-password/', EnforcePasswordChangeView.as_view(), name='change_password'),
    path('user-role/', UserRoleView.as_view(), name="user_role"),
    path('request-password-reset/', RequestPasswordResetView.as_view(), name="request-password-reset"),

    # Password reset confirmation URL (under api/accounts/)
    path('reset-password/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='reset-password-confirm'),
    path("auth/", include("djoser.urls")),
    path("auth/", include("djoser.urls.jwt")),
    path("auth/password/reset/confirm/", UserViewSet.as_view({'post': 'reset_password_confirm'})),

    # budget allocation
    
    path("budgets/", BudgetListView.as_view(), name="budget-list"),  # GET only
    path('budget/', BudgetCreateView.as_view(), name='budget-create'),  # Create budget allocation
    path('budget/<str:department_name>/', BudgetDetailView.as_view(), name='budget-detail'),  # View budget
    path('budget/<str:department_name>/update/', BudgetUpdateView.as_view(), name='budget-update'),  # Update budget
    path('budget/<str:department_name>/delete/', BudgetDeleteView.as_view(), name='budget-delete'),  # Delete budget
]

