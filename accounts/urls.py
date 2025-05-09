# accounts/urls.py
from django.urls import path, include
from djoser.views import UserViewSet
from .views import (
    RegisterAccountsView, 
    UserRoleView, 
    AdminDashboardView, 
    EnforcePasswordChangeView, 
    RequestPasswordResetView, 
    PasswordResetConfirmView,
# budget allocation
        # Admin Budget Views
    AdminBudgetListView,
    AdminBudgetCreateView,
    AdminBudgetDetailView,
    AdminBudgetUpdateView,
    AdminBudgetDeleteView,
    
    # Manager Budget Views
    ManagerBudgetListView,
    ManagerBudgetCreateView,
    ManagerBudgetRemainingView,
    UserListView,
    ManagerBudgetListView,
    ManagerBudgetCreateView,
    ManagerBudgetRemainingView
)

urlpatterns = [
    path('register/', RegisterAccountsView.as_view(), name='register'),
    path('dashboard/admin/', AdminDashboardView.as_view(), name='admin_dashboard'), 
    path('change-password/', EnforcePasswordChangeView.as_view(), name='change_password'),
    path('user-role/', UserRoleView.as_view(), name="user_role"),
    path('users/', UserListView.as_view(), name='user-list'),
    path('request-password-reset/', RequestPasswordResetView.as_view(), name="request-password-reset"),

    # Password reset confirmation URL (under api/accounts/)
    path('reset-password/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='reset-password-confirm'),
    path("auth/", include("djoser.urls")),
    path("auth/", include("djoser.urls.jwt")),
    path("auth/password/reset/confirm/", UserViewSet.as_view({'post': 'reset_password_confirm'})),

    # Budget allocation URLs
        # Admin Budget URLs
    path('admin/budgets/', AdminBudgetListView.as_view(), name='admin-budget-list'),
    path('admin/budgets/create/', AdminBudgetCreateView.as_view(), name='admin-budget-create'),
    path('admin/budgets/<int:id>/', AdminBudgetDetailView.as_view(), name='admin-budget-detail'),
    path('admin/budgets/<int:id>/update/', AdminBudgetUpdateView.as_view(), name='admin-budget-update'),
    path('admin/budgets/<int:id>/delete/', AdminBudgetDeleteView.as_view(), name='admin-budget-delete'),

    # CRUD FOR ADMIN
    path('admin/budgets/<int:pk>/update/', AdminBudgetUpdateView.as_view(), name='admin-budget-update'),
    path(
        'admin/budgets/<int:pk>/delete/',
        AdminBudgetDeleteView.as_view(),
        name='admin-budget-delete'
    ),
    
    # Manager Budget URLs
    path('manager/budgets/', ManagerBudgetListView.as_view(), name='manager-budget-list'),
    path('manager/budgets/create/', ManagerBudgetCreateView.as_view(), name='manager-budget-create'),
    path('manager/budgets/remaining/', ManagerBudgetRemainingView.as_view(), name='manager-budget-remaining'),

]

         

