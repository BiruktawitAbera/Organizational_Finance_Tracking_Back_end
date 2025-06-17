# accounts/urls.py
from django.urls import path, include
from djoser.views import UserViewSet
from rest_framework.routers import DefaultRouter
from django.db.models.functions import TruncMonth

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
    ManagerBudgetRemainingView,
    ManagerBudgetUpdateView,
    ManagerBudgetDeleteView,

        # New views for income and expense
    IncomeCreateView,
    IncomeListView,
    DepartmentIncomeListView,
    IncomeDetailView,
    IncomeSummaryView,
    AdminIncomeHistoryView,
    DepartmentIncomeSummaryView,

        # expense tracking
    ExpenseCreateView,
    ExpenseListView,
    ExpenseUpdateView,
    DepartmentBudgetStatusView,
    ExpenseDetailListView,

    # budget request department head
    BudgetRequestCreateView,
    UserBudgetRequestListView,
    ManagerBudgetRequestListView,
    BudgetRequestUpdateView,

    # total income record quarterly
    IncomeTimelineView,
    # total approved expense record quarterly
    ExpenseTimelineView,
    # predictions

    BudgetPredictionView,
    # user profile
     UserProfileView, 
    #  dashboared
    ManagerDashboardView,
    DepartmentHeadDashboardView,
    UserDeleteView



)



urlpatterns = [
    path('register/', RegisterAccountsView.as_view(), name='register'),
    path('dashboard/admin/', AdminDashboardView.as_view(), name='admin_dashboard'), 
    path('change-password/', EnforcePasswordChangeView.as_view(), name='change_password'),
    path('user-role/', UserRoleView.as_view(), name="user_role"),
    path('users/', UserListView.as_view(), name='user-list'),
    path('users/<int:pk>/', UserListView.as_view(), name='user-delete'), 
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
    path('api/manager/budgets/create/', ManagerBudgetCreateView.as_view(), name='manager-budget-create'),
    path('api/manager/budgets/remaining/', ManagerBudgetRemainingView.as_view(), name='manager-budget-remaining'),
    path('manager/budgets/<int:pk>/update/', ManagerBudgetUpdateView.as_view(), name='manager-budget-update'),
    path('api/manager/budgets/<int:pk>/delete/', ManagerBudgetDeleteView.as_view(), name='manager-budget-delete'),

        # Income Management URLs
    
    path('incomes/', IncomeCreateView.as_view(), name='income-create'),
    # List all incomes (Admin/Manager) or department-specific (Department Head)
    path('income-list/', IncomeListView.as_view(), name='income-list'),
    
    # Department-specific incomes (Department Head + Admin/Manager)
    path('incomes/department/', DepartmentIncomeListView.as_view(), name='department-incomes'),
    
    # Income detail view
    path('incomes/<int:pk>/', IncomeDetailView.as_view(), name='income-detail'),
    
    # Full summary (Admin/Manager) or department summary (Department Head)
    path('incomes/summary/', IncomeSummaryView.as_view(), name='income-summary'),
    
    # Department-specific summary (Department Head only)
    path('incomes/department-summary/', DepartmentIncomeSummaryView.as_view(), name='department-income-summary'),
    
    # Full history with filters (Admin/Manager only)
    path('incomes/history/', AdminIncomeHistoryView.as_view(), name='income-history'),
    
    # expense
    path('expenses/create/', ExpenseCreateView.as_view(), name='expense-create'),
    path('expenses/', ExpenseListView.as_view(), name='expense-list'),
    path('expenses/<int:pk>/update/', ExpenseUpdateView.as_view(), name='expense-update'),
    path('budget-status/', DepartmentBudgetStatusView.as_view(), name='dept-budget-status'),
        # New detailed view
    path('expenses/all/', ExpenseDetailListView.as_view(), name='expense-detail-list'),
    # budget request department head
    path('budget-request/', BudgetRequestCreateView.as_view()),
    path('my-budget-requests/', UserBudgetRequestListView.as_view()),
    path('manager/budget-requests/', ManagerBudgetRequestListView.as_view()),
    path('budget-request/<int:pk>/', BudgetRequestUpdateView.as_view()),

    # total income record quarterly
    path('incomes/timeline/', IncomeTimelineView.as_view(), name='income-timeline'),

    # total approved expense record quarterly
    path('expenses/timeline/', ExpenseTimelineView.as_view(), name='expense-timeline'),
    # predicitons
    path('predictionss/',  BudgetPredictionView.as_view(), name='budget-predictions'),
    # user profile
    path('user-profile/', UserProfileView.as_view(), name='user-profile'),
    # dashboared
    path('dashboard/admin/', AdminDashboardView.as_view(), name='admin_dashboard'),
    path('manager/dashboard/', ManagerDashboardView.as_view(), name='manager_dashboard'),
    path('department/dashboard/', DepartmentHeadDashboardView.as_view(), name='dept_head_dashboard'),
    path('api/users/delete/<int:user_id>/', UserDeleteView.as_view(), name='user-delete'),


] 

         

