from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role == 'admin'

class IsManager(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role in ['admin', 'manager']

class IsDepartmentHead(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role in ['admin', 'manager', 'department_head']


class CanVerifyIncome(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_manager() or request.user.is_superuser

class CanCreateIncome(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_department_head() or request.user.is_manager() or request.user.is_superuser

class CanViewAllIncomes(BasePermission):
    def has_permission(self, request, view):
        return request.user.has_perm('finance.view_all_incomes') or request.user.is_superuser