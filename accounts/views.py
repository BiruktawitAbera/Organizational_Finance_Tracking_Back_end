from rest_framework import generics,permissions, status
from django.contrib.auth import get_user_model, authenticate
from .serializers import AccountRegistrationSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_str 
from django.core.mail import send_mail
from functools import wraps
from rest_framework.permissions import AllowAny
from rest_framework import status, generics
from rest_framework.response import Response
from .serializers import PasswordResetSerializer
from rest_framework import serializers, viewsets, status, mixins
from rest_framework.decorators import action

from .models import  User
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from .models import CustomUser
import logging
from django.db.models import Q , Sum , Count
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import AdminBudget, ManagerBudget, User, BudgetRequest
from .serializers import AdminBudgetSerializer, ManagerBudgetSerializer, UserSerializer, BudgetRequestSerializer, BudgetRequestUpdateSerializer

from .models import   CustomUser
from .serializers import (
    AccountRegistrationSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    ExpenseDetailSerializer

)
from django.utils import timezone
from datetime import timedelta
from .models import (
    User, 
)

from .models import Income
from .serializers import IncomeSerializer
from .permissions import (
    CanCreateIncome, CanVerifyIncome, IsDepartmentHead, 
    IsManager, IsAdmin, CanViewAllIncomes
)
from .models import Expense, ManagerBudget
from .serializers import ExpenseSerializer, ExpenseUpdateSerializer

import logging

from django.db.models import Sum, F, Func, Value, CharField
from django.db.models.functions import ExtractMonth, ExtractYear, ExtractQuarter, TruncMonth, TruncQuarter
from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response

from django.core.exceptions import EmptyResultSet
from rest_framework.exceptions import ValidationError

# Get user model
User = get_user_model()
logger = logging.getLogger(__name__)

# Custom permission classes
class IsManager(permissions.BasePermission):
    """Allows access only to manager users."""
    def has_permission(self, request, view):
        return request.user.is_manager()

class IsDepartmentHead(permissions.BasePermission):
    """Allows access only to department head users."""
    def has_permission(self, request, view):
        return request.user.is_department_head()

User = get_user_model()
logger = logging.getLogger(__name__)

# ✅ Decorator for Role-Based Access Control
def role_required(allowed_roles):
    """Decorator to restrict API access based on user role"""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(self, request, *args, **kwargs):
            if request.user.role not in allowed_roles:
                return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
            return view_func(self, request, *args, **kwargs)
        return _wrapped_view
    return decorator

# ✅ Register a new user
class RegisterAccountsView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = AccountRegistrationSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        user = User.objects.get(email=response.data["email"])  # Get newly created user

        # ✅ Generate JWT tokens for the new user
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        response.data["access"] = access_token
        response.data["refresh"] = str(refresh)
        response.data["role"] = user.role  # ✅ Add user role to response

        return response

# ✅ Custom login view - Includes role in response
class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")

        user = authenticate(request, username=email, password=password)

        if user:
            # ✅ Check if the user is required to change their password
            if not user.has_changed_password:
                return Response(
                    {"detail": "Password change required", "force_password_change": True},
                    status=status.HTTP_403_FORBIDDEN
                )

            # ✅ Proceed with issuing tokens
            response = super().post(request, *args, **kwargs)
            response.data['full_name'] = user.get_full_name()
            response.data['role'] = user.role  # ✅ Include user role

            return response

        return Response({"detail": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)

# ✅ Force users to change password
class EnforcePasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        print("User:", user)  # ✅ Check if Django recognizes the logged-in user
        print("Old Password Entered:", old_password)  # ✅ Check if password is received correctly

        if not old_password or not new_password or not confirm_password:
            return Response({"error": "All password fields are required"}, status=status.HTTP_400_BAD_REQUEST)

        if new_password != confirm_password:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Debugging: Check if old password matches
        if not user.check_password(old_password):
            print("❌ Old password does not match!")
            return Response({"error": "Incorrect old password"}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Set the new password
        user.set_password(new_password)
        user.has_changed_password = True  # ✅ Mark password as changed
        user.save()

        # ✅ Generate new JWT tokens after the password change
        refresh = RefreshToken.for_user(user)

        return Response({
            "message": "Password updated successfully",
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        }, status=status.HTTP_200_OK)
class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    @role_required(["admin"])
    def get(self, request):
        if not request.user.has_changed_password:
            return Response({"detail": "Password change required"}, status=status.HTTP_403_FORBIDDEN)

        return Response({"message": "Welcome, Admin!"}, status=status.HTTP_200_OK)

# ✅ Manager Dashboard - Requires Manager or Admin Role
class ManagerDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    @role_required(["admin", "manager"])
    def get(self, request):
        if not request.user.has_changed_password:
            return Response({"detail": "Password change required"}, status=status.HTTP_403_FORBIDDEN)

        return Response({"message": "Welcome, Manager!"}, status=status.HTTP_200_OK)

# ✅ Department Head Dashboard - Requires Department Head Role
class DepartmentHeadDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    @role_required(["admin", "manager", "department_head"])
    def get(self, request):
        if not request.user.has_changed_password:
            return Response({"detail": "Password change required"}, status=status.HTTP_403_FORBIDDEN)

        return Response({"message": "Welcome, Department Head!"}, status=status.HTTP_200_OK)

# ✅ Get user role endpoint
class UserRoleView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"role": request.user.role})

class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        role = request.query_params.get('role')
        if not role:
            return Response({"error": "Role parameter is required"}, status=status.HTTP_400_BAD_REQUEST)

        users = CustomUser.objects.filter(role=role)
        data = [{"email": user.email, "department": user.department} for user in users]
        return Response(data)

class RequestPasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer
    permission_classes = [AllowAny]  # Allow unauthenticated access to this endpoint

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.send_password_reset_email(request)
            return Response({"message": "Password reset link sent to email."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# ✅ Password Reset Confirmation View
class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]  # This allows unauthenticated access to the view.

    def post(self, request, uidb64, token):
        # Decode the UID from the URL (which is base64-encoded)
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.get(pk=uid)  # Get user by decoded ID
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            # If the user does not exist or the decoding fails, return an error
            return Response({"detail": "Invalid token or user."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the provided token is valid for this user
        if not default_token_generator.check_token(user, token):
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

        # Retrieve the new password and confirm password from the request body
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        # Validate that the passwords are not empty
        if not new_password or not confirm_password:
            return Response({"detail": "Password is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if the passwords match
        if new_password != confirm_password:
            return Response({"detail": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

        # Set the new password for the user
        user.set_password(new_password)

        # Optional: If you want to ensure the user is active after a password reset, you can do it here.
        user.is_active = True  # Activate the user if necessary (if account was inactive)
        user.save()

        # Return a success message indicating that the password was successfully reset
        return Response({"detail": "Password reset successful. You can now log in."}, status=status.HTTP_200_OK)

class AdminBudgetListView(generics.ListAPIView):
    serializer_class = AdminBudgetSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_admin():
            return AdminBudget.objects.filter(allocated_by=user)
        elif user.is_manager():
            return AdminBudget.objects.filter(allocated_to=user, budget_level='organization')
        elif user.is_department_head():
            return AdminBudget.objects.filter(allocated_to=user, budget_level='department')
        return AdminBudget.objects.none()

class AdminBudgetCreateView(generics.CreateAPIView):
    serializer_class = AdminBudgetSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(allocated_by=self.request.user)

class AdminBudgetDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, id):
        try:
            budget = AdminBudget.objects.get(
                Q(id=id) & 
                (Q(allocated_by=request.user) | Q(allocated_to=request.user))
            )
            serializer = AdminBudgetSerializer(budget)
            return Response(serializer.data)
        except AdminBudget.DoesNotExist:
            return Response(
                {"error": "Budget not found or unauthorized access"},
                status=status.HTTP_404_NOT_FOUND
            )

class AdminBudgetUpdateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, id):
        try:
            budget = AdminBudget.objects.get(id=id)
            if budget.allocated_by != request.user:
                return Response(
                    {"error": "You can only update your own allocations"},
                    status=status.HTTP_403_FORBIDDEN
                )
            serializer = AdminBudgetSerializer(budget, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except AdminBudget.DoesNotExist:
            return Response(
                {"error": "Budget not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )

class AdminBudgetDeleteView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, id):
        try:
            budget = AdminBudget.objects.get(id=id)
            if budget.allocated_by != request.user:
                return Response(
                    {"error": "You can only delete your own allocations"},
                    status=status.HTTP_403_FORBIDDEN
                )
            budget.delete()
            return Response(
                {"message": "Budget allocation deleted successfully"},
                status=status.HTTP_204_NO_CONTENT
            )
        except AdminBudget.DoesNotExist:
            return Response(
                {"error": "Budget not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )

# CRUD for admin

class AdminBudgetUpdateView(APIView):
    """
    Bulletproof budget update endpoint with:
    - Complete error handling
    - Multiple PK extraction methods
    - Comprehensive validation
    - Detailed logging
    """
    permission_classes = [permissions.IsAuthenticated]

    def extract_budget_id(self, request, kwargs):
        """Safely extract budget ID from all possible sources"""
        try:
            # Check all possible parameter locations
            possible_sources = [
                kwargs.get('pk'),
                kwargs.get('id'),
                getattr(request.resolver_match, 'kwargs', {}).get('pk'),
                request.GET.get('pk'),
                request.data.get('id'),
                request.data.get('pk'),
                request.path.strip('/').split('/')[-2]  # Fallback from URL path
            ]
            
            # Find first valid integer value
            for source in possible_sources:
                try:
                    if source is not None:
                        return int(source)
                except (ValueError, TypeError):
                    continue
            
            logger.error(f"Budget ID extraction failed. Sources: {possible_sources}")
            return None
            
        except Exception as e:
            logger.exception("Budget ID extraction crashed")
            return None

    def validate_update_data(self, budget, data):
        """Validate all update parameters"""
        errors = {}
        
        # Budget level validation
        if 'budget_level' in data and data['budget_level'] != budget.budget_level:
            errors['budget_level'] = "Cannot change budget level after creation"
        
        # Amount validation
        if 'allocated_amount' in data:
            try:
                new_amount = float(data['allocated_amount'])
                
                if budget.budget_level == 'organization':
                    total_allocated = ManagerBudget.objects.filter(
                        allocated_to=budget.allocated_to
                    ).aggregate(total=Sum('amount'))['total'] or 0
                    
                    if new_amount < float(total_allocated):
                        errors['allocated_amount'] = (
                            f"Cannot reduce below allocated amount: {total_allocated}"
                        )
            except (ValueError, TypeError):
                errors['allocated_amount'] = "Must be a valid number"
        
        return errors

    def put(self, request, *args, **kwargs):
        """Handle PUT requests with comprehensive error handling"""
        try:
            # ===== STEP 1: Extract and validate budget ID =====
            budget_id = self.extract_budget_id(request, kwargs)
            if not budget_id:
                return Response(
                    {"error": "Could not determine budget ID from URL"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            logger.info(f"Attempting update for budget ID: {budget_id}")
            
            # ===== STEP 2: Retrieve budget instance =====
            try:
                budget = AdminBudget.objects.get(pk=budget_id)
            except AdminBudget.DoesNotExist:
                return Response(
                    {"error": "Budget not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # ===== STEP 3: Authorization check =====
            if budget.allocated_by != request.user or not request.user.is_admin():
                return Response(
                    {"error": "Only the allocating admin can update this budget"},
                    status=status.HTTP_403_FORBIDDEN
                )

            # ===== STEP 4: Data validation =====
            data = request.data.copy()
            validation_errors = self.validate_update_data(budget, data)
            
            if validation_errors:
                return Response(
                    {"errors": validation_errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # ===== STEP 5: Serialization and save =====
            serializer = AdminBudgetSerializer(
                budget,
                data=data,
                partial=True,
                context={'request': request}
            )
            
            if not serializer.is_valid():
                return Response(
                    serializer.errors,
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer.save()
            logger.info(f"Successfully updated budget ID: {budget_id}")
            return Response(serializer.data)

        except Exception as e:
            logger.exception("Unexpected error in budget update")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
class AdminBudgetDeleteView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, id):
        try:
            budget = AdminBudget.objects.get(id=id)
            
            # Authorization - Only admin who created can delete
            if budget.allocated_by != request.user or not request.user.is_admin():
                return Response(
                    {"error": "Only the admin who allocated this budget can delete it"},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Prevent deletion if budget has been partially allocated
            if budget.budget_level == 'organization':
                total_allocated = ManagerBudget.objects.filter(
                    allocated_to=budget.allocated_to
                ).aggregate(total=Sum('amount'))['total'] or 0
                
                if float(total_allocated) > 0:
                    return Response(
                        {
                            "error": "Cannot delete organization budget with existing allocations",
                            "allocated_amount": total_allocated
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            budget.delete()
            return Response(
                {"message": "Admin budget allocation deleted successfully"},
                status=status.HTTP_204_NO_CONTENT
            )

        except AdminBudget.DoesNotExist:
            return Response(
                {"error": "Admin budget not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )

# Manager Budget Views
class ManagerBudgetListView(generics.ListAPIView):
    serializer_class = ManagerBudgetSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_manager():
            return ManagerBudget.objects.filter(allocated_by=user)
        elif user.is_department_head():
            return ManagerBudget.objects.filter(allocated_to=user)
        return ManagerBudget.objects.none()

class ManagerBudgetCreateView(generics.CreateAPIView):
    serializer_class = ManagerBudgetSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        if not user.is_manager():
            raise permissions.PermissionDenied("Only managers can allocate department budgets")
        
        budget_data = serializer.validated_data
        amount = budget_data.get('amount')
        budget_level = budget_data.get('budget_level')

        if budget_level != 'department':
            raise serializers.ValidationError("Managers can only allocate department-level budgets")

        total_allocated = ManagerBudget.objects.filter(
            allocated_by=user,
            budget_level='department'
        ).aggregate(total=Sum('amount'))['total'] or 0

        manager_budget = AdminBudget.objects.filter(
            allocated_to=user,
            budget_level='organization'
        ).first()

        if not manager_budget:
            raise serializers.ValidationError("No organizational budget allocated to this manager")

        remaining_budget = float(manager_budget.allocated_amount) - float(total_allocated)

        if float(amount) > remaining_budget:
            raise serializers.ValidationError(
                f"Not enough remaining budget. Only {remaining_budget} available."
            )

        serializer.save(allocated_by=user)

class ManagerBudgetRemainingView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        if not user.is_manager():
            raise permissions.PermissionDenied("Only managers can check remaining budget")

        manager_budget = AdminBudget.objects.filter(
            allocated_to=user,
            budget_level='organization'
        ).first()

        if not manager_budget:
            return Response(
                {"error": "No organizational budget allocated to this manager"},
                status=status.HTTP_404_NOT_FOUND
            )

        total_allocated = ManagerBudget.objects.filter(
            allocated_by=user,
            budget_level='department'
        ).aggregate(total=Sum('amount'))['total'] or 0

        remaining = float(manager_budget.allocated_amount) - float(total_allocated)

        return Response({
            'total_amount': manager_budget.allocated_amount,
            'allocated_amount': total_allocated,
            'remaining_amount': remaining,
        })
    
class ManagerBudgetUpdateView(APIView):
    """
    Secure manager budget update endpoint with:
    - Comprehensive error handling
    - Strict permission checks
    - Budget validation
    - Detailed logging
    """
    permission_classes = [permissions.IsAuthenticated]

    def extract_budget_id(self, request, kwargs):
        """Safely extract budget ID from all possible sources"""
        try:
            # Check all possible parameter locations
            possible_sources = [
                kwargs.get('pk'),
                kwargs.get('id'),
                request.GET.get('pk'),
                request.data.get('id'),
                request.data.get('pk'),
                request.path.strip('/').split('/')[-1]  # Fallback from URL path
            ]
            
            # Find first valid integer value
            for source in possible_sources:
                try:
                    if source is not None:
                        return int(source)
                except (ValueError, TypeError):
                    continue
            
            logger.error(f"Budget ID extraction failed. Sources: {possible_sources}")
            return None
            
        except Exception as e:
            logger.exception("Budget ID extraction crashed")
            return None

    def validate_update_data(self, budget, data, request):
        """Validate all update parameters for manager budget"""
        errors = {}
        
        # Budget level validation
        if 'budget_level' in data and data['budget_level'] != budget.budget_level:
            errors['budget_level'] = "Cannot change budget level after creation"
        
        # Amount validation
        if 'amount' in data:
            try:
                new_amount = float(data['amount'])
                old_amount = float(budget.amount)
                amount_difference = new_amount - old_amount
                
                # Only check if increasing the amount
                if amount_difference > 0:
                    # Get remaining budget from admin allocation
                    admin_budget = AdminBudget.objects.filter(
                        allocated_to=request.user,
                        budget_level='organization'
                    ).first()
                    
                    if admin_budget:
                        total_allocated = ManagerBudget.objects.filter(
                            allocated_by=request.user
                        ).exclude(id=budget.id).aggregate(total=Sum('amount'))['total'] or 0
                        
                        remaining = float(admin_budget.allocated_amount) - float(total_allocated)
                        
                        if amount_difference > remaining:
                            errors['amount'] = (
                                f"Update would exceed remaining budget by {amount_difference - remaining}. "
                                f"Only {remaining} available."
                            )
            except (ValueError, TypeError):
                errors['amount'] = "Must be a valid number"
        
        # Department validation for department-level budgets
        if budget.budget_level == 'department' and 'department' in data:
            if not data['department']:
                errors['department'] = "Department must be specified for department-level budgets"
        
        return errors

    def put(self, request, *args, **kwargs):
        """Handle PUT requests with comprehensive error handling"""
        try:
            # ===== STEP 1: Extract and validate budget ID =====
            budget_id = self.extract_budget_id(request, kwargs)
            if not budget_id:
                return Response(
                    {"error": "Could not determine budget ID from URL"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            logger.info(f"Attempting manager budget update for ID: {budget_id}")
            
            # ===== STEP 2: Retrieve budget instance =====
            try:
                budget = ManagerBudget.objects.get(pk=budget_id)
            except ManagerBudget.DoesNotExist:
                return Response(
                    {"error": "Manager budget not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # ===== STEP 3: Authorization check =====
            if budget.allocated_by != request.user or not request.user.is_manager():
                return Response(
                    {"error": "Only the allocating manager can update this budget"},
                    status=status.HTTP_403_FORBIDDEN
                )

            # ===== STEP 4: Data validation =====
            data = request.data.copy()
            validation_errors = self.validate_update_data(budget, data, request)
            
            if validation_errors:
                return Response(
                    {"errors": validation_errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Handle allocated_to_email if provided
            if 'allocated_to_email' in data:
                try:
                    allocated_to = User.objects.get(email=data['allocated_to_email'])
                    if budget.budget_level == 'department' and not allocated_to.is_department_head():
                        return Response(
                            {"error": "Department budgets must be allocated to department heads"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    data['allocated_to'] = allocated_to.id
                except User.DoesNotExist:
                    return Response(
                        {"allocated_to_email": "User with this email does not exist"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # ===== STEP 5: Serialization and save =====
            serializer = ManagerBudgetSerializer(
                budget,
                data=data,
                partial=True,
                context={'request': request}
            )
            
            if not serializer.is_valid():
                return Response(
                    serializer.errors,
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer.save()
            logger.info(f"Successfully updated manager budget ID: {budget_id}")
            return Response(serializer.data)

        except Exception as e:
            logger.exception("Unexpected error in manager budget update")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ManagerBudgetDeleteView(APIView):
    """
    Secure manager budget deletion endpoint with:
    - Permission checks
    - Validation of dependencies
    - Detailed logging
    """
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        try:
            # ===== STEP 1: Extract budget ID =====
            budget_id = kwargs.get('pk') or kwargs.get('id')
            if not budget_id:
                return Response(
                    {"error": "Budget ID not provided"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            logger.info(f"Attempting to delete manager budget ID: {budget_id}")
            
            # ===== STEP 2: Retrieve budget instance =====
            try:
                budget = ManagerBudget.objects.get(pk=budget_id)
            except ManagerBudget.DoesNotExist:
                return Response(
                    {"error": "Manager budget not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # ===== STEP 3: Authorization check =====
            if budget.allocated_by != request.user or not request.user.is_manager():
                return Response(
                    {"error": "Only the allocating manager can delete this budget"},
                    status=status.HTTP_403_FORBIDDEN
                )

            # ===== STEP 4: Perform deletion =====
            budget.delete()
            logger.info(f"Successfully deleted manager budget ID: {budget_id}")
            return Response(
                {"message": "Manager budget allocation deleted successfully"},
                status=status.HTTP_204_NO_CONTENT
            )

        except Exception as e:
            logger.exception("Unexpected error in manager budget deletion")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
# income and expense tracking

class IncomeCreateView(generics.CreateAPIView):
    serializer_class = IncomeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        if not user.is_department_head:
            raise permissions.PermissionDenied(
                "Only department heads can create income records"
            )
        serializer.save(
            created_by=user,
            department=user.department  # Set department from user's department
        )

class IncomeListView(generics.ListAPIView):
    serializer_class = IncomeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        department = self.request.query_params.get('department', None)
        
        queryset = Income.objects.all()
        
        if user.is_department_head:
            queryset = queryset.filter(department=user.department)
        elif not (user.is_manager or user.is_superuser):
            queryset = queryset.none()
        
        if department and (user.is_manager or user.is_superuser):
            queryset = queryset.filter(department=department)
            
        return queryset

class DepartmentIncomeListView(generics.ListAPIView):
    serializer_class = IncomeSerializer
    permission_classes = [permissions.IsAuthenticated, IsDepartmentHead | IsManager | IsAdmin]

    def get_queryset(self):
        user = self.request.user
        if user.is_department_head:
            return Income.objects.filter(department=user.department)
        return Income.objects.all()

class IncomeDetailView(generics.RetrieveAPIView):
    queryset = Income.objects.all()
    serializer_class = IncomeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.is_manager:
            return Income.objects.all()
        if user.is_department_head:
            return Income.objects.filter(department=user.department)
        return Income.objects.none()

class IncomeSummaryView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated, IsManager | IsAdmin]
    
    def get(self, request):
        queryset = Income.objects.all()
        
        department_summary = queryset.values('department').annotate(
            total_amount=Sum('amount'),
            count=Count('id')  # Removed "models." prefix here
        ).order_by('department')

        total_income = queryset.aggregate(total=Sum('amount'))['total'] or 0

        return Response({
            'department_summary': department_summary,
            'total_income': total_income
        })
class DepartmentIncomeSummaryView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated, IsDepartmentHead]

    def get(self, request):
        user = request.user
        queryset = Income.objects.filter(department=user.department)
        
        summary = queryset.aggregate(
            total_amount=Sum('amount'),
            total_records=Count('id')
        )

        return Response({
            'department': user.department,
            'total_amount': summary['total_amount'] or 0,
            'total_records': summary['total_records'] or 0
        })
    
class AdminIncomeHistoryView(generics.ListAPIView):
    serializer_class = IncomeSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdmin | IsManager]
    filterset_fields = ['department']
    search_fields = ['description']
    ordering_fields = ['date', 'amount', 'created_at']

    def get_queryset(self):
        return Income.objects.all()
    

# Expense logic

# Department Head: Create Expense
class ExpenseCreateView(generics.CreateAPIView):
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        if not user.is_department_head():
            raise permissions.PermissionDenied("Only department heads can create expenses")
        
        budget = ManagerBudget.objects.filter(
            allocated_to=user
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        used_budget = Expense.objects.filter(
            department_head=user,
            status__in=['PENDING', 'APPROVED']
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        amount = serializer.validated_data['amount']
        if float(used_budget) + float(amount) > float(budget):
            available = float(budget) - float(used_budget)
            raise serializers.ValidationError(
                f"Exceeds available budget. Remaining: {available:.2f}"
            )
        
        manager_budget = ManagerBudget.objects.filter(allocated_to=user).first()
        serializer.save(
            department_head=user,
            manager=manager_budget.allocated_by if manager_budget else None
        )

class ExpenseListView(generics.ListAPIView):
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        queryset = Expense.objects.all()
        
        if user.is_admin():
            return queryset
        elif user.is_manager():
            return queryset.filter(manager=user)
        elif user.is_department_head():
            return queryset.filter(department_head=user)
        
        return queryset.none()

class ExpenseUpdateView(generics.UpdateAPIView):
    queryset = Expense.objects.all()
    serializer_class = ExpenseUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_update(self, serializer):
        user = self.request.user
        expense = self.get_object()
        
        if not user.is_manager():
            raise permissions.PermissionDenied("Only managers can approve expenses")
        
        if expense.manager != user:
            raise permissions.PermissionDenied("You don't manage this expense")
        
        new_status = serializer.validated_data['status']
        valid_statuses = [Expense.APPROVED, Expense.DISAPPROVED]
        
        if new_status not in valid_statuses:
            raise serializers.ValidationError(
                f"Invalid status. Allowed: {', '.join(valid_statuses)}"
            )
        
        serializer.save()

class DepartmentBudgetStatusView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        if not user.is_department_head():
            raise permissions.PermissionDenied("Only department heads can view budget status")
        
        allocated = ManagerBudget.objects.filter(
            allocated_to=user
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        expenses = Expense.objects.filter(department_head=user).aggregate(
            pending=Sum('amount', filter=Q(status='PENDING')),
            approved=Sum('amount', filter=Q(status='APPROVED')),
            total_used=Sum('amount', filter=Q(status__in=['PENDING', 'APPROVED']))
        )
        
        available = float(allocated) - float(expenses['total_used'] or 0)
        
        return Response({
            'allocated_budget': allocated,
            'pending_expenses': expenses['pending'] or 0,
            'approved_expenses': expenses['approved'] or 0,
            'available_budget': available
        })

class ExpenseDetailListView(generics.ListAPIView):
    serializer_class = ExpenseDetailSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        queryset = Expense.objects.all()
        
        if user.is_admin():
            return queryset
        elif user.is_manager():
            managed_departments = ManagerBudget.objects.filter(
                allocated_by=user
            ).values_list('allocated_to', flat=True)
            return queryset.filter(department_head__in=managed_departments)
        
        return queryset.none()
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request
        return context
    
# Department Head: Create Budget Request
class BudgetRequestCreateView(generics.CreateAPIView):
    serializer_class = BudgetRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        if not user.is_department_head():
            raise permissions.PermissionDenied(
                "Only department heads can request additional budget"
            )
        serializer.save(requested_by=user)

# Department Head: List Budget Requests
class UserBudgetRequestListView(generics.ListAPIView):
    serializer_class = BudgetRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_department_head():
            return BudgetRequest.objects.filter(requested_by=user)
        return BudgetRequest.objects.none()

# Manager: List Budget Requests
class ManagerBudgetRequestListView(generics.ListAPIView):
    serializer_class = BudgetRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_manager():
            # Get department heads managed by this manager
            dept_heads = ManagerBudget.objects.filter(
                allocated_by=user
            ).values_list('allocated_to', flat=True)
            return BudgetRequest.objects.filter(requested_by__in=dept_heads)
        return BudgetRequest.objects.none()

# Manager: Approve/Disapprove Budget Request
class BudgetRequestUpdateView(generics.UpdateAPIView):
    queryset = BudgetRequest.objects.all()
    serializer_class = BudgetRequestUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_update(self, serializer):
        user = self.request.user
        budget_request = self.get_object()
        
        if not user.is_manager():
            raise permissions.PermissionDenied(
                "Only managers can process budget requests"
            )
        
        # Check if manager manages this department head
        if not ManagerBudget.objects.filter(
            allocated_by=user,
            allocated_to=budget_request.requested_by
        ).exists():
            raise permissions.PermissionDenied(
                "You don't manage this department head"
            )
        
        new_status = serializer.validated_data['status']
        valid_statuses = [BudgetRequest.APPROVED, BudgetRequest.DISAPPROVED]
        
        if new_status not in valid_statuses:
            raise serializers.ValidationError(
                f"Invalid status. Allowed: {', '.join(valid_statuses)}"
            )
        
        # If approved, add to allocated budget
        if new_status == BudgetRequest.APPROVED:
            ManagerBudget.objects.create(
                allocated_by=user,
                allocated_to=budget_request.requested_by,
                amount=budget_request.amount
            )
        
        serializer.save()

# quarterly income records

class IncomeTimelineView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        # Get parameters with defaults
        months = int(request.query_params.get('months', 3))
        aggregate_by = request.query_params.get('aggregate_by', 'month')
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=months*30)
        
        # Base queryset
        queryset = Income.objects.filter(
            date__gte=start_date,
            date__lte=end_date
        )
        
        # Apply department filter if manager
        if request.user.is_manager and not request.user.is_admin:
            managed_departments = ManagerBudget.objects.filter(
                allocated_by=request.user
            ).values_list('allocated_to__department', flat=True).distinct()
            queryset = queryset.filter(department__in=managed_departments)
        
        # Database-agnostic aggregation
        if aggregate_by == 'quarter':
            # Quarterly aggregation - works with all databases
            result = queryset.annotate(
                year=ExtractYear('date'),
                quarter=ExtractQuarter('date')
            ).values('year', 'quarter').annotate(
                total_amount=Sum('amount'),
                record_count=Count('id')
            ).order_by('year', 'quarter')
            
            # Format results
            formatted_results = []
            for entry in result:
                period = f"{entry['year']}-Q{entry['quarter']}"
                formatted_results.append({
                    'period': period,
                    'total_amount': entry['total_amount'],
                    'record_count': entry['record_count']
                })
            result = formatted_results
        else:
            # Monthly aggregation (default)
            result = queryset.annotate(
                period=TruncMonth('date')
            ).values('period').annotate(
                total_amount=Sum('amount'),
                record_count=Count('id')
            ).order_by('period')
        
        # Format response
        data = {
            "time_period": f"Last {months} months",
            "aggregation": aggregate_by,
            "start_date": start_date.date(),
            "end_date": end_date.date(),
            "results": list(result)
        }
        
        return Response(data)
    
# total expense record quarterly

class ExpenseTimelineView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            # Validate and parse parameters
            months = int(request.query_params.get('months', 3))
            if months <= 0:
                raise ValidationError("Months parameter must be a positive integer")
                
            aggregate_by = request.query_params.get('aggregate_by', 'month')
            if aggregate_by not in ['month', 'quarter']:
                raise ValidationError("Invalid aggregation type. Use 'month' or 'quarter'")
            
            # Calculate date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=months*30)
            
            # Base queryset - only approved expenses
            queryset = Expense.objects.filter(
                status='APPROVED',
                created_at__gte=start_date,
                created_at__lte=end_date
            )
            
            # Apply security filtering
            if not request.user.is_admin:
                if request.user.is_manager:
                    # Get departments managed by this manager
                    managed_departments = ManagerBudget.objects.filter(
                        allocated_by=request.user
                    ).values_list('allocated_to__department', flat=True).distinct()
                    
                    # Filter expenses by department of department_head
                    queryset = queryset.filter(
                        department_head__userprofile__department__in=managed_departments
                    )
                elif request.user.is_department_head:
                    # Only show expenses created by this department head
                    queryset = queryset.filter(department_head=request.user)
                else:
                    queryset = Expense.objects.none()
            
            # Aggregation logic
            if aggregate_by == 'quarter':
                # Quarterly aggregation
                result = queryset.annotate(
                    year=ExtractYear('created_at'),
                    quarter=ExtractQuarter('created_at')
                ).values('year', 'quarter').annotate(
                    total_amount=Sum('amount'),
                    record_count=Count('id')
                ).order_by('year', 'quarter')
                
                # Format quarterly results
                formatted_results = []
                for entry in result:
                    formatted_results.append({
                        'period': f"{entry['year']}-Q{entry['quarter']}",
                        'total_amount': float(entry['total_amount']),
                        'record_count': entry['record_count']
                    })
                result = formatted_results
            else:
                # Monthly aggregation (default)
                result = queryset.annotate(
                    period=TruncMonth('created_at')
                ).values('period').annotate(
                    total_amount=Sum('amount'),
                    record_count=Count('id')
                ).order_by('period')
                
                # Format monthly results
                formatted_results = []
                for entry in result:
                    formatted_results.append({
                        'period': entry['period'].strftime('%Y-%m'),
                        'total_amount': float(entry['total_amount']),
                        'record_count': entry['record_count']
                    })
                result = formatted_results
            
            return Response({
                "time_period": f"Last {months} months",
                "aggregation": aggregate_by,
                "start_date": start_date.date(),
                "end_date": end_date.date(),
                "total_approved_expenses": sum(item['total_amount'] for item in result),
                "results": result
            })
            
        except (ValueError, ValidationError) as e:
            return Response({"error": str(e)}, status=400)
        except EmptyResultSet:
            return Response({"results": []})
        except Exception as e:
            return Response({"error": "Server error"}, status=500)