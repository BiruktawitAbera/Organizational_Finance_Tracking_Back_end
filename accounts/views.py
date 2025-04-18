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

from .models import  User
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from .models import CustomUser
import logging
from django.db.models import Q , Sum
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import AdminBudget, ManagerBudget, User
from .serializers import AdminBudgetSerializer, ManagerBudgetSerializer, UserSerializer

from .models import   CustomUser
from .serializers import (
    AccountRegistrationSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,

)

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