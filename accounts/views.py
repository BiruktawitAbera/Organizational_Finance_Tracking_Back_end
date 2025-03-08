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

from .models import Budget, User
from .serializers import BudgetSerializer
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from .models import CustomUser
import logging

User = get_user_model()

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

        return Response({"role": request.user.role})  # ✅ Ensure role is always returned
    
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

class BudgetListView(generics.ListAPIView):
    queryset = Budget.objects.all()
    serializer_class = BudgetSerializer
    permission_classes = [permissions.IsAuthenticated]
        
class BudgetCreateView(generics.CreateAPIView):
    serializer_class = BudgetSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user

        # Check if the user is a manager
        if user.role != "manager":
            return Response({"error": "Only managers can allocate budgets."}, status=status.HTTP_403_FORBIDDEN)

        # Automatically determine the department head for the manager's department
        try:
            department_head = CustomUser.objects.get(department=user.department, role="department_head")
        except CustomUser.DoesNotExist:
            return Response({"error": "No department head found for your department."}, status=status.HTTP_404_NOT_FOUND)

        # Save the budget allocation
        serializer.save(allocated_by=user, allocated_to=department_head, department=user.department)
# ✅ Update an existing budget
logger = logging.getLogger(__name__)

class BudgetUpdateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, id):
        # Log the request data for debugging
        logger.debug(f"Request data: {request.data}")
        logger.debug(f"Authenticated user: {request.user}")
        logger.debug(f"Budget ID: {id}")

        # Ensure the user is a manager
        if request.user.role != "manager":
            logger.debug("User is not a manager.")
            return Response({"error": "Only managers can update budgets."}, status=status.HTTP_403_FORBIDDEN)

        # Get the budget by ID and ensure it belongs to the authenticated user
        try:
            budget = Budget.objects.get(id=id, allocated_by=request.user)
            logger.debug(f"Found budget: {budget}")
        except Budget.DoesNotExist:
            logger.debug("Budget not found.")
            return Response({"error": "Budget not found."}, status=status.HTTP_404_NOT_FOUND)

        # Validate and update the budget
        serializer = BudgetSerializer(budget, data=request.data, partial=True)
        if serializer.is_valid():
            logger.debug("Budget data is valid.")
            serializer.save()
            logger.debug(f"Updated budget: {serializer.data}")
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            logger.debug(f"Validation errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# ✅ Remove a budget allocation
logger = logging.getLogger(__name__)

class BudgetDeleteView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, id):
        logger.debug(f"Authenticated user: {request.user}")
        logger.debug(f"Budget ID: {id}")

        # Ensure the user is a manager
        if request.user.role != "manager":
            logger.debug("User is not a manager.")
            return Response({"error": "Only managers can delete budgets."}, status=status.HTTP_403_FORBIDDEN)

        # Ensure the budget exists and belongs to the authenticated manager
        try:
            budget = Budget.objects.get(id=id, allocated_by=request.user)
            logger.debug(f"Found budget: {budget}")
        except Budget.DoesNotExist:
            logger.debug("Budget not found.")
            return Response({"error": "Budget not found."}, status=status.HTTP_404_NOT_FOUND)

        # Delete the budget
        budget.delete()
        logger.debug("Budget deleted successfully.")
        return Response({"message": "Budget allocation deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    
class BudgetDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, id):
        # Ensure the user is authorized (manager or department head)
        if request.user.role not in ["manager", "department_head"]:
            return Response({"error": "Unauthorized access."}, status=status.HTTP_403_FORBIDDEN)

        # Get the budget by ID and ensure it belongs to the authenticated user
        try:
            budget = Budget.objects.get(id=id, allocated_by=request.user)
        except Budget.DoesNotExist:
            return Response({"error": "Budget not found."}, status=status.HTTP_404_NOT_FOUND)

        # Serialize and return the budget
        serializer = BudgetSerializer(budget)
        return Response(serializer.data, status=status.HTTP_200_OK)