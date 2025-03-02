from rest_framework import generics, status
from django.contrib.auth import get_user_model, authenticate
from .serializers import AccountRegistrationSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

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

        return response

# ✅ Custom login view - Enforce password change for temporary passwords
class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        # Extract email and password from request
        email = request.data.get("email")
        password = request.data.get("password")

        # Authenticate user with the provided credentials
        user = authenticate(request, username=email, password=password)

        if user:
            # Check if the user is required to change their password
            if not user.has_changed_password:
                return Response(
                    {"detail": "Password change required", "force_password_change": True},
                    status=status.HTTP_403_FORBIDDEN
                )

            # If password has already been changed, proceed with issuing tokens
            response = super().post(request, *args, **kwargs)

            # Optionally, you can add custom data to the response here if needed
            response.data['full_name'] = user.get_full_name()

            return response

        return Response({"detail": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)

# ✅ Force users to change password
class EnforcePasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        # Get the old password, new password, and confirm password from the request data
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        if not old_password or not new_password or not confirm_password:
            return Response({"error": "Old password, new password, and confirm password are required"},
                            status=status.HTTP_400_BAD_REQUEST)

        if new_password != confirm_password:
            return Response({"error": "New password and confirm password must match"},
                            status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(old_password):
            return Response({"error": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

        # Set the new password
        user.set_password(new_password)
        user.has_changed_password = True  # Mark password as changed
        user.save()

        # Generate new JWT tokens after the password change
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        return Response({
            "message": "Password updated successfully",
            "access": access_token,
            "refresh": refresh_token
        }, status=status.HTTP_200_OK)

# ✅ Admin dashboard view - Users must change password before access
class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not getattr(request.user, "has_changed_password", False):  # Ensure attribute exists
            return Response({"detail": "Password change required"}, status=status.HTTP_403_FORBIDDEN)

        return Response({"message": "Welcome, Admin!"}, status=status.HTTP_200_OK)

# ✅ Get user role endpoint
class UserRoleView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({"role": user.role})  # Assuming `role` is a field in your User model
