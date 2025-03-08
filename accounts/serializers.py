from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework import serializers
from django.contrib.auth import get_user_model
from decimal import Decimal
from django.conf import settings
from .models import Budget

User = get_user_model()


# ✅ Account Registration Serializer (Includes Email-Based Password Setup)
class AccountRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'role', 'department', 'salary']

    def create(self, validated_data):
        # Generate a temporary 8-character password
        temporary_password = get_random_string(length=8)

        # Ensure salary is correctly handled as a decimal
        salary = validated_data.get('salary', 0)
        if salary:
            salary = Decimal(salary)  # Convert to decimal safely
        
        # Create the user with the temporary password
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=temporary_password,
            role=validated_data.get('role', 'department_head'),
            department=validated_data.get('department', None),  # Set to None if missing
            salary=salary,
        )

        # Send an email with the temporary password
        try:
            send_mail(
                'Your Temporary Password',
                f'Hello {user.username},\n\nYour temporary password is: {temporary_password}\nPlease change it after logging in.',
                settings.EMAIL_HOST_USER,  # Use email from settings
                [user.email],
                fail_silently=False,
            )
        except Exception as e:
            print(f"Email sending failed: {e}")  # Log the error

        return user

# ✅ Password Reset Request Serializer
class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        """Ensure the email is associated with an existing user."""
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user found with this email address.")
        return value

    def send_password_reset_email(self, request):
        """Generate password reset link and send email."""
        email = self.validated_data["email"]
        user = User.objects.get(email=email)
        uid = urlsafe_base64_encode(force_bytes(user.pk))  # Base64 encode the user ID
        token = default_token_generator.make_token(user)  # Generate token
        domain = request.get_host()  # Get the domain dynamically
        reset_link = f"http://localhost:5173/ResetPassword?uidb64={uid}&token={token}"   # Ensure this matches the URL pattern

        # Send email
        try:
            send_mail(
                'Password Reset Request',
                f'Hello {user.username},\n\nClick the link below to reset your password:\n{reset_link}',
                settings.EMAIL_HOST_USER,  # Use email from settings
                [user.email],
                fail_silently=False,
            )
        except Exception as e:
            print(f"Email sending failed: {e}")  # Log the error

        return reset_link

# ✅ Password Reset Confirmation Serializer
class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        """Ensure new password and confirm password match."""
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError({"password": "Passwords do not match"})
        return data

    def save(self, user):
        """Set the new password for the user."""
        user.set_password(self.validated_data["new_password"])
        user.save()
        user.is_active = True
        return user
    


class BudgetSerializer(serializers.ModelSerializer):
    allocated_by = serializers.ReadOnlyField(source='allocated_by.email')  
    allocated_to = serializers.ReadOnlyField(source='allocated_to.email')

    class Meta:
        model = Budget
        fields = ['id', 'department', 'allocated_amount', 'allocated_by', 'allocated_to', 'allocated_at', 'updated_at']
        read_only_fields = ["id", "allocated_by", "allocated_at"]