from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from rest_framework import serializers
from django.contrib.auth import get_user_model
from decimal import Decimal

User = get_user_model()

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
                'birukspace0900@gmail.com',  # Must match EMAIL_HOST_USER in settings.py
                [user.email],
                fail_silently=False,
            )
        except Exception as e:
            print(f"Email sending failed: {e}")  # Log the error

        return user
