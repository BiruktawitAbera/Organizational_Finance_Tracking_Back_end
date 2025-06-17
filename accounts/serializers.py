from django.db import models
from django.db.models import Sum  # Add this import at the top
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework import serializers
from django.contrib.auth import get_user_model
from decimal import Decimal
from django.conf import settings
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import  AdminBudget, ManagerBudget , User

from .models import AdminBudget, ManagerBudget
from .models import (
    User,  AdminBudget, ManagerBudget
)

from .models import Income, DEPARTMENT_CHOICES
from .models import Expense, BudgetRequest



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

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email']
        read_only_fields = fields   

# ✅ Admin Budget Allocation Serializer
class AdminBudgetSerializer(serializers.ModelSerializer):
    allocated_by = serializers.ReadOnlyField(source='allocated_by.email')
    allocated_to = serializers.ReadOnlyField(source='allocated_to.email')
    allocated_to_email = serializers.EmailField(
        write_only=True,
        required=False,  # Not required for updates
        allow_null=True  # Allow null for partial updates
    )
    budget_level = serializers.ChoiceField(
        choices=AdminBudget.BUDGET_LEVEL_CHOICES,
        required=False  # Not required for updates
    )

    class Meta:
        model = AdminBudget
        fields = [
            'id', 
            'budget_level',
            'allocated_amount', 
            'allocated_by', 
            'allocated_to',
            'allocated_to_email',
            'allocated_at', 
            'updated_at',
            'created_at'
        ]
        read_only_fields = [
            'id',
            'allocated_by', 
            'allocated_at',
            'allocated_to',  # Will be set during creation only
            'created_at'
        ]

    def validate(self, data):
        request = self.context.get('request')
        if not request or not hasattr(request, 'user'):
            raise serializers.ValidationError("Authentication required")

        # Skip allocation validation for updates
        if self.instance is not None:
            return data

        # For creation, require allocated_to_email
        allocated_to_email = data.pop('allocated_to_email', None)
        if not allocated_to_email:
            raise serializers.ValidationError({
                "allocated_to_email": "This field is required when creating a budget"
            })

        try:
            allocated_to = User.objects.get(email=allocated_to_email)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                "allocated_to_email": "User with this email does not exist."
            })

        budget_level = data.get('budget_level')
        if not budget_level:
            raise serializers.ValidationError({
                "budget_level": "This field is required when creating a budget"
            })

        # Validate allocation hierarchy
        if budget_level == 'organization':
            if not request.user.is_admin():
                raise serializers.ValidationError(
                    "Only admins can allocate organization budgets."
                )
            if not allocated_to.is_manager():
                raise serializers.ValidationError(
                    "Organization budgets must be allocated to managers."
                )
        elif budget_level == 'department':
            if not request.user.is_admin():
                raise serializers.ValidationError(
                    "Only admins can allocate department budgets."
                )
            if not allocated_to.is_department_head():
                raise serializers.ValidationError(
                    "Department budgets must be allocated to department heads."
                )

        data['allocated_to'] = allocated_to
        return data

    def update(self, instance, validated_data):
        # Remove fields that shouldn't be updated
        validated_data.pop('allocated_to_email', None)
        validated_data.pop('allocated_to', None)
        validated_data.pop('budget_level', None)
        
        return super().update(instance, validated_data)

    def create(self, validated_data):
        request = self.context.get('request')
        validated_data['allocated_by'] = request.user
        return super().create(validated_data)

class ManagerBudgetSerializer(serializers.ModelSerializer):
    allocated_by = serializers.ReadOnlyField(source='allocated_by.email')
    allocated_to = serializers.ReadOnlyField(source='allocated_to.email')
    allocated_to_email = serializers.EmailField(write_only=True)
    budget_level = serializers.ChoiceField(choices=ManagerBudget.BUDGET_LEVEL_CHOICES)
    department = serializers.ChoiceField(choices=ManagerBudget.DEPARTMENT_CHOICES, required=False, allow_null=True)
    
    class Meta:
        model = ManagerBudget
        fields = [
            'id',
            'allocated_by',
            'allocated_to',
            'allocated_to_email',
            'amount',
            'budget_level',
            'department',
            'fiscal_year',
            'created_at',
            'updated_at',
            'notes'
        ]
        read_only_fields = [
            'id',
            'allocated_by',
            'created_at',
            'updated_at'
        ]

    def validate(self, data):
        request = self.context.get('request')
        budget_level = data.get('budget_level')
        department = data.get('department')
        allocated_to_email = data.get('allocated_to_email')

        # Get user by email
        try:
            allocated_to = User.objects.get(email=allocated_to_email)
            data['allocated_to'] = allocated_to
        except User.DoesNotExist:
            raise serializers.ValidationError({
                'allocated_to_email': 'User with this email does not exist'
            })

        if request and request.user.is_authenticated:
            if request.user.is_manager() and budget_level == 'department':
                if not allocated_to.is_department_head():
                    raise serializers.ValidationError(
                        "Department budgets must be allocated to department heads"
                    )
                
                if not department:
                    raise serializers.ValidationError(
                        "Department must be specified for department-level budgets"
                    )
                
                total_allocated = ManagerBudget.objects.filter(
                    allocated_by=request.user,
                    budget_level='department'
                ).aggregate(total=Sum('amount'))['total'] or 0
                
                manager_budget = AdminBudget.objects.filter(
                    allocated_to=request.user,
                    budget_level='organization'
                ).first()
                
                if manager_budget and float(data['amount']) > (float(manager_budget.allocated_amount) - float(total_allocated)):
                    raise serializers.ValidationError(
                        f"Not enough remaining budget. Only {float(manager_budget.allocated_amount) - float(total_allocated)} available."
                    )

        return data

    def create(self, validated_data):
        validated_data.pop('allocated_to_email', None)
        validated_data['allocated_by'] = self.context['request'].user
        return super().create(validated_data)
    
#  serializer for income 

class IncomeSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    department = serializers.CharField(read_only=True)
    created_by = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Income
        fields = [
            'id', 'amount', 'date', 'description', 'department',
            'created_by', 'created_at', 'updated_at'
        ]

# expense
class ExpenseSerializer(serializers.ModelSerializer):
    department = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = Expense
        fields = '__all__'
        read_only_fields = ['department_head', 'manager', 'created_at', 'updated_at', 'department']
    
    def get_department(self, obj):
        # Directly access department through department_head
        if obj.department_head and obj.department_head.department:
            return obj.department_head.department
        return None

class ExpenseUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Expense
        fields = ['status']

class ExpenseDetailSerializer(serializers.ModelSerializer):
    department_head_name = serializers.CharField(source='department_head.full_name', read_only=True)
    manager_name = serializers.CharField(source='manager.full_name', read_only=True)
    department = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = Expense
        fields = [
            'id', 'amount', 'description', 'status',
            'department_head', 'department_head_name',
            'manager', 'manager_name', 'created_at', 
            'updated_at', 'department'
        ]
    
    def get_department(self, obj):
        if obj.department_head and obj.department_head.department:
            return obj.department_head.department
        return None

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        user = self.context['request'].user
        
        if user.is_department_head():
            representation.pop('manager', None)
            representation.pop('manager_name', None)
        
        return representation

# additional budget request

class BudgetRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = BudgetRequest
        fields = ['id', 'amount', 'reason', 'status', 'created_at']
        read_only_fields = ['status', 'created_at']

class BudgetRequestUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = BudgetRequest
        fields = ['status']
        extra_kwargs = {'status': {'required': True}}



