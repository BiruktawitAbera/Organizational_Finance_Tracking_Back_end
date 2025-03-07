from django.contrib.auth.models import AbstractUser, BaseUserManager, Permission
from django.db import models
from django.core.exceptions import ValidationError


class CustomUserManager(BaseUserManager):
    """Custom user manager that allows email-based authentication."""

    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user with the given email and password."""
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        extra_fields.setdefault('role', 'department_head')  # Default role
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)


class Role(models.Model):
    """Role model for defining user roles and linking them to permissions."""
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('manager', 'Manager'),
        ('department_head', 'Department Head'),
    ]

    name = models.CharField(max_length=20, choices=ROLE_CHOICES, unique=True)

    def __str__(self):
        return self.get_name_display()


class CustomUser(AbstractUser):
    """Custom user model with role-based access control (RBAC)."""
    
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=Role.ROLE_CHOICES, default='department_head')
    department = models.CharField(max_length=255, blank=True, null=True)
    salary = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    has_changed_password = models.BooleanField(default=False)  # Ensure password change enforcement

    # User Manager
    objects = CustomUserManager()

    USERNAME_FIELD = 'email'  # Email is the primary authentication field
    REQUIRED_FIELDS = ['username']  # Username is required but not used for login

    def __str__(self):
        return f"{self.email} ({self.role})"

    def save(self, *args, **kwargs):
        """Override the save method to enforce department logic based on role."""
        if self.role == 'admin' and self.department:
            self.department = None  # Admin should not have a department
        elif self.role in ['manager', 'department_head'] and not self.department:
            raise ValidationError("Department is required for managers and department heads.")
        super().save(*args, **kwargs)

    def has_permission(self, permission_codename):
        """Check if the user has a specific permission."""
        return self.groups.filter(permissions__codename=permission_codename).exists()

    def is_admin(self):
        return self.role == 'admin'

    def is_manager(self):
        return self.role == 'manager'

    def is_department_head(self):
        return self.role == 'department_head'

    class Meta:
        permissions = [
            ("view_admin_dashboard", "Can view admin dashboard"),
            ("view_manager_dashboard", "Can view manager dashboard"),
            ("view_department_dashboard", "Can view department dashboard"),
            ("manage_users", "Can manage users"),
            ("approve_budgets", "Can approve budgets"),
            ("view_reports", "Can view financial reports"),
        ]


User = CustomUser


class Budget(models.Model):
    DEPARTMENT_CHOICES = [
        ('income', 'Income Breakdown'),
        ('savings', 'Savings & Investments'),
        ('fixed_expenses', 'Fixed Expenses'),
        ('variable_expenses', 'Variable Expenses'),
    ]
    department = models.CharField(max_length=50, choices=DEPARTMENT_CHOICES)
    allocated_amount = models.DecimalField(max_digits=12, decimal_places=2)
    allocated_by = models.ForeignKey(
        User, related_name="allocated_budgets", on_delete=models.CASCADE,
        limit_choices_to={'role': 'manager'}
    )  # Only Managers can allocate budgets

    allocated_to = models.ForeignKey(
        User, related_name="received_budgets", on_delete=models.CASCADE,
        limit_choices_to={'role': 'department_head'}
    )  # Only Department Heads receive budgets

    allocated_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['department', 'allocated_by', 'allocated_to']  # Ensures one budget allocation per department

    def save(self, *args, **kwargs):
        """Ensure Managers allocate budgets to department heads in their own department."""
        if self.allocated_by.role != 'manager':
            raise ValidationError("Only managers can allocate budgets.")
        
        if self.allocated_to.role != 'department_head':
            raise ValidationError("Budgets can only be allocated to department heads.")
        
        if self.allocated_by.department != self.department or self.allocated_to.department != self.department:
            raise ValidationError("Manager and Department Head must belong to the same department.")

        super().save(*args, **kwargs)

    def __str__(self):
        return f"Budget for {self.get_department_display()} (£{self.allocated_amount}) by {self.allocated_by.email} to {self.allocated_to.email}"
