from django.contrib.auth.models import AbstractUser, BaseUserManager, Permission
from django.db import models
from django.contrib.auth.models import Group


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

    def str(self):
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

    def str(self):
        return f"{self.email} ({self.role})"

    def has_permission(self, permission_codename):
        """Check if the user has a specific permission"""
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