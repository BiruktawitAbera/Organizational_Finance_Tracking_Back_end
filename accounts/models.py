from django.db.models import Sum
from django.core.validators import MinValueValidator
from django.contrib.auth.models import AbstractUser, BaseUserManager, Permission
from django.db import models
from django.core.exceptions import ValidationError
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta

DEPARTMENT_CHOICES = [
        ('HR', 'Human Resources'),
        ('OPS', 'Operations'), 
        ('IT', 'Information Technology'),
        ('SALES', 'Sales & Revenue Management'),
    ]

INCOME_STATUS_CHOICES = [
    ('PENDING', 'Pending'),
    ('APPROVED', 'Approved'),
    ('DISAPPROVED', 'Disapproved'),
    ] 




class CustomUserManager(BaseUserManager):
    """Custom user manager that allows email-based authentication."""
    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user with the given email and password."""
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        extra_fields.setdefault('role', 'department_head')
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
    """Role model for defining user roles."""
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('manager', 'Manager'),
        ('department_head', 'Department Head'),
    ]



    name = models.CharField(max_length=20, choices=ROLE_CHOICES, unique=True)

    def __str__(self):
        return self.get_name_display()

class CustomUser(AbstractUser):
    """Custom user model with RBAC."""
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=Role.ROLE_CHOICES, default='department_head')
    department = models.CharField(max_length=255, blank=True, null=True)
    salary = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    has_changed_password = models.BooleanField(default=False)
    organization_budget = models.DecimalField(
        max_digits=15, 
        decimal_places=2, 
        default=0,
        help_text="Total organization budget capacity"
    )

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return f"{self.email} ({self.role})"

    def save(self, *args, **kwargs):
        """Enforce department logic based on role."""
        # Admin shouldn't have a department
        if self.role == 'admin' and self.department:
            self.department = None
        
        # Department heads must have a department
        elif self.role == 'department_head' and not self.department:
            raise ValidationError("Department is required for department heads.")
        
        # Managers shouldn't have a department
        elif self.role == 'manager' and self.department:
            self.department = None
            
        super().save(*args, **kwargs)

    def has_permission(self, permission_codename):
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

class AdminBudget(models.Model):
    BUDGET_LEVEL_CHOICES = [
        ('organization', 'Organization Budget'),
        ('department', 'Department Budget'),
    ]

    budget_level = models.CharField(max_length=20, choices=BUDGET_LEVEL_CHOICES)
    allocated_amount = models.DecimalField(max_digits=15, decimal_places=2)
    allocated_by = models.ForeignKey(
        User,
        related_name='admin_allocations_made',
        on_delete=models.CASCADE,
        limit_choices_to={'role__in': ['admin']}
    )
    allocated_to = models.ForeignKey(
        User,
        related_name='admin_allocations_received',
        on_delete=models.CASCADE,
        limit_choices_to={'role__in': ['manager', 'department_head']}
    )
    allocated_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.get_budget_level_display()}: {self.allocated_amount}"
    

class ManagerBudget(models.Model):
    BUDGET_LEVEL_CHOICES = [
        ('organization', 'Organization Level'),
        ('department', 'Department Level'),
    ]
    
    DEPARTMENT_CHOICES = [
        ('HR', 'Human Resources'),
        ('OPS', 'Operations'),
        ('IT', 'IT & Systems Management'),
        ('SALES', 'Sales and Revenue Management'),
    ]
    
    allocated_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='manager_allocations_made',
        verbose_name='Allocated By',
        limit_choices_to={'role__in': ['manager']}
    )
    allocated_to = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='manager_allocations_received',
        verbose_name='Allocated To',
        limit_choices_to={'role__in': ['department_head']}
    )
    amount = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        validators=[MinValueValidator(0)]
    )
    budget_level = models.CharField(
        max_length=20,
        choices=BUDGET_LEVEL_CHOICES
    )
    department = models.CharField(
        max_length=20,
        choices=DEPARTMENT_CHOICES,
        blank=True,
        null=True
    )
    fiscal_year = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Manager Budget Allocation'
        verbose_name_plural = 'Manager Budget Allocations'
    
    def __str__(self):
        return f"{self.allocated_by} → {self.allocated_to}: {self.amount} ({self.budget_level})"
    
    def clean(self):
        if self.budget_level == 'department' and not self.department:
            raise ValidationError("Department must be specified for department-level budgets")
        if self.budget_level == 'organization' and self.department:
            raise ValidationError("Organization-level budgets cannot have a department")
    
    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    # income a

class Income(models.Model):
    amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(0.01)]
    )
    date = models.DateField()
    description = models.TextField(max_length=500)
    department = models.CharField(
        max_length=30,
        choices=DEPARTMENT_CHOICES,
        editable=False
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='created_incomes'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-date']

    def __str__(self):
        return f"{self.amount} ({self.date}) - {self.department}"
    
# expense

class Expense(models.Model):
    PENDING = 'PENDING'
    APPROVED = 'APPROVED'
    DISAPPROVED = 'DISAPPROVED'
    
    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (APPROVED, 'Approved'),
        (DISAPPROVED, 'Disapproved'),
    ]
    
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=PENDING)
    department_head = models.ForeignKey(User, on_delete=models.CASCADE, related_name='expenses')
    manager = models.ForeignKey(User, on_delete=models.CASCADE, related_name='managed_expenses', null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

# Additional budget request of department head

class BudgetRequest(models.Model):
    PENDING = 'PENDING'
    APPROVED = 'APPROVED'
    DISAPPROVED = 'DISAPPROVED'
    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (APPROVED, 'Approved'),
        (DISAPPROVED, 'Disapproved'),
    ]
    
    requested_by = models.ForeignKey(
        User, 
        on_delete=models.CASCADE,
        related_name='budget_requests'
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    reason = models.TextField()
    status = models.CharField(
        max_length=20, 
        choices=STATUS_CHOICES, 
        default=PENDING
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.requested_by} - {self.amount} - {self.status}"
    
    # dashboared

