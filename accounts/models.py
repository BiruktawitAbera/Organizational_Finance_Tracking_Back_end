from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('manager', 'Manager'),
        ('department_head', 'Department Head'),
    ]
    
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='department_head')
    department = models.CharField(max_length=255, blank=True, null=True)
    salary = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    has_changed_password = models.BooleanField(default=False)  # Ensure password change enforcement

    USERNAME_FIELD = 'email'  # Email is the primary authentication field
    REQUIRED_FIELDS = ['username']  # Username is required but not used for login

    def __str__(self):
        return self.email
