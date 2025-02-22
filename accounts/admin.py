# accounts/admin.py

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser
from django.core.mail import send_mail
from django.conf import settings
import random
import string

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('username', 'email', 'role', 'department', 'salary', 'is_staff')

    fieldsets = UserAdmin.fieldsets + (
        ('Additional Info', {'fields': ('role', 'department', 'salary')}),
    )

    def save_model(self, request, obj, form, change):
        if not obj.pk:  # Only generate password for new users
            temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            obj.set_password(temp_password)
            obj.save()

            # Send email with login credentials
            send_mail(
                'Your Temporary Password',
                f'Hello {obj.username},\n\nYour temporary password is: {temp_password}\nPlease log in and change it immediately.',
                settings.DEFAULT_FROM_EMAIL,
                [obj.email],
                fail_silently=False,
            )
        else:
            super().save_model(request, obj, form, change)

admin.site.register(CustomUser, CustomUserAdmin)
