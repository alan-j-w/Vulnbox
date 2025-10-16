from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .forms import CustomUserCreationForm, CustomUserChangeForm
from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    """
    Defines the admin interface for the CustomUser model.
    """

    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = CustomUser

    # Fields to display in the user list
    list_display = ['email', 'username', 'score', 'is_staff']

    # Editable fields in detail view
    fieldsets = (
        *BaseUserAdmin.fieldsets,
        ('Additional Info', {'fields': ('score', 'profile_picture', 'badges')}),
    )

    # Fields in add form
    add_fieldsets = (
        *BaseUserAdmin.add_fieldsets,
        ('Additional Info', {'fields': ('score',)}),
    )
