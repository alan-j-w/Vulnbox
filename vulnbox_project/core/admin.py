# core/admin.py

from django.contrib import admin
from .models import Badge, Question, Choice

class ChoiceInline(admin.TabularInline):
    """
    Allows editing Choices directly within the Question admin page.
    This is much more intuitive than managing them separately.
    """
    model = Choice
    extra = 4  # Provides 4 empty slots for new choices by default.

@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    """
    Custom admin configuration for the Question model.
    """
    # --- Detail/Edit View Configuration ---
    # Nest the Choice editor directly on the Question page.
    inlines = [ChoiceInline]

    # --- List View Configuration ---
    # Customize the columns shown in the list of all questions.
    list_display = ('text', 'category')
    
    # Add a search bar to find questions by their text.
    search_fields = ('text',)

    # Add a filter sidebar for easy navigation by category.
    list_filter = ('category',)

@admin.register(Badge)
class BadgeAdmin(admin.ModelAdmin):
    """
    Custom admin configuration for the Badge model.
    """
    # Customize the columns shown in the list of all badges.
    # Note: Replace 'name' and 'description' with your actual model field names.
    list_display = ('name', 'description')
    
    # Add a search bar to easily find badges by name.
    search_fields = ('name',)


    