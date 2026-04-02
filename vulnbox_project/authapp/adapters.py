from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.contrib.auth import get_user_model

User = get_user_model()

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Custom adapter to ensure Google OAuth works with our CustomUser model.
    It auto-populates the username from the Google email if not already set.
    """

    def pre_social_login(self, request, sociallogin):
        """
        If a user with this email already exists, connect the Google account
        to their existing account instead of creating a new one.
        """
        if sociallogin.is_existing:
            return

        # Try to find a user with the same email
        try:
            email = sociallogin.account.extra_data.get('email', '').lower()
            existing_user = User.objects.get(email=email)
            sociallogin.connect(request, existing_user)
        except User.DoesNotExist:
            pass

    def populate_user(self, request, sociallogin, data):
        """
        Automate username generation from Google's email if none provided.
        """
        user = super().populate_user(request, sociallogin, data)
        if not user.username:
            email = data.get('email', '')
            base_username = email.split('@')[0]
            username = base_username
            # Ensure username is unique
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1
            user.username = username
        return user
