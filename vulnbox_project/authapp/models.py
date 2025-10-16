from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from core.models import Badge

class CustomUser(AbstractUser):
    # Core authentication fields
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)

    # Gamification and profile fields
    score = models.IntegerField(default=0)
    profile_picture = models.ImageField(
        upload_to='profile_pics/',
        default='profile_pics/default.png'
    )
    completed_challenges = models.JSONField(default=list)
    
    # Badges relationship
    badges = models.ManyToManyField(Badge, blank=True)

    # --- NEW FIELD FOR ONLINE STATUS ---
    last_seen = models.DateTimeField(default=timezone.now)

    # Django configuration
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.username

    # --- HELPER METHOD ---
    def is_online(self):
        """
        Returns True if the user was active in the last 2 minutes.
        """
        now = timezone.now()
        return (now - self.last_seen).total_seconds() < 120
