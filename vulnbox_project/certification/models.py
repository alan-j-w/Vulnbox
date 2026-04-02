import uuid
from django.db import models
from django.conf import settings

class ExamAttempt(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    score = models.FloatField()
    passed = models.BooleanField()
    timestamp = models.DateTimeField(auto_now_add=True)
    attempt_number = models.IntegerField(default=1)
    cooldown_until = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} - Attempt {self.attempt_number} - {'Passed' if self.passed else 'Failed'}"


class Certificate(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    certificate_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    issue_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=[('Valid', 'Valid'), ('Revoked', 'Revoked')], default='Valid')

    def __str__(self):
        return f"Certificate for {self.user.username} - {self.status}"
