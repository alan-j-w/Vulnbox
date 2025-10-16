from django.db import models
from django.conf import settings

import uuid

# --- Question & Exam Models ---
QUESTION_CATEGORY_CHOICES = [
    ('SQL Injection', 'SQL Injection'),
    ('Brute-Force', 'Brute-Force'),
    ('Cryptography', 'Cryptography'),
    ('XSS', 'XSS'),
    ('CSRF', 'CSRF'),
    ('NoSQL Injection', 'NoSQL Injection'),
    ('SSTI', 'SSTI'),
    ('Command Injection', 'Command Injection'),
    ('Prompt Injection', 'Prompt Injection'),
    ('Data Poisoning', 'Data Poisoning'),
    ('Model Theft', 'Model Theft'),
]

class Badge(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    # Optional: icon = models.ImageField(upload_to='badges/', blank=True, null=True)

    def __str__(self):
        return self.name

class Question(models.Model):
    category = models.CharField(max_length=50, choices=QUESTION_CATEGORY_CHOICES)
    text = models.TextField()

    def __str__(self):
        return f"{self.category}: {self.text[:50]}..."

class Choice(models.Model):
    question = models.ForeignKey(Question, related_name='choices', on_delete=models.CASCADE)
    text = models.CharField(max_length=255)
    is_correct = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.question.text[:30]}... -> {self.text}"

# --- Community / Messaging Models ---
class Channel(models.Model):
    """
    Represents a discussion channel or topic, like #sql-injection-help.
    """
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return self.name

class Message(models.Model):
    """
    Represents a single message posted by a user in a channel.
    """
    channel = models.ForeignKey(Channel, related_name='messages', on_delete=models.CASCADE)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']  # Messages display oldest to newest

    def __str__(self):
        return f'Message by {self.author.username} in {self.channel.name}: {self.content[:30]}'
