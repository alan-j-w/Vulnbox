from django.db import models
from django.conf import settings

class Module(models.Model):
    title = models.CharField(max_length=200) # e.g., "Module 1: Web Security Fundamentals"
    slug = models.SlugField(unique=True)     # SEO friendly
    description = models.TextField()
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['order']

    def __str__(self):
        return self.title

class CourseLab(models.Model):
    module = models.ForeignKey(Module, related_name='labs', on_delete=models.CASCADE)
    title = models.CharField(max_length=200) # e.g., "SQL Injection (Union Based)"
    slug = models.SlugField(unique=True)
    content_type = models.CharField(max_length=50, choices=[('theory', 'Theory'), ('lab', 'Practical Lab')])
    points = models.IntegerField(default=10)
    order = models.PositiveIntegerField(default=0)
    url_name = models.CharField(max_length=100) # Maps to existing view e.g., 'core:sql_injection'
    
    # SEO fields
    meta_title = models.CharField(max_length=150, blank=True)
    meta_description = models.CharField(max_length=300, blank=True)

    class Meta:
        ordering = ['module__order', 'order']

    def __str__(self):
        return f"{self.module.title} - {self.title}"

class LabCompletion(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='lab_completions', on_delete=models.CASCADE)
    lab = models.ForeignKey(CourseLab, on_delete=models.CASCADE)
    completed_at = models.DateTimeField(auto_now_add=True)
    score_earned = models.IntegerField(default=0)

    class Meta:
        unique_together = ('user', 'lab') # Prevent duplicate submissions

    def __str__(self):
        return f"{self.user.username} - {self.lab.title}"
