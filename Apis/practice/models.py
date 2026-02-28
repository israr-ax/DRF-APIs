from django.db import models
from django.contrib.auth.models import User
# Create your models here.
class userprofile(model.Model):
    user=models.OneToOneField(User, on_delete=models.CASCADE , related_name='profile')
    bio=models.TextField(blank=True, null=True)
    phone = models.CharField(max_length=50, blank=True, null=True)
    created_at =models.DateTimeField(auto_now_add=True)
    Updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.user.username

class BlacklistedToken(models.Model):
    """
    Stores blacklisted JWT refresh tokens on logout.
    Acts as a simple token blocklist without third-party dependencies.
    """
    token = models.TextField(unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blacklisted_tokens')
    blacklisted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Blacklisted token for {self.user.username} at {self.blacklisted_at}"
