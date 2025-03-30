from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now

class VPC(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    vpc_id = models.CharField(max_length=255, unique=True)
    vpc_name = models.CharField(max_length=255)
    created_at = models.DateTimeField(default=now)  # Use default=now instead of auto_now_add=True

    def __str__(self):
        return f"{self.vpc_name} ({self.vpc_id})"
