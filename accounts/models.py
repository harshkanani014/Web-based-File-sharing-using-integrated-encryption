from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

class Message(models.Model):
    emitter = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, on_delete=models.CASCADE)
    date_message = models.DateTimeField(default=timezone.now)
    file_upload = models.FileField(upload_to='documents/')

class Register(models.Model):
    first_name = models.TextField(default="")
    username = models.TextField()
    public_key = models.TextField()

class userdetails(models.Model):
    first_name = models.TextField()
    username = models.TextField()
    public_key = models.TextField()
