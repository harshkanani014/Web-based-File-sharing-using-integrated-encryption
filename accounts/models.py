from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
import base64

class Message(models.Model):
    emitter = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE, null=True)
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    date_message = models.DateTimeField(default=timezone.now, null=True)
    file_name = models.TextField(default="filename")
    file_upload = models.TextField(db_column='data', blank=True, null=True)
    """def set_data(self, data):
        self._data = base64.encodestring(data)

    def get_data(self):
        return base64.decodestring(self._data)

    data = property(get_data, set_data)"""


class userdetails(models.Model):
    username = models.TextField()
    public_keyX = models.TextField()
    public_keyY = models.TextField()