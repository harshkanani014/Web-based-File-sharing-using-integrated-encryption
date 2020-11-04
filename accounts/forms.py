from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import Message


class MessageForm(forms.ModelForm):
    class Meta:
        model = Message
        fields = ('emitter', 'receiver', 'file_upload')


class CreateUserForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username','email','password1','password2']