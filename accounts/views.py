from django.contrib import messages
from django.shortcuts import render, HttpResponse, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, get_user
from django.contrib.auth.models import User, auth
from django.http import Http404
from .models import Message, userdetails
import json
from django.http import JsonResponse
from django.core.files.storage import FileSystemStorage
from .forms import MessageForm
from django.urls import reverse_lazy
from django.views import generic
from django.views.decorators.csrf import csrf_protect
# Create your views here.

def home_page(request):
    return render(request, "home_page.html")


###########################################################
## ACCOUNTS 
###########################################################
def login(request):
    return render(request,'login.html')    

def register(request):
    return render(request, 'register.html')



def logout(request):
    auth.logout(request)
    return redirect('/')

################################################################################
# AFTER AUTHENTICATION
################################################################################

def send_file(request):
        return render(request, 'register.html')      

def received_file(request):
    if request.user.is_authenticated:
        Messages = Message.objects.all()
        return render(request, 'received_file.html', {'Messages': Messages })
    else:
        return redirect('/')

def authenticate_user(request):
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)
    username = body.get('username', None)
    if User.objects.filter(username=username).exists():
            return JsonResponse({"result": "ok"})
    else:
        print("error")
        return redirect("/")





@csrf_protect
def new_user_register(request):
    body_unicode = request.body.decode('utf-8')
    print(body_unicode)
    body = json.loads(body_unicode)
    username = body.get('username', None)
    user = User.objects.create_user(username=username)
    user.save()
    u = userdetails(**body)
    u.save()
    return JsonResponse({"result": "ok"})

