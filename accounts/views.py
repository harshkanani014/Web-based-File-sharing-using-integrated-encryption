from django.contrib import messages
from django.shortcuts import render, HttpResponse, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, get_user
from django.contrib.auth.models import User, auth
from django.http import Http404
from .models import Message, Register, userdetails
import json
from django.http import JsonResponse
from django.core.files.storage import FileSystemStorage
from .forms import MessageForm
from django.urls import reverse_lazy
from django.views import generic
# Create your views here.

def home_page(request):
    return render(request, "home_page.html")


###########################################################
## ACCOUNTS 
###########################################################
def login(request):
    if request.method== 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username,password=password)

        if user is not None:
            auth.login(request, user)
            return redirect("/")
        else:
            messages.info(request,'invalid credentials')
            return redirect('login')

    else:
        return render(request,'login.html')    

def register(request):

    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        email = request.POST['email']

        if password1==password2:
            if User.objects.filter(username=username).exists():
                messages.info(request,'Username Taken')
                return redirect('register')
            elif User.objects.filter(email=email).exists():
                messages.info(request,'Email Taken')
                return redirect('register')
            else:   
                user = User.objects.create_user(username=username, password=password1, email=email,first_name=first_name,last_name=last_name)
                user.save();
                newuser = Register()
                newuser.username = username
                newuser.public_key = "abcdadadajjdjp"
                newuser.save()
                print('user created')
                return redirect('login')

        else:
            messages.info(request,'password not matching..')    
            return redirect('register')
        return redirect('/')
        
    else:
        return render(request,'register.html')



def logout(request):
    auth.logout(request)
    return redirect('/')

################################################################################
# AFTER AUTHENTICATION
################################################################################

def send_file(request):
    if request.user.is_authenticated:
        context = {}
        if request.method == 'POST':
            uploaded_file = request.FILES['document']
            fs = FileSystemStorage()
            name = fs.save(uploaded_file.name, uploaded_file)
            context['url'] = fs.url(name)
            message = request.POST.get('username')
            print(message)
            newMessage = Message()
            newMessage.file_upload = uploaded_file
            newMessage.emitter = request.user
            newMessage.receiver = User.objects.get(username=message)
            newMessage.save()
            return render(request, 'send_file.html', context)

        else:
            return render(request, 'send_file.html')
    else:
        return redirect('/')      

def received_file(request):
    if request.user.is_authenticated:
        Messages = Message.objects.all()
        return render(request, 'received_file.html', {'Messages': Messages })
    else:
        return redirect('/')
    

def new_user_register(request):
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)
    u = userdetails(**body)
    u.save()
    return JsonResponse({"result": "OK"})