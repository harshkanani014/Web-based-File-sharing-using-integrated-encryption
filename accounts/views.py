from django.contrib import messages
from django.shortcuts import render, HttpResponse, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, get_user
from django.contrib.auth.models import User, auth
from django.http import Http404
from .models import Message, userdetails
import json
from django.http import JsonResponse
from django.core.files.storage import FileSystemStorage
#from .forms import MessageForm
from django.urls import reverse_lazy
from django.views import generic
from django.views.decorators.csrf import csrf_protect
import base64
# Create your views here.

def home_page(request):
    return render(request, "unautherisedHomePage.html")

def index_page(request):
    return render(request, "authorisedHomePage.html")


###########################################################
## ACCOUNTS 
###########################################################
def login(request):
    return render(request,'login.html')    

def register(request):
    if request.user.is_authenticated:
        return render(request, 'register.html')
    return redirect("/")



def logout(request):
    auth.logout(request)
    return redirect('/')

################################################################################
# AFTER AUTHENTICATION
################################################################################
"""def send_file(request):
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
        return redirect('/')"""

def send_file(request):
    return render(request, "send_file.html")

def send_request(request):
    if request.user.is_authenticated:
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        username = body.get('username', None)
        data = userdetails.objects.get(username=username)
        publickeyX = data.public_keyX
        publickeyY = data.public_keyY
        print(publickeyX)
        print(publickeyY)
        return JsonResponse({"public_keyX": publickeyX, "public_keyY": publickeyY})



def get_payload(request):
    if request.user.is_authenticated:
        #print(type(request.body))
        #print(request.body)
        body_unicode = request.body.decode('utf-8')
        #print(request.body)
        #print(type(request.body))
        #print(type(body_unicode))
        body = json.loads(body_unicode)
        receiver = body.get('username')
        emitter = request.user
        file_rec = body.get('payload')
        payload_name = body.get('payloadName')   
        #print(type(file_rec))
        #print(file_rec)
        #print(file_rec)
        new_message = Message()
        new_message.emitter = emitter
        new_message.receiver = User.objects.get(username=receiver)
        new_message.file_upload = file_rec
        new_message.file_name = payload_name
        new_message.save()
        return JsonResponse({"result": "ok"})
    




def received_file(request):
    if request.user.is_authenticated:
        Messages = Message.objects.all()
        return render(request, 'received_file.html', {'Messages': Messages })
    else:
        return redirect('/')

"""def authenticate_user(request):
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)
    username = body.get('username', None)
    if User.objects.filter(username=username).exists():
            return JsonResponse({"result": "ok"})
    else:
        print("error")
        return redirect("/")"""

def authenticate_user(request):
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)
    username = body.get('username', None)
    password = "harsh1234"
    user = auth.authenticate(username=username, password=password)
    if user is not None:
        auth.login(request, user)
        return JsonResponse({"result": "ok"})
    else:
        print("error")
        return redirect("/")

def send_encrypted_file(request):
    currentuser = request.user
    data = Message.objects.get(receiver=currentuser)
    file_is = data.file_upload
    file_name = data.file_name
    #print(file_is)
    our_json = {"userFiles": file_is}
    #new_json = json.dump(our_json)
    return JsonResponse({"userFiles": file_is, "filename":file_name})

def fetch_emmiter(request):
    currentuser = request.user
    data = Message.objects.get(receiver=currentuser)
    emmiter = data.emitter
    data1 = userdetails.objects.get(username=emmiter)
    public_keyX = data1.public_keyX
    public_keyY = data1.public_keyY
    return JsonResponse({"public_keyX": public_keyX, "public_keyY": public_keyY})



@csrf_protect
def new_user_register(request):
    body_unicode = request.body.decode('utf-8')
    print(body_unicode)
    body = json.loads(body_unicode)
    username = body.get('username', None)
    user = User.objects.create_user(username=username, password="harsh1234")
    user.save()
    u = userdetails(**body)
    u.save()
    return JsonResponse({"result": "ok"})

