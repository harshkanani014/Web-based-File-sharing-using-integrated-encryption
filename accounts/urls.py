

from django.urls import path

from . import views

urlpatterns = [
    path("register", views.register, name="register"),
    path("login",views.login, name="login"),
    path("logout",views.logout,name="logout"),
    path("", views.home_page, name="home_page"),
    path("send_file", views.send_file, name="send_file"),
    path("received_file", views.received_file, name="received_file"),
    path("read_json_data", views.new_user_register, name="new_user_register")
]
