

from django.urls import path

from . import views

urlpatterns = [
    path("register", views.register, name="register"),
    path("login",views.login, name="login"),
    path("logout",views.logout,name="logout"),
    path("", views.home_page, name="home_page"),
    path("send_file", views.send_file, name="send_file"),
    path("received_file", views.received_file, name="received_file"),
    path("read_json_data", views.new_user_register, name="new_user_register"),
    path("login_successful", views.authenticate_user, name="authenticate_user"),
     path("send_request", views.send_request, name="send_request"),
    path("get_payload", views.get_payload, name="get_payload"),
    path("get_received_files", views.send_encrypted_file, name="send_encrypted_file"),
    path("get_senderpublickey", views.fetch_emmiter, name="fetch_emmiter"),
    path("index", views.index_page, name="index_page")
]


