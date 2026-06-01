from django.contrib import admin
from django.urls import path
from main import views as u

urlpatterns = [
    path('login', u.siteuser_login),
    path('signup', u.siteuser_signup),
    path('', u.siteuser_login)
]
