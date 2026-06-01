from django.contrib import admin
from django.urls import path
import main.views as u

urlpatterns = [
    path('', u.index),
    path('details', u.details),
    path('repository', u.book_filtering),
    path('admin', u.admin)
]
