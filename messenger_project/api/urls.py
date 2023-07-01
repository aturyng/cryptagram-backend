from django.urls import path

from .views import MessageViews

urlpatterns = [
    path('messages/', MessageViews.as_view()),
    path('messages/<str:message_id>/', MessageViews.as_view()),
]
