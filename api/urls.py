from django.urls import path

from .views import MessageViews
from .delete_expired_messages_view import DeleteExpiredMessagesView

urlpatterns = [
    path('messages/', MessageViews.as_view()),
    path('messages/<str:message_id>', MessageViews.as_view()),
    path('tasks/delete-expired-messages', DeleteExpiredMessagesView.as_view(), name='delete-expired-messages'),
]
