from rest_framework.views import APIView
from rest_framework.response import Response
from core_app.models import Message
from .serializers import MessageSerializer
from django.db.models import F
from django.utils import timezone

import logging
logger = logging.getLogger( __name__ )

class DeleteExpiredMessagesView(APIView):
    serializer_class = MessageSerializer

    def delete(self, request, id=None):
        logger.info('API request: %s %s' % (request.method, request.path))
        queryset = Message.objects.filter(created__lt=timezone.now() - timezone.timedelta(days=1)*F("destroyAfterDays"))
        logger.info("Found expired messages: " + str(queryset.count()))
        queryset.delete()
        response = Response({"status": "success", "data": "Record Deleted"})  
        logger.info('API response: %s' % (response.data))
        return response