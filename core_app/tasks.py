

from celery.utils.log import get_task_logger
from django.utils import timezone
from messenger_project.celery import app



logger = get_task_logger(__name__)


#Asynchronous task for removing old messages
@app.task
def remove_expired_messages_task():
    logger.info("Running remove_expired_messages_task...")
    from django.db.models import F
    from .models import Message
    Message.objects.filter(created__lte=timezone.now() - timezone.timedelta(days=1)*F("destroyAfterDays")).delete()