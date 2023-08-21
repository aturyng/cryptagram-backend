import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "messenger_project.settings")

app = Celery("messenger_project")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

# Celery Beat Settings
app.conf.beat_schedule = {
    'remove-expr-msg': {
        'task': 'core_app.tasks.remove_expired_messages_task',
        'schedule': crontab(minute="*/1"),
    }
    
}


# Celery Schedules - https://docs.celeryproject.org/en/stable/reference/celery.schedules.html



@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')