import shortuuid, shortuuidfield
import uuid
from django.db import models

class Message(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    body = models.TextField(max_length=2048)
    destroyLiveAfterSeconds = models.IntegerField(blank=True, null=True)
    password = models.CharField(max_length=256, blank=True)
    destroyAfterDays = models.IntegerField()
                            
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now = True)

    def __str__(self):
        return self.body
