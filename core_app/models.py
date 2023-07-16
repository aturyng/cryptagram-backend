import uuid
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator

class Message(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    body = models.TextField(max_length=5000)
    destroyLiveAfterSeconds = models.IntegerField(blank=True, null=True,
        validators=[
            MinValueValidator(0, message="Value must be greater than or equal to 1."),
            MaxValueValidator(60, message="Value must be less than or equal to 30.")
        ])
    password = models.CharField(max_length=256)
    destroyAfterDays = models.IntegerField(
        validators=[
            MinValueValidator(1, message="Value must be greater than or equal to 1."),
            MaxValueValidator(30, message="Value must be less than or equal to 30.")
        ])
                            
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now = True)

    def __str__(self):
        return self.body
