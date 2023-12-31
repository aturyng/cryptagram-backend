# Generated by Django 4.2.2 on 2023-07-08 14:32

import django.core.validators
from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('body', models.TextField(editable=False, max_length=5000)),
                ('destroyLiveAfterSeconds', models.IntegerField(blank=True, null=True, validators=[django.core.validators.MinValueValidator(0, message='Value must be greater than or equal to 1.'), django.core.validators.MaxValueValidator(60, message='Value must be less than or equal to 30.')])),
                ('password', models.CharField(max_length=256)),
                ('destroyAfterDays', models.IntegerField(validators=[django.core.validators.MinValueValidator(1, message='Value must be greater than or equal to 1.'), django.core.validators.MaxValueValidator(30, message='Value must be less than or equal to 30.')])),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
