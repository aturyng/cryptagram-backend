# Generated by Django 4.2.2 on 2023-07-02 16:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core_app', '0002_alter_message_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='body',
            field=models.TextField(max_length=5000),
        ),
        migrations.AlterField(
            model_name='message',
            name='password',
            field=models.CharField(blank=True, max_length=256),
        ),
    ]
