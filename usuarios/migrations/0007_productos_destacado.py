# Generated by Django 5.1.2 on 2024-11-19 14:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('usuarios', '0006_alter_productos_imagen'),
    ]

    operations = [
        migrations.AddField(
            model_name='productos',
            name='destacado',
            field=models.BooleanField(blank=True, default=False),
        ),
    ]
