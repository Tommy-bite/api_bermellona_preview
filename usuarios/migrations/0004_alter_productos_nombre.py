# Generated by Django 5.1.2 on 2024-11-18 04:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('usuarios', '0003_productos'),
    ]

    operations = [
        migrations.AlterField(
            model_name='productos',
            name='nombre',
            field=models.CharField(max_length=255, verbose_name='Nombre del producto'),
        ),
    ]
