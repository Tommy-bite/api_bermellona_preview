# Generated by Django 5.1.2 on 2024-12-09 22:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('usuarios', '0015_remove_productoventa_cantidad_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='productoventa',
            name='cantidad',
            field=models.PositiveIntegerField(default=1, verbose_name='Cantidad'),
        ),
    ]