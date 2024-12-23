# Generated by Django 5.1.2 on 2024-12-09 13:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('usuarios', '0013_soporte_codigo_userprofile_rut'),
    ]

    operations = [
        migrations.AddField(
            model_name='venta',
            name='calle',
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name='venta',
            name='celular',
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name='venta',
            name='comuna',
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name='venta',
            name='opcion_entrega',
            field=models.CharField(default=1, max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='venta',
            name='region',
            field=models.CharField(blank=True, max_length=255),
        ),
    ]
