# Generated by Django 5.1.2 on 2024-12-10 12:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('usuarios', '0016_productoventa_cantidad'),
    ]

    operations = [
        migrations.AddField(
            model_name='venta',
            name='metodo_pago',
            field=models.CharField(blank=True, max_length=255),
        ),
    ]
