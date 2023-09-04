# Generated by Django 4.2.4 on 2023-09-04 19:47

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Productos",
            fields=[
                (
                    "product_id",
                    models.CharField(max_length=50, primary_key=True, serialize=False),
                ),
                ("conexion", models.GenericIPAddressField()),
            ],
        ),
        migrations.CreateModel(
            name="Tiempo_real",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("voltaje", models.FloatField(default=None)),
                ("consumo", models.FloatField(default=None)),
                ("solar", models.BooleanField(default=None)),
                ("cargando", models.BooleanField(default=None)),
                ("voltaje_bateria", models.IntegerField(default=None)),
                ("errores", models.BooleanField(default=None)),
                (
                    "user",
                    models.ForeignKey(
                        default=None,
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Emergencia",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("voltaje", models.FloatField(default=None)),
                ("consumo", models.FloatField(default=None)),
                ("dia", models.IntegerField(default=None)),
                ("mes", models.IntegerField(default=None)),
                ("hora", models.IntegerField(default=None)),
                ("voltaje_bajo", models.BooleanField()),
                ("voltaje_alto", models.BooleanField()),
                ("red", models.BooleanField()),
                ("corriente", models.BooleanField()),
                (
                    "user",
                    models.ForeignKey(
                        default=None,
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Datos_hora",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("voltaje_hora_red", models.FloatField(default=None)),
                ("consumo_hora_solar", models.FloatField(default=None)),
                ("consumo_hora_red", models.FloatField(default=None)),
                ("hora", models.IntegerField(default=None)),
                ("dia", models.IntegerField(default=None)),
                ("mes", models.IntegerField(default=None)),
                ("año", models.IntegerField(default=None)),
                ("solar_ahora", models.BooleanField(default=None)),
                ("panel_potencia", models.IntegerField(default=None)),
                ("cargando", models.BooleanField(default=None)),
                ("voltaje_bateria", models.IntegerField(default=None)),
                ("errores", models.BooleanField(default=None)),
                ("product_id", models.CharField(max_length=50)),
                (
                    "user",
                    models.ForeignKey(
                        default=None,
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Datos_dias",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("voltaje_maximo_dia_red", models.FloatField(default=None)),
                ("voltaje_minimo_dia_red", models.FloatField(default=None)),
                ("consumo_dia_red", models.FloatField(default=None)),
                ("consumo_dia_solar", models.FloatField(default=None)),
                ("dia", models.IntegerField(default=None)),
                ("mes", models.IntegerField(default=None)),
                ("año", models.IntegerField(default=None)),
                ("horas_potencia_panel", models.IntegerField(default=None)),
                ("potencia_dia_panel", models.IntegerField(default=None)),
                ("horas_de_carga", models.IntegerField(default=None)),
                ("voltajes_bateria", models.CharField(default=None, max_length=400)),
                ("errores", models.BooleanField(default=None)),
                ("product_id", models.CharField(default=None, max_length=50)),
                (
                    "user",
                    models.ForeignKey(
                        default=None,
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
