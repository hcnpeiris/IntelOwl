# Generated by Django 4.2.15 on 2024-10-14 07:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("analyzers_manager", "0133_analyzer_config_urldna_search"),
    ]

    operations = [
        migrations.AddField(
            model_name="analyzerconfig",
            name="mapping_data_model",
            field=models.JSONField(
                default=dict, help_text="Mapping data_model_key: analyzer_report_key. "
            ),
        ),
    ]
