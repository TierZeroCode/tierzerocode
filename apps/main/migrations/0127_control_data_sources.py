from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0126_control_warning_thresholds'),
    ]

    operations = [
        migrations.AddField(
            model_name='control',
            name='data_sources',
            field=models.JSONField(blank=True, default=list, help_text='List of data source names, e.g. ["Microsoft Entra ID", "CrowdStrike Falcon"].'),
        ),
    ]
