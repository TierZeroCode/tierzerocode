from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0108_defender_vmmetadata_textfield'),
    ]

    operations = [
        migrations.AddField(
            model_name='integration',
            name='device_ownership_filter',
            field=models.CharField(
                choices=[('All', 'All Devices'), ('Company', 'Corporate Devices Only'), ('Personal', 'Personal Devices Only')],
                default='All', max_length=20, null=True,
            ),
        ),
        migrations.RunSQL(
            sql=["ALTER TABLE main_integration ADD COLUMN IF NOT EXISTS device_ownership_filter varchar(20) DEFAULT 'All';"],
            reverse_sql=["ALTER TABLE main_integration DROP COLUMN IF EXISTS device_ownership_filter;"],
            state_operations=[],
        ),
    ]
