from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0107_widen_field_max_lengths'),
    ]

    operations = [
        migrations.AlterField(
            model_name='microsoftdefenderforendpointdevicedata',
            name='vmMetadata',
            field=models.TextField(null=True),
        ),
        migrations.RunSQL(
            sql=['ALTER TABLE main_microsoftdefenderforendpointdevicedata ALTER COLUMN "vmMetadata" TYPE text;'],
            reverse_sql=['ALTER TABLE main_microsoftdefenderforendpointdevicedata ALTER COLUMN "vmMetadata" TYPE varchar(200);'],
            state_operations=[],
        ),
    ]
