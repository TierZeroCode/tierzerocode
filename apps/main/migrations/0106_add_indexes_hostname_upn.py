from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0001_initial_squashed_0105_integration_last_connection_test_at'),
    ]

    operations = [
        # AlterField for Django state tracking
        migrations.AlterField(
            model_name='device',
            name='hostname',
            field=models.CharField(db_index=True, max_length=75, null=True),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='upn',
            field=models.EmailField(db_index=True, max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='tailscaledevicedata',
            name='user',
            field=models.EmailField(max_length=254, null=True),
        ),
        # RunSQL to guarantee the DB changes actually happen
        migrations.RunSQL(
            sql=[
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS main_device_hostname_idx ON main_device (hostname);',
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS main_userdata_upn_idx ON main_userdata (upn);',
                'ALTER TABLE main_tailscaledevicedata ALTER COLUMN "user" TYPE varchar(254);',
            ],
            reverse_sql=[
                'DROP INDEX IF EXISTS main_device_hostname_idx;',
                'DROP INDEX IF EXISTS main_userdata_upn_idx;',
                'ALTER TABLE main_tailscaledevicedata ALTER COLUMN "user" TYPE varchar(50);',
            ],
            state_operations=[],
        ),
    ]
