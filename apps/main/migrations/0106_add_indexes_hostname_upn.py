from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0001_initial_squashed_0105_integration_last_connection_test_at'),
    ]

    operations = [
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
    ]
