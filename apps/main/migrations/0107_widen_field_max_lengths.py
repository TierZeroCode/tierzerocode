from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0106_add_indexes_hostname_upn'),
    ]

    operations = [
        # AlterField operations for Django state tracking
        migrations.AlterField(
            model_name='device',
            name='osPlatform',
            field=models.CharField(
                choices=[('Android', 'Android'), ('iOS/iPadOS', 'iOS/iPadOS'), ('MacOS', 'MacOS'),
                         ('Red Hat Enterprise Linux', 'Red Hat Enterprise Linux'), ('CentOS', 'CentOS'),
                         ('Ubuntu', 'Ubuntu'), ('Windows', 'Windows'), ('Windows Server', 'Windows Server'),
                         ('Other', 'Other')],
                max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='microsoftintunedevicedata',
            name='managedDeviceOwnerType',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='microsoftintunedevicedata',
            name='operatingSystem',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='microsoftintunedevicedata',
            name='complianceState',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='microsoftintunedevicedata',
            name='jailBroken',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='microsoftintunedevicedata',
            name='osVersion',
            field=models.CharField(max_length=200, null=True),
        ),
        # RunSQL to guarantee the DB columns are actually altered
        migrations.RunSQL(
            sql=[
                'ALTER TABLE main_device ALTER COLUMN "osPlatform" TYPE varchar(100);',
                'ALTER TABLE main_microsoftintunedevicedata ALTER COLUMN "managedDeviceOwnerType" TYPE varchar(200);',
                'ALTER TABLE main_microsoftintunedevicedata ALTER COLUMN "operatingSystem" TYPE varchar(200);',
                'ALTER TABLE main_microsoftintunedevicedata ALTER COLUMN "complianceState" TYPE varchar(200);',
                'ALTER TABLE main_microsoftintunedevicedata ALTER COLUMN "jailBroken" TYPE varchar(200);',
                'ALTER TABLE main_microsoftintunedevicedata ALTER COLUMN "osVersion" TYPE varchar(200);',
            ],
            reverse_sql=[
                'ALTER TABLE main_device ALTER COLUMN "osPlatform" TYPE varchar(25);',
                'ALTER TABLE main_microsoftintunedevicedata ALTER COLUMN "managedDeviceOwnerType" TYPE varchar(25);',
                'ALTER TABLE main_microsoftintunedevicedata ALTER COLUMN "operatingSystem" TYPE varchar(25);',
                'ALTER TABLE main_microsoftintunedevicedata ALTER COLUMN "complianceState" TYPE varchar(25);',
                'ALTER TABLE main_microsoftintunedevicedata ALTER COLUMN "jailBroken" TYPE varchar(25);',
                'ALTER TABLE main_microsoftintunedevicedata ALTER COLUMN "osVersion" TYPE varchar(25);',
            ],
            state_operations=[],
        ),
    ]
