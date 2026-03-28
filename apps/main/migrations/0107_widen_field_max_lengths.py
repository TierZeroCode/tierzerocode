from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0106_add_indexes_hostname_upn'),
    ]

    operations = [
        # Device.osPlatform: 25 -> 100
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
        # MicrosoftIntuneDeviceData fields: 25 -> 200
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
    ]
