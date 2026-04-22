from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0118_userdata_passkeysynced'),
    ]

    operations = [
        migrations.AddField(
            model_name='userdata',
            name='onPremisesSyncEnabled',
            field=models.BooleanField(null=True),
        ),
    ]
