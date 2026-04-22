from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0117_tenant_auth_methods_policy'),
    ]

    operations = [
        migrations.AddField(
            model_name='userdata',
            name='passKeySynced_authentication_method',
            field=models.BooleanField(null=True),
        ),
    ]
