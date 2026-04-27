from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0129_entra_sign_in_method_stat_mfa_satisfied'),
    ]

    operations = [
        migrations.AddField(
            model_name='entrasigninmethodstat',
            name='hardware_bound_signins',
            field=models.IntegerField(default=0),
        ),
    ]
