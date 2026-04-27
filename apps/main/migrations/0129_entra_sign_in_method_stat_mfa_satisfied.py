from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0128_entra_sign_in_method_stat'),
    ]

    operations = [
        migrations.AddField(
            model_name='entrasigninmethodstat',
            name='mfa_satisfied_signins',
            field=models.IntegerField(default=0),
        ),
    ]
