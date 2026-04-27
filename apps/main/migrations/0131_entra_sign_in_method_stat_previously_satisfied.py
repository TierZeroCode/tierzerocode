from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0130_entra_sign_in_method_stat_hardware_bound'),
    ]

    operations = [
        migrations.AddField(
            model_name='entrasigninmethodstat',
            name='previously_satisfied_signins',
            field=models.IntegerField(default=0),
        ),
    ]
