from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0131_entra_sign_in_method_stat_previously_satisfied'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='entrasigninmethodstat',
            name='previously_satisfied_signins',
        ),
    ]
