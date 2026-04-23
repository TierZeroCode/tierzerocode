from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0122_rename_adpasswordpolicy_to_passwordpolicy'),
    ]

    operations = [
        migrations.AddField(
            model_name='userdata',
            name='password_policy',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='users',
                to='main.passwordpolicy',
            ),
        ),
    ]
