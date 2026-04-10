from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0113_conditionalaccesspolicy'),
    ]

    operations = [
        migrations.AddField(
            model_name='persona',
            name='aal_level',
            field=models.IntegerField(choices=[(1, 'AAL1'), (2, 'AAL2'), (3, 'AAL3')], default=1, help_text='Authentication Assurance Level per NIST SP 800-63'),
        ),
    ]
