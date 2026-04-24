from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0125_personatag_is_default'),
    ]

    operations = [
        migrations.AlterField(
            model_name='control',
            name='status',
            field=models.CharField(
                choices=[
                    ('passing', 'Passing'),
                    ('warning', 'Warning'),
                    ('failing', 'Failing'),
                    ('not_measured', 'Not Measured'),
                ],
                default='not_measured',
                max_length=20,
            ),
        ),
        migrations.AlterField(
            model_name='control',
            name='manual_status',
            field=models.CharField(
                blank=True,
                choices=[
                    ('passing', 'Passing'),
                    ('warning', 'Warning'),
                    ('failing', 'Failing'),
                    ('not_measured', 'Not Measured'),
                ],
                help_text='Manually set status, used when use_manual=True.',
                max_length=20,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='control',
            name='amber_threshold',
            field=models.CharField(
                blank=True,
                help_text='Amber alert threshold, e.g. "< 100%". Display only.',
                max_length=100,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='control',
            name='red_threshold',
            field=models.CharField(
                blank=True,
                help_text='Red alert threshold, e.g. "< 95%". Display only.',
                max_length=100,
                null=True,
            ),
        ),
    ]
