from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0115_tenantsecurityconfig'),
    ]

    operations = [
        migrations.AddField(
            model_name='control',
            name='use_manual',
            field=models.BooleanField(default=False, help_text='When True, skip automated evaluator and use manual_status/manual_value instead.'),
        ),
        migrations.AddField(
            model_name='control',
            name='manual_status',
            field=models.CharField(
                max_length=20,
                null=True,
                blank=True,
                choices=[('passing', 'Passing'), ('failing', 'Failing'), ('not_measured', 'Not Measured')],
                help_text='Manually set status, used when use_manual=True.',
            ),
        ),
        migrations.AddField(
            model_name='control',
            name='manual_value',
            field=models.CharField(max_length=200, null=True, blank=True, help_text='Manually set current value, used when use_manual=True.'),
        ),
        migrations.AddField(
            model_name='control',
            name='manual_notes',
            field=models.TextField(null=True, blank=True, help_text='Evidence, context, or rationale for the manual override.'),
        ),
        migrations.AlterField(
            model_name='control',
            name='target',
            field=models.CharField(max_length=200, default='100%'),
        ),
    ]
