from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('logger', '0001_initial_squashed_0003_log_session_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='log',
            name='additional_data',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.RunSQL(
            sql=['ALTER TABLE logger_log ALTER COLUMN additional_data TYPE text;'],
            reverse_sql=['ALTER TABLE logger_log ALTER COLUMN additional_data TYPE varchar(250);'],
            state_operations=[],
        ),
    ]
