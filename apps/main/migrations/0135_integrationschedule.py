from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0134_personatag_break_glass'),
    ]

    operations = [
        migrations.CreateModel(
            name='IntegrationSchedule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('task_key', models.CharField(help_text='Stable identifier for this task within the integration (e.g. "users", "signins", "devices"). See INTEGRATION_TASKS in apps.main.scheduling for the registry.', max_length=64)),
                ('cron_expression', models.CharField(blank=True, help_text='5-field cron expression in UTC. Null when no schedule is set.', max_length=128, null=True)),
                ('enabled', models.BooleanField(default=False, help_text='Toggle without losing the cron expression.')),
                ('rq_job_id', models.CharField(blank=True, help_text='rq-scheduler job id. Cleared when the schedule is unregistered.', max_length=128, null=True)),
                ('last_run_at', models.DateTimeField(blank=True, null=True)),
                ('next_run_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('integration', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='schedules', to='main.integration')),
            ],
            options={
                'verbose_name': 'Integration Schedule',
                'verbose_name_plural': 'Integration Schedules',
                'ordering': ['integration__integration_type', 'task_key'],
                'unique_together': {('integration', 'task_key')},
            },
        ),
    ]
