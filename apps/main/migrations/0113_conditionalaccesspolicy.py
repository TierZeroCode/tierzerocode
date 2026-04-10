from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0112_control_evaluator'),
    ]

    operations = [
        migrations.CreateModel(
            name='ConditionalAccessPolicy',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('policy_id', models.CharField(db_index=True, max_length=100, unique=True)),
                ('display_name', models.CharField(max_length=500)),
                ('state', models.CharField(max_length=50)),
                ('conditions_users', models.JSONField(blank=True, null=True)),
                ('conditions_applications', models.JSONField(blank=True, null=True)),
                ('conditions_platforms', models.JSONField(blank=True, null=True)),
                ('conditions_locations', models.JSONField(blank=True, null=True)),
                ('grant_controls', models.JSONField(blank=True, null=True)),
                ('session_controls', models.JSONField(blank=True, null=True)),
                ('sign_in_frequency_value', models.IntegerField(blank=True, null=True)),
                ('sign_in_frequency_type', models.CharField(blank=True, max_length=20, null=True)),
                ('sign_in_frequency_enabled', models.BooleanField(default=False)),
                ('persistent_browser_mode', models.CharField(blank=True, max_length=20, null=True)),
                ('persistent_browser_enabled', models.BooleanField(default=False)),
                ('raw_policy', models.JSONField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
            ],
            options={
                'verbose_name': 'Conditional Access Policy',
                'verbose_name_plural': 'Conditional Access Policies',
                'ordering': ['display_name'],
            },
        ),
    ]
