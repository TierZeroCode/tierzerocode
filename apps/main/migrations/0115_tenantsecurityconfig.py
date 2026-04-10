from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0114_persona_aal_level'),
    ]

    operations = [
        migrations.CreateModel(
            name='TenantSecurityConfig',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password_protection_enabled', models.BooleanField(default=False)),
                ('password_protection_mode', models.CharField(blank=True, max_length=20, null=True)),
                ('password_protection_on_premises_enabled', models.BooleanField(default=False)),
                ('custom_banned_passwords_enabled', models.BooleanField(default=False)),
                ('custom_banned_password_list', models.JSONField(blank=True, null=True)),
                ('raw_settings', models.JSONField(blank=True, null=True)),
                ('synced_at', models.DateTimeField(auto_now=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
            ],
            options={
                'verbose_name': 'Tenant Security Config',
                'verbose_name_plural': 'Tenant Security Configs',
            },
        ),
    ]
