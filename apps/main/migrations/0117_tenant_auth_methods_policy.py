from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0116_control_manual_override'),
    ]

    operations = [
        migrations.CreateModel(
            name='TenantAuthMethodsPolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email_otp_enabled', models.BooleanField(default=True)),
                ('fido2_enabled', models.BooleanField(default=True)),
                ('microsoft_authenticator_enabled', models.BooleanField(default=True)),
                ('sms_enabled', models.BooleanField(default=True)),
                ('software_oath_enabled', models.BooleanField(default=True)),
                ('temporary_access_pass_enabled', models.BooleanField(default=False)),
                ('x509_certificate_enabled', models.BooleanField(default=False)),
                ('windows_hello_business_enabled', models.BooleanField(default=True)),
                ('passkey_enabled', models.BooleanField(default=True)),
                ('sspr_state', models.CharField(blank=True, max_length=20, null=True)),
                ('sspr_security_questions_enabled', models.BooleanField(default=False)),
                ('sspr_methods_required', models.IntegerField(blank=True, null=True)),
                ('sspr_allowed_methods', models.JSONField(default=list)),
                ('raw_auth_methods', models.JSONField(default=dict)),
                ('raw_sspr', models.JSONField(default=dict)),
                ('synced_at', models.DateTimeField(auto_now=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
            ],
            options={
                'verbose_name': 'Tenant Auth Methods Policy',
                'verbose_name_plural': 'Tenant Auth Methods Policies',
            },
        ),
    ]
