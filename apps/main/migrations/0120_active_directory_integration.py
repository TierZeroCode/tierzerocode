from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0119_userdata_onpremisessyncenabled'),
    ]

    operations = [
        migrations.AddField(
            model_name='integration',
            name='integration_config',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='integration',
            name='integration_type',
            field=models.CharField(
                max_length=35,
                choices=[
                    ("Cloudflare Zero Trust", "Cloudflare Zero Trust"),
                    ("CrowdStrike Falcon", "CrowdStrike Falcon"),
                    ("Microsoft Defender for Endpoint", "Microsoft Defender for Endpoint"),
                    ("Microsoft Entra ID", "Microsoft Entra ID"),
                    ("Microsoft Intune", "Microsoft Intune"),
                    ("Sophos Central", "Sophos Central"),
                    ("Qualys", "Qualys"),
                    ("Tailscale", "Tailscale"),
                    ("Active Directory", "Active Directory"),
                ],
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='userdata',
            name='ad_object_guid',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='userdata',
            name='ad_sam_account_name',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='userdata',
            name='ad_distinguished_name',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
        migrations.AddField(
            model_name='userdata',
            name='ad_password_last_set',
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name='userdata',
            name='ad_resultant_pso',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
        migrations.AddField(
            model_name='userdata',
            name='ad_synced_at',
            field=models.DateTimeField(null=True),
        ),
        migrations.CreateModel(
            name='ADPasswordPolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('policy_dn', models.CharField(max_length=500, unique=True)),
                ('name', models.CharField(max_length=200, null=True)),
                ('min_password_length', models.IntegerField(null=True)),
                ('password_history_length', models.IntegerField(null=True)),
                ('max_password_age_days', models.IntegerField(null=True)),
                ('min_password_age_days', models.IntegerField(null=True)),
                ('lockout_threshold', models.IntegerField(null=True)),
                ('lockout_duration_minutes', models.IntegerField(null=True)),
                ('lockout_observation_window_minutes', models.IntegerField(null=True)),
                ('complexity_enabled', models.BooleanField(null=True)),
                ('reversible_encryption_enabled', models.BooleanField(null=True)),
                ('precedence', models.IntegerField(null=True)),
                ('synced_at', models.DateTimeField(auto_now=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
            ],
            options={
                'verbose_name': 'AD Password Policy',
                'verbose_name_plural': 'AD Password Policies',
            },
        ),
    ]
