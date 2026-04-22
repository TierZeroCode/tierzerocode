# Hand-written: rename ADPasswordPolicy -> PasswordPolicy, rename policy_dn -> policy_identifier,
# add source / password_notification_window_days, set blank=True on nullable int fields.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0121_integration_field_max_length_500'),
    ]

    operations = [
        # 1. Rename the table — all existing rows are preserved.
        migrations.RenameModel(
            old_name='ADPasswordPolicy',
            new_name='PasswordPolicy',
        ),

        # 2. Rename the identifying field.
        migrations.RenameField(
            model_name='passwordpolicy',
            old_name='policy_dn',
            new_name='policy_identifier',
        ),

        # 3. Add source field (default existing rows to 'active_directory').
        migrations.AddField(
            model_name='passwordpolicy',
            name='source',
            field=models.CharField(
                choices=[('active_directory', 'Active Directory'), ('entra_id', 'Microsoft Entra ID')],
                db_index=True,
                default='active_directory',
                max_length=50,
            ),
            preserve_default=False,
        ),

        # 4. Add Entra-specific field.
        migrations.AddField(
            model_name='passwordpolicy',
            name='password_notification_window_days',
            field=models.IntegerField(blank=True, null=True),
        ),

        # 5. Add blank=True to existing nullable int fields (no DB change, just Django metadata).
        migrations.AlterField(
            model_name='passwordpolicy',
            name='min_password_length',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='passwordpolicy',
            name='password_history_length',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='passwordpolicy',
            name='max_password_age_days',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='passwordpolicy',
            name='min_password_age_days',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='passwordpolicy',
            name='lockout_threshold',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='passwordpolicy',
            name='lockout_duration_minutes',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='passwordpolicy',
            name='lockout_observation_window_minutes',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='passwordpolicy',
            name='precedence',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='passwordpolicy',
            name='name',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),

        # 6. Update verbose names and ordering via AlterModelOptions.
        migrations.AlterModelOptions(
            name='passwordpolicy',
            options={
                'ordering': ['source', 'name'],
                'verbose_name': 'Password Policy',
                'verbose_name_plural': 'Password Policies',
            },
        ),
    ]
