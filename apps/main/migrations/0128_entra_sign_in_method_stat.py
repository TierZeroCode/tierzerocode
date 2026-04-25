from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0127_control_data_sources'),
    ]

    operations = [
        migrations.CreateModel(
            name='EntraSignInMethodStat',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('upn', models.CharField(db_index=True, max_length=256, unique=True)),
                ('total_signins', models.IntegerField(default=0)),
                ('replay_resistant_signins', models.IntegerField(default=0)),
                ('non_replay_resistant_signins', models.IntegerField(default=0)),
                ('last_signin_at', models.DateTimeField(blank=True, null=True)),
                ('synced_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Entra Sign-In Method Stat',
                'verbose_name_plural': 'Entra Sign-In Method Stats',
            },
        ),
    ]
