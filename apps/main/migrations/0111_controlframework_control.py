from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0110_signinsummary'),
    ]

    operations = [
        migrations.CreateModel(
            name='ControlFramework',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('short_name', models.CharField(max_length=50)),
                ('version', models.CharField(blank=True, max_length=50, null=True)),
                ('url', models.URLField(blank=True, max_length=500, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
            ],
            options={
                'ordering': ['short_name'],
            },
        ),
        migrations.CreateModel(
            name='Control',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('control_id', models.CharField(db_index=True, max_length=20, unique=True)),
                ('domain', models.CharField(max_length=200)),
                ('statement', models.TextField()),
                ('source_reference', models.CharField(blank=True, max_length=200, null=True)),
                ('indicator', models.TextField(blank=True, null=True)),
                ('measurement_method', models.TextField(blank=True, null=True)),
                ('target', models.CharField(default='100%', max_length=50)),
                ('current_value', models.CharField(blank=True, max_length=50, null=True)),
                ('status', models.CharField(choices=[('passing', 'Passing'), ('failing', 'Failing'), ('not_measured', 'Not Measured')], default='not_measured', max_length=20)),
                ('enabled', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('framework', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='controls', to='main.controlframework')),
            ],
            options={
                'ordering': ['control_id'],
            },
        ),
    ]
