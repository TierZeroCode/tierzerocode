from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0123_userdata_password_policy'),
    ]

    operations = [
        migrations.CreateModel(
            name='PersonaTag',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
            ],
            options={
                'verbose_name': 'Persona Tag',
                'verbose_name_plural': 'Persona Tags',
                'ordering': ['name'],
            },
        ),
        migrations.AddField(
            model_name='persona',
            name='tags',
            field=models.ManyToManyField(blank=True, related_name='personas', to='main.personatag'),
        ),
    ]
