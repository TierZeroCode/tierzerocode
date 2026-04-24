from django.db import migrations, models


DEFAULT_TAGS = ['Human', 'Non-Human', 'Privileged']


def create_default_tags(apps, schema_editor):
    PersonaTag = apps.get_model('main', 'PersonaTag')
    for name in DEFAULT_TAGS:
        PersonaTag.objects.update_or_create(
            name=name,
            defaults={'is_default': True},
        )


def remove_default_flag(apps, schema_editor):
    PersonaTag = apps.get_model('main', 'PersonaTag')
    PersonaTag.objects.filter(name__in=DEFAULT_TAGS).update(is_default=False)


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0124_personatag'),
    ]

    operations = [
        migrations.AddField(
            model_name='personatag',
            name='is_default',
            field=models.BooleanField(default=False),
        ),
        migrations.RunPython(create_default_tags, remove_default_flag),
    ]
