from django.db import migrations


TAG_NAME = 'Break Glass'


def add_break_glass_tag(apps, schema_editor):
    PersonaTag = apps.get_model('main', 'PersonaTag')
    PersonaTag.objects.update_or_create(
        name=TAG_NAME,
        defaults={'is_default': True},
    )


def remove_break_glass_tag(apps, schema_editor):
    PersonaTag = apps.get_model('main', 'PersonaTag')
    PersonaTag.objects.filter(name=TAG_NAME).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0133_controlframework_display_order'),
    ]

    operations = [
        migrations.RunPython(add_break_glass_tag, remove_break_glass_tag),
    ]
