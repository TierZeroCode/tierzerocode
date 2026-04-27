from django.db import migrations, models


def set_initial_display_order(apps, schema_editor):
    """Backfill display_order — Custom Controls sits at the bottom (100)."""
    ControlFramework = apps.get_model('main', 'ControlFramework')
    for fw in ControlFramework.objects.all():
        if fw.short_name == 'Custom':
            fw.display_order = 100
        else:
            fw.display_order = 0
        fw.save(update_fields=['display_order'])


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0132_drop_previously_satisfied_signins'),
    ]

    operations = [
        migrations.AddField(
            model_name='controlframework',
            name='display_order',
            field=models.IntegerField(default=0),
        ),
        migrations.AlterModelOptions(
            name='controlframework',
            options={'ordering': ['display_order', 'name']},
        ),
        migrations.RunPython(set_initial_display_order, noop_reverse),
    ]
