from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0111_controlframework_control'),
    ]

    operations = [
        migrations.AddField(
            model_name='control',
            name='evaluator',
            field=models.CharField(blank=True, help_text='Dotted path to evaluator function, e.g. alm_01', max_length=100, null=True),
        ),
    ]
