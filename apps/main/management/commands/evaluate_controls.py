from django.core.management.base import BaseCommand
from django.utils import timezone
from apps.main.models import Control
from apps.main.controls import evaluators


class Command(BaseCommand):
    help = 'Evaluate all controls that have an evaluator function assigned'

    def add_arguments(self, parser):
        parser.add_argument(
            '--control-id',
            type=str,
            help='Evaluate a single control by its ID (e.g. ALM-01)',
        )

    def handle(self, *args, **options):
        single_id = options.get('control_id')

        if single_id:
            controls = Control.objects.filter(control_id=single_id, enabled=True)
        else:
            controls = Control.objects.filter(
                enabled=True,
                evaluator__isnull=False,
            ).exclude(evaluator='')

        if not controls.exists():
            self.stdout.write(self.style.WARNING('No evaluable controls found.'))
            return

        evaluated = 0
        failed = 0

        for ctrl in controls:
            func_name = ctrl.evaluator
            func = getattr(evaluators, func_name, None)

            if func is None:
                self.stdout.write(self.style.ERROR(
                    f'  {ctrl.control_id}: evaluator "{func_name}" not found in evaluators module'
                ))
                failed += 1
                continue

            try:
                current_value, status = func()
                ctrl.current_value = current_value
                ctrl.status = status
                ctrl.save(update_fields=['current_value', 'status', 'updated_at'])
                evaluated += 1

                style = self.style.SUCCESS if status == 'passing' else (
                    self.style.ERROR if status == 'failing' else self.style.WARNING
                )
                self.stdout.write(style(
                    f'  {ctrl.control_id}: {current_value} — {status}'
                ))

            except Exception as e:
                self.stdout.write(self.style.ERROR(
                    f'  {ctrl.control_id}: evaluation error — {e}'
                ))
                ctrl.current_value = 'Error'
                ctrl.status = 'not_measured'
                ctrl.save(update_fields=['current_value', 'status', 'updated_at'])
                failed += 1

        self.stdout.write(self.style.SUCCESS(
            f'\nDone. {evaluated} evaluated, {failed} failed.'
        ))
