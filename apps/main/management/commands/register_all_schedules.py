from django.core.management.base import BaseCommand

from apps.main.models import IntegrationSchedule
from apps.main.scheduling import register_schedule, unregister_schedule, validate_cron


class Command(BaseCommand):
    help = (
        'Re-register every IntegrationSchedule with rq-scheduler. Idempotent — '
        'cancels any prior job and re-creates with the current cron expression. '
        'Run after a Redis flush, after a worker restart that loses scheduled '
        'jobs, or to recover from drift between the DB and rq-scheduler state.'
    )

    def handle(self, *args, **options):
        registered = 0
        skipped = 0
        invalid = 0

        for schedule in IntegrationSchedule.objects.select_related('integration'):
            if not schedule.enabled or not schedule.cron_expression:
                unregister_schedule(schedule)
                skipped += 1
                continue

            is_valid, err = validate_cron(schedule.cron_expression)
            if not is_valid:
                self.stdout.write(self.style.WARNING(
                    f'  Invalid cron on schedule {schedule.pk} '
                    f'({schedule.integration.integration_type}/{schedule.task_key}): {err}'
                ))
                unregister_schedule(schedule)
                invalid += 1
                continue

            register_schedule(schedule)
            registered += 1
            self.stdout.write(
                f'  Registered {schedule.integration.integration_type}/{schedule.task_key} '
                f'({schedule.cron_expression})'
            )

        self.stdout.write(self.style.SUCCESS(
            f'Done. Registered: {registered}  Skipped (disabled/empty): {skipped}  '
            f'Invalid: {invalid}'
        ))
