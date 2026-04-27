from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.main.models import Notification
from apps.main.tasks import (
    microsoftEntraIDUserSyncTask,
    entraUsersSyncTask,
    entraSignInsSyncTask,
    entraCaPoliciesSyncTask,
    entraTenantConfigSyncTask,
    entraAuthMethodsPolicySyncTask,
    entraPasswordPolicySyncTask,
)


# Phase slug → (RQ task, notification title)
PHASES = {
    'all': (microsoftEntraIDUserSyncTask, 'Microsoft Entra ID — All Phases (umbrella)'),
    'users': (entraUsersSyncTask, 'Microsoft Entra ID — Users Sync'),
    'sign-ins': (entraSignInsSyncTask, 'Microsoft Entra ID — Sign-In Logs Sync'),
    'ca-policies': (entraCaPoliciesSyncTask, 'Microsoft Entra ID — CA Policies Sync'),
    'tenant-config': (entraTenantConfigSyncTask, 'Microsoft Entra ID — Tenant Security Config Sync'),
    'auth-methods-policy': (entraAuthMethodsPolicySyncTask, 'Microsoft Entra ID — Auth Methods Policy Sync'),
    'password-policy': (entraPasswordPolicySyncTask, 'Microsoft Entra ID — Password Policy Sync'),
}


class Command(BaseCommand):
    help = (
        'Enqueue a single Entra ID sync phase as a queued task. '
        'Use --phase to pick which phase to run; --inline to skip the queue and run synchronously.'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--phase', required=True, choices=sorted(PHASES.keys()),
            help='Which sync phase to run.',
        )
        parser.add_argument(
            '--inline', action='store_true',
            help='Run the sync function synchronously in this process instead of enqueueing.',
        )

    def handle(self, *args, **options):
        phase = options['phase']
        task_fn, title = PHASES[phase]

        if options['inline']:
            # Bypass the queue — useful for debugging or one-off ops without a worker.
            self.stdout.write(f'Running "{title}" inline (no queue)…')
            task_fn(
                user_email='system@tierzerocode.com',
                ip_address='127.0.0.1',
                user_agent='Django Management Command',
                browser='System',
                operating_system='System',
                notification_id=None,
            )
            self.stdout.write(self.style.SUCCESS('Done.'))
            return

        notification = Notification.objects.create(
            title=title, status='Queued',
            created_at=timezone.now(), updated_at=timezone.now(),
        )

        try:
            result = task_fn.enqueue(
                'system@tierzerocode.com',
                '127.0.0.1',
                'Django Management Command',
                'System',
                'System',
                notification.id,
            )
        except Exception as e:
            notification.status = 'Failure'
            notification.updated_at = timezone.now()
            notification.save()
            raise CommandError(f'Failed to enqueue {phase} task: {e}')

        self.stdout.write(self.style.SUCCESS(
            f'Enqueued {phase} task — notification id {notification.id}, job id {result.id}.'
        ))
