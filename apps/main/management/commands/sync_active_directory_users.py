from django.core.management.base import BaseCommand
from django.utils import timezone
from apps.main.tasks import activeDirectoryUserSyncTask
from apps.main.models import Notification
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Sync Active Directory users'

    def handle(self, *args, **options):
        self.stdout.write('Enqueueing Active Directory user sync task...')

        user_email = 'system@tierzerocode.com'
        ip_address = '127.0.0.1'
        user_agent = 'Django Management Command'
        browser = 'System'
        operating_system = 'System'

        notification = Notification.objects.create(
            title="Active Directory User Integration Sync (Automated)",
            status="Queued",
            created_at=timezone.now(),
            updated_at=timezone.now(),
        )

        try:
            result = activeDirectoryUserSyncTask.enqueue(
                user_email, ip_address, user_agent, browser, operating_system, notification.id
            )
            self.stdout.write(
                self.style.SUCCESS(f'Active Directory user sync task enqueued successfully! Task ID: {result.id}')
            )
        except Exception as e:
            notification.status = "Failure"
            notification.updated_at = timezone.now()
            notification.save()
            error_msg = f'Failed to enqueue Active Directory user sync task: {str(e)}'
            self.stdout.write(self.style.ERROR(error_msg))
            logger.error(error_msg)
            raise
