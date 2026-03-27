import logging
from django_tasks import task
from apps.main.integrations.user_integrations.MicrosoftEntraID import syncMicrosoftEntraIDUser
from apps.main.integrations.device_integrations.MicrosoftEntraID import syncMicrosoftEntraIDDevice
from apps.main.integrations.device_integrations.MicrosoftIntune import syncMicrosoftIntuneDevice
from apps.main.integrations.device_integrations.MicrosoftDefenderforEndpoint import syncMicrosoftDefenderforEndpointDevice
from apps.main.integrations.device_integrations.CrowdStrikeFalcon import syncCrowdStrikeFalconDevice
from apps.main.integrations.device_integrations.Tailscale import syncTailscaleDevice
from apps.main.integrations.device_integrations.CloudflareZeroTrust import syncCloudflareZeroTrustDevice
from apps.main.integrations.device_integrations.Qualys import syncQualys
from apps.main.integrations.device_integrations.SophosCentral import syncSophos
from apps.logger.views import createLog
from apps.main.models import Notification
from django.utils import timezone

logger = logging.getLogger(__name__)

DEVICE_SYNC_MAP = {
    'microsoft-entra-id': syncMicrosoftEntraIDDevice,
    'microsoft-intune': syncMicrosoftIntuneDevice,
    'microsoft-defender-for-endpoint': syncMicrosoftDefenderforEndpointDevice,
    'crowdstrike-falcon': syncCrowdStrikeFalconDevice,
    'tailscale': syncTailscaleDevice,
    'cloudflare-zero-trust': syncCloudflareZeroTrustDevice,
    'qualys': syncQualys,
    'sophos-central': syncSophos,
}

def _update_notification(obj, status):
    """Safely update notification status — never let this throw."""
    try:
        obj.status = status
        obj.updated_at = timezone.now()
        obj.save()
    except Exception as e:
        logger.error("Failed to update notification %s to %s: %s", obj.id, status, e)

def _safe_log(event_code, outcome, additional_data, user_email, ip_address, user_agent, browser, operating_system):
    """Log without throwing — never let logging failure block notification updates."""
    try:
        createLog(None, event_code, "System Integration", "System Integration Event", "Superuser", True,
                  "System Integration Sync", outcome, additional_data=additional_data,
                  user_id=user_email, ip_address=ip_address, user_agent=user_agent,
                  browser=browser, operating_system=operating_system)
    except Exception as e:
        logger.error("Failed to create audit log: %s", e)

def _get_or_create_notification(notification_id, title):
    """Get existing notification or create a new one."""
    if notification_id:
        try:
            return Notification.objects.get(id=notification_id)
        except Notification.DoesNotExist:
            pass
    return Notification.objects.create(
        title=title, status="In Progress",
        created_at=timezone.now(), updated_at=timezone.now(),
    )

@task(queue_name='default')
def deviceIntegrationSyncTask(user_email, ip_address, user_agent, browser, operating_system, integration, integration_clean, notification_id=None):
    """Run Device Integration Sync in a Background Thread."""
    obj = _get_or_create_notification(notification_id, f"{integration_clean} Device Integration Sync")
    _update_notification(obj, "In Progress")

    sync_fn = DEVICE_SYNC_MAP.get(integration)
    if not sync_fn:
        _update_notification(obj, "Failure")
        _safe_log("1505", "Failure", f"{integration_clean} Device - Unknown integration: {integration}",
                  user_email, ip_address, user_agent, browser, operating_system)
        return

    try:
        sync_fn()

        # Update notification FIRST, then log (so notification is never stuck)
        _update_notification(obj, "Success")
        _safe_log("1505", "Success", f"{integration_clean} Device",
                  user_email, ip_address, user_agent, browser, operating_system)
    except Exception as e:
        logger.error("Error syncing %s devices: %s", integration_clean, e)

        # Update notification FIRST, then log
        _update_notification(obj, "Failure")
        _safe_log("1505", "Failure", f"{integration_clean} Device - {e}",
                  user_email, ip_address, user_agent, browser, operating_system)


@task(queue_name='default')
def microsoftEntraIDUserSyncTask(user_email, ip_address, user_agent, browser, operating_system, notification_id=None):
    """Run Microsoft Entra ID user sync in a background thread."""
    obj = _get_or_create_notification(notification_id, "Microsoft Entra ID User Integration Sync")
    _update_notification(obj, "In Progress")

    try:
        syncMicrosoftEntraIDUser()

        _update_notification(obj, "Success")
        _safe_log("1505", "Success", "Microsoft Entra ID User",
                  user_email, ip_address, user_agent, browser, operating_system)
    except Exception as e:
        logger.error("Error syncing Microsoft Entra ID users: %s", e)

        _update_notification(obj, "Failure")
        _safe_log("1505", "Failure", f"Microsoft Entra ID User - {e}",
                  user_email, ip_address, user_agent, browser, operating_system)
