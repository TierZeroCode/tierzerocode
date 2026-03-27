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
# from django.contrib import messages

@task(queue_name='default')
def deviceIntegrationSyncTask(user_email, ip_address, user_agent, browser, operating_system, integration, integration_clean, notification_id=None):
    """Run Device Integration Sync in a Background Thread."""
    if notification_id:
        try:
            obj = Notification.objects.get(id=notification_id)
        except Notification.DoesNotExist:
            obj = Notification.objects.create(
                title=f"{integration_clean} Device Integration Sync",
                status="In Progress",
                created_at=timezone.now(),
                updated_at=timezone.now(),
            )
        obj.status = "In Progress"
        obj.updated_at = timezone.now()
        obj.save()
    else:
        obj = Notification.objects.create(
            title=f"{integration_clean} Device Integration Sync",
            status="In Progress",
            created_at=timezone.now(),
            updated_at=timezone.now(),
        )
    try:
        #X6969
        print(f"Syncing {integration_clean} devices class started")
        if integration == 'microsoft-entra-id':
            syncMicrosoftEntraIDDevice()
        elif integration == 'microsoft-intune':
            syncMicrosoftIntuneDevice()
        elif integration == 'microsoft-defender-for-endpoint':
            syncMicrosoftDefenderforEndpointDevice()
        elif integration == 'crowdstrike-falcon':
            syncCrowdStrikeFalconDevice()
        elif integration == 'tailscale':
            syncTailscaleDevice()
        elif integration == 'cloudflare-zero-trust':
            syncCloudflareZeroTrustDevice()
        elif integration == 'qualys':
            syncQualys()
        elif integration == 'sophos-central':
            syncSophos()
        print(f"Syncing {integration_clean} devices class completed")

        createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", additional_data=f"{integration_clean} Device", user_id=user_email, ip_address=ip_address, user_agent=user_agent, browser=browser, operating_system=operating_system)
        obj.status = "Success"
        obj.updated_at = timezone.now()
        obj.save()
    except Exception as e:
        createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", additional_data=f"{integration_clean} Device - {e}", user_id=user_email, ip_address=ip_address, user_agent=user_agent, browser=browser, operating_system=operating_system)
        print(f"Error syncing {integration_clean} devices: {e}")
        obj.status = "Failure"
        obj.updated_at = timezone.now()
        obj.save()


@task(queue_name='default')
def microsoftEntraIDUserSyncTask(user_email, ip_address, user_agent, browser, operating_system, notification_id=None):
    """Run Microsoft Entra ID user sync in a background thread."""
    if notification_id:
        try:
            obj = Notification.objects.get(id=notification_id)
        except Notification.DoesNotExist:
            obj = Notification.objects.create(
                title="Microsoft Entra ID User Integration Sync",
                status="In Progress",
                created_at=timezone.now(),
                updated_at=timezone.now(),
            )
        obj.status = "In Progress"
        obj.updated_at = timezone.now()
        obj.save()
    else:
        obj = Notification.objects.create(
            title="Microsoft Entra ID User Integration Sync",
            status="In Progress",
            created_at=timezone.now(),
            updated_at=timezone.now(),
        )
    try:
        print("Syncing Microsoft Entra ID users class started")
        syncMicrosoftEntraIDUser()
        print("Syncing Microsoft Entra ID users class completed")
        createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", additional_data="Microsoft Entra ID User", user_id=user_email, ip_address=ip_address, user_agent=user_agent, browser=browser, operating_system=operating_system)
        obj.status = "Success"
        obj.updated_at = timezone.now()
        obj.save()
    except Exception as e:
        createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", additional_data=f"Microsoft Entra ID User - {e}", user_id=user_email, ip_address=ip_address, user_agent=user_agent, browser=browser, operating_system=operating_system)
        obj.status = "Failure"
        obj.updated_at = timezone.now()
        obj.save()
		# messages.error(request, f'Microsoft Entra ID User Integration Sync Failed: {e}')