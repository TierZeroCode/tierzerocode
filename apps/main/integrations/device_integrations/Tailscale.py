# Import Dependencies
import logging
import requests
from django.utils import timezone

logger = logging.getLogger(__name__)
# Import Models
from apps.main.models import Integration, Device, TailscaleDeviceData, DeviceComplianceSettings
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import *
from apps.main.integrations.device_integrations.ReusedFunctions import complianceSettings

######################################## Start Get Tailscale Access Token ########################################
def getTailscaleAccessToken(client_id, client_secret):
    auth_url = 'https://api.tailscale.com/api/v2/oauth/token'
    auth_payload = {'client_id': client_id, 'client_secret': client_secret, 'grant_type': 'client_credentials'}
    response = requests.post(auth_url, data=auth_payload)
    if response.status_code == 200:
        access_token = 'Bearer ' + response.json()['access_token']
        return access_token
    else:
        logger.error("Tailscale auth failed. Status: %s", response.status_code)
        return {'error': f'Authentication failed with status {response.status_code}'}
######################################## End Get Tailscale Access Token ########################################

######################################## Start Get CrowdStrike Falcon Devices ########################################
def getTailscaleDevices(access_token, tenant_domain):
    url = f'https://api.tailscale.com/api/v2/tailnet/{tenant_domain}/devices'
    headers = {'Authorization': access_token}
    return ((requests.get(url=url, headers=headers)).json())['devices']

######################################## End Get CrowdStrike Falcon Devices ########################################

######################################## Start Update/Create CrowdStrike Falcon Devices ########################################
def updateTailscaleDeviceDatabase(total_tailscale_results):
    integration = Integration.objects.get(integration_type="Tailscale")
    for device_data in total_tailscale_results:
        hostname = device_data.get('hostname').lower()
        os_platform = device_data.get('os')

        clean_data = cleanAPIData(os_platform)
        defaults = {
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
        }

        obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
        obj.integration.add(integration)

        # Check compliance: device must have ALL required integrations
        compliance_settings = complianceSettings(clean_data[0])
        if compliance_settings:
            # Get all required integrations (where value is True)
            required_integrations = [name for name, is_required in compliance_settings.items() if is_required]
            # Get device's current integrations
            device_integrations = set(obj.integration.values_list('integration_type', flat=True))
            # Device is compliant if it has all required integrations
            obj.compliant = all(integration_name in device_integrations for integration_name in required_integrations)
        else:
            # No compliance requirements = compliant
            obj.compliant = True
        obj.save()

        defaults_all = {
            'id': device_data['id'],
            'nodeId': device_data['nodeId'],
            'hostname': device_data['hostname'],
            'user': device_data['user'],
            'name': device_data['name'],
            'clientVersion': device_data['clientVersion'],
            'updateAvailable': device_data['updateAvailable'],
            'os': device_data['os'],
            'created': device_data['created'],
            'connectedToControl': device_data['connectedToControl'],
            'lastSeen': device_data['lastSeen'],
            'expires': device_data['expires'],
            'keyExpiryDisabled': device_data['keyExpiryDisabled'],
            'authorized': device_data['authorized'],
            'isExternal': device_data['isExternal'],
            'machineKey': device_data['machineKey'],
            'nodeKey': device_data['nodeKey'],
            'tailnetLockKey': device_data['tailnetLockKey'],
            'blocksIncomingConnections': device_data['blocksIncomingConnections'],
            'tailnetLockError': device_data['tailnetLockError'],
            'parentDevice': obj
        }
        TailscaleDeviceData.objects.update_or_create(id=device_data['id'], defaults=defaults_all)
######################################## End Update/Create Tailscale Devices ########################################

######################################## Start Sync Tailscale ########################################
def syncTailscaleDevice():
    data = Integration.objects.get(integration_type="Tailscale")
    if not data.client_id or not data.client_secret:
        raise Exception("Tailscale integration is not properly configured. Missing client_id or client_secret.")

    access_token = getTailscaleAccessToken(data.client_id, data.client_secret)
    if isinstance(access_token, dict) and 'error' in access_token:
        error_msg = str(access_token['error'])
        raise Exception(f"Failed to get access token: {error_msg}")

    updateTailscaleDeviceDatabase(getTailscaleDevices(access_token, data.tenant_domain))
    data.last_synced_at = timezone.now()
    data.save()
    return True
