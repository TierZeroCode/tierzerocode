# Import Dependencies
import logging
import requests
from django.utils import timezone

logger = logging.getLogger(__name__)
# Import Models
from apps.main.models import Integration, Device, TailscaleDeviceData, DeviceComplianceSettings
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import cleanAPIData, complianceSettings, bulk_sync_devices

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

######################################## Start Update/Create Tailscale Devices ########################################

_TS_UPDATE_FIELDS = [
    'nodeId', 'hostname', 'user', 'name', 'clientVersion', 'updateAvailable', 'os',
    'created', 'connectedToControl', 'lastSeen', 'expires', 'keyExpiryDisabled',
    'authorized', 'isExternal', 'machineKey', 'nodeKey', 'tailnetLockKey',
    'blocksIncomingConnections', 'tailnetLockError', 'parentDevice',
]

def _build_ts_detail(device_data, hostname, parent):
    return {
        'id': device_data.get('id'), 'nodeId': device_data.get('nodeId'),
        'hostname': device_data.get('hostname'), 'user': device_data.get('user'),
        'name': device_data.get('name'), 'clientVersion': device_data.get('clientVersion'),
        'updateAvailable': device_data.get('updateAvailable'), 'os': device_data.get('os'),
        'created': device_data.get('created'), 'connectedToControl': device_data.get('connectedToControl'),
        'lastSeen': device_data.get('lastSeen'), 'expires': device_data.get('expires'),
        'keyExpiryDisabled': device_data.get('keyExpiryDisabled'), 'authorized': device_data.get('authorized'),
        'isExternal': device_data.get('isExternal'), 'machineKey': device_data.get('machineKey'),
        'nodeKey': device_data.get('nodeKey'), 'tailnetLockKey': device_data.get('tailnetLockKey'),
        'blocksIncomingConnections': device_data.get('blocksIncomingConnections'),
        'tailnetLockError': device_data.get('tailnetLockError'), 'parentDevice': parent,
    }

def updateTailscaleDeviceDatabase(total_tailscale_results):
    integration = Integration.objects.get(integration_type="Tailscale")
    processed = []
    for device_data in total_tailscale_results:
        hostname = (device_data.get('hostname') or '').lower()
        if not hostname:
            continue
        clean_data = cleanAPIData(device_data.get('os'))
        processed.append({
            'hostname': hostname, 'os_platform': clean_data[0],
            'endpoint_type': clean_data[1], 'device_data': device_data,
            'detail_id': device_data.get('id'),
        })
    bulk_sync_devices(integration, processed, TailscaleDeviceData, _TS_UPDATE_FIELDS, _build_ts_detail)
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
