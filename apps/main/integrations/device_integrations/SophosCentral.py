# Import Dependencies
import logging
import requests
from django.utils import timezone

logger = logging.getLogger(__name__)
# Import Models
from ...models import Integration, Device, SophosCentralDeviceData, DeviceComplianceSettings
# Import Functions Scripts
from .ReusedFunctions import cleanAPIData, complianceSettings, bulk_sync_devices

######################################## Start Get Sophos Central Access Token ########################################
def getSophosAccessToken(client_id, client_secret):
    auth_url = 'https://id.sophos.com/api/v2/oauth2/token'
    auth_payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'token'
    }
    try:
        response = requests.post(auth_url, data=auth_payload)
        if response.status_code == 200:
            return 'Bearer ' + response.json()['access_token']
        else:
            logger.error("Sophos auth failed. Status: %s", response.status_code)
            return {'error': f'Authentication failed with status {response.status_code}'}
    except Exception as e:
        logger.error("Sophos auth error: %s", str(e))
        return {'error': str(e)}
######################################## End Get Sophos Central Access Token ########################################

######################################## Start Get Sophos Central Devices ########################################
def _get_sophos_api_host(access_token):
    """Discover the correct regional API host via Sophos whoami endpoint."""
    response = requests.get(
        'https://api.central.sophos.com/whoami/v1',
        headers={'Authorization': access_token}
    )
    if response.status_code != 200:
        raise Exception(f"Sophos whoami failed with status {response.status_code}")
    data = response.json()
    api_url = data.get('apiHosts', {}).get('dataRegion')
    if not api_url:
        raise Exception("Sophos whoami did not return a dataRegion API host")
    return api_url

def getSophosDevices(access_token, tenant_id):
    """Fetch all Sophos Central devices with pagination and regional API discovery."""
    api_host = _get_sophos_api_host(access_token)
    url = f'{api_host}/endpoint/v1/endpoints'
    headers = {
        'Authorization': access_token,
        'X-Tenant-ID': tenant_id
    }
    all_items = []
    while url:
        response = requests.get(url=url, headers=headers)
        if response.status_code != 200:
            logger.error("Sophos device fetch failed. Status: %s", response.status_code)
            break
        data = response.json()
        all_items.extend(data.get('items', []))
        # Sophos uses pages.nextKey for cursor-based pagination
        next_key = data.get('pages', {}).get('nextKey')
        if next_key:
            url = f'{api_host}/endpoint/v1/endpoints?pageFromKey={next_key}'
        else:
            url = None
    return {'items': all_items}
######################################## End Get Sophos Central Devices ########################################

######################################## Start Update/Create Sophos Central Devices ########################################

_SOPHOS_UPDATE_FIELDS = [
    'type', 'hostname', 'os_isServer', 'os_platform', 'os_name', 'os_majorVersion',
    'os_minorVersion', 'os_build', 'associatedPerson_name', 'associatedPerson_viaLogin',
    'associatedPerson_id', 'tamperProtectionEnabled', 'lastSeenAt', 'parentDevice',
]

def _build_sophos_detail(device_data, hostname, parent):
    return {
        'id': device_data.get('id'), 'type': device_data.get('type'), 'hostname': hostname,
        'os_isServer': device_data.get('os', {}).get('isServer'),
        'os_platform': device_data.get('os', {}).get('platform'),
        'os_name': device_data.get('os', {}).get('name'),
        'os_majorVersion': device_data.get('os', {}).get('majorVersion'),
        'os_minorVersion': device_data.get('os', {}).get('minorVersion'),
        'os_build': device_data.get('os', {}).get('build'),
        'associatedPerson_name': device_data.get('associatedPerson', {}).get('name'),
        'associatedPerson_viaLogin': device_data.get('associatedPerson', {}).get('viaLogin'),
        'associatedPerson_id': device_data.get('associatedPerson', {}).get('id'),
        'tamperProtectionEnabled': device_data.get('tamperProtectionEnabled'),
        'lastSeenAt': device_data.get('lastSeenAt'), 'parentDevice': parent,
    }

def updateSophosDeviceDatabase(json_data):
    integration = Integration.objects.get(integration_type="Sophos Central")
    processed = []
    for device_data in json_data.get('items', []):
        hostname = (device_data.get('hostname') or '').lower()
        if not hostname:
            continue
        clean_data = cleanAPIData(device_data.get('os', {}).get('name'))
        processed.append({
            'hostname': hostname, 'os_platform': clean_data[0],
            'endpoint_type': clean_data[1], 'device_data': device_data,
            'detail_id': device_data.get('id'),
        })
    bulk_sync_devices(integration, processed, SophosCentralDeviceData, _SOPHOS_UPDATE_FIELDS, _build_sophos_detail)
######################################## End Update/Create Sophos Central Devices ########################################

######################################## Start Sync Sophos Central ######################################## 
def syncSophos():
    data = Integration.objects.get(integration_type="Sophos Central")
    if not data.client_id or not data.client_secret or not data.tenant_id:
        raise Exception("Sophos Central integration is not properly configured. Missing client_id, client_secret, or tenant_id.")

    access_token = getSophosAccessToken(data.client_id, data.client_secret)
    if isinstance(access_token, dict) and 'error' in access_token:
        raise Exception(f"Failed to get access token: {access_token['error']}")

    updateSophosDeviceDatabase(getSophosDevices(access_token, data.tenant_id))
    data.last_synced_at = timezone.now()
    data.save()
    return True
######################################## End Sync Sophos Central ########################################
