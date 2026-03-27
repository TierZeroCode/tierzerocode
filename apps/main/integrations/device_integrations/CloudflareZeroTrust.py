# Import Dependencies
import requests
from django.utils import timezone
# Import Models
from apps.main.models import Integration, Device, CloudflareZeroTrustDeviceData
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import cleanAPIData, complianceSettings, bulk_sync_devices

######################################## Start Get Cloudflare Zero Trust Devices ########################################
def getCloudflareZeroTrustDevices(access_token, tenant_id):
    url = 'https://api.cloudflare.com/client/v4/accounts/' + tenant_id +'/devices'
    headers = {'Authorization': 'Bearer ' + access_token,'Content-Type': 'application/json',}
    graph_result = requests.get(url=url, headers=headers)
    return graph_result.json()
######################################## End Get Cloudflare Zero Trust Devices ########################################
######################################## Start Update/Create Cloudflare Zero Trust Devices ########################################

_CF_UPDATE_FIELDS = [
    'key', 'hostname', 'osPlatform', 'endpointType', 'version', 'updated', 'created',
    'last_seen', 'model', 'os_version', 'manufacturer', 'ip', 'gateway_device_id',
    'serial_number', 'parentDevice',
]

def _build_cf_detail(device_data, hostname, parent):
    clean_data = cleanAPIData(device_data.get('device_type') or device_data.get('os'))
    return {
        'id': device_data['id'], 'key': device_data.get('key'), 'hostname': hostname,
        'osPlatform': clean_data[0], 'endpointType': clean_data[1],
        'version': device_data.get('version'), 'updated': device_data.get('updated'),
        'created': device_data.get('created'), 'last_seen': device_data.get('last_seen'),
        'model': device_data.get('model'), 'os_version': device_data.get('os_version'),
        'manufacturer': device_data.get('manufacturer'), 'ip': device_data.get('ip'),
        'gateway_device_id': device_data.get('gateway_device_id'),
        'serial_number': device_data.get('serial_number'), 'parentDevice': parent,
    }

def updateCloudflareZeroTrustDeviceDatabase(total_cloudflare_zero_trust_results):
    integration = Integration.objects.get(integration_type="Cloudflare Zero Trust")
    processed = []
    for device_data in total_cloudflare_zero_trust_results.get('result', []):
        hostname = (device_data.get('name') or device_data.get('hostname') or '').lower()
        if not hostname:
            continue
        clean_data = cleanAPIData(device_data.get('device_type') or device_data.get('os'))
        processed.append({
            'hostname': hostname, 'os_platform': clean_data[0],
            'endpoint_type': clean_data[1], 'device_data': device_data,
            'detail_id': device_data.get('id'),
        })
    bulk_sync_devices(integration, processed, CloudflareZeroTrustDeviceData, _CF_UPDATE_FIELDS, _build_cf_detail)
######################################## End Update/Create Cloudflare Zero Trust Devices ########################################

######################################## Start Sync Cloudflare Zero Trust ########################################
def syncCloudflareZeroTrustDevice():
    data = Integration.objects.get(integration_type="Cloudflare Zero Trust")
    if not data.client_secret or not data.tenant_id or not data.tenant_domain:
        raise Exception("Cloudflare Zero Trust integration is not properly configured. Missing client_secret or tenant_domain.")

    updateCloudflareZeroTrustDeviceDatabase(getCloudflareZeroTrustDevices(data.client_secret, data.tenant_id))
    data.last_synced_at = timezone.now()
    data.save()
    return True
######################################## End Sync Cloudflare Zero Trust ########################################