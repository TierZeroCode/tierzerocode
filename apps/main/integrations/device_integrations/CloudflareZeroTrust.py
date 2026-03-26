# Import Dependencies
import requests
from django.utils import timezone
# Import Models
from apps.main.models import Integration, Device, CloudflareZeroTrustDeviceData
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import *
from apps.main.integrations.device_integrations.ReusedFunctions import complianceSettings

######################################## Start Get Cloudflare Zero Trust Devices ########################################
def getCloudflareZeroTrustDevices(access_token, tenant_id):
    url = 'https://api.cloudflare.com/client/v4/accounts/' + tenant_id +'/devices'
    headers = {'Authorization': 'Bearer ' + access_token,'Content-Type': 'application/json',}
    graph_result = requests.get(url=url, headers=headers)
    return graph_result.json()
######################################## End Get Cloudflare Zero Trust Devices ########################################
######################################## Start Update/Create Cloudflare Zero Trust Devices ########################################
def updateCloudflareZeroTrustDeviceDatabase(total_cloudflare_zero_trust_results):
    devices = total_cloudflare_zero_trust_results.get('result', [])
    for device_data in devices:
        hostname = (device_data.get('name') or device_data.get('hostname') or '').lower()
        if not hostname:
            continue  # Skip devices without a name or hostname
        os_platform = device_data.get('device_type') or device_data.get('os')

        clean_data = cleanAPIData(os_platform)
        defaults = {
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
        }

        obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
        obj.integration.add(Integration.objects.get(integration_type="Cloudflare Zero Trust"))

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
            'key': device_data.get('key'),
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
            'version': device_data.get('version'),
            'updated': device_data.get('updated'),
            'created': device_data.get('created'),
            'last_seen': device_data.get('last_seen'),
            'model': device_data.get('model'),
            'os_version': device_data.get('os_version'),
            'manufacturer': device_data.get('manufacturer'),
            'ip': device_data.get('ip'),
            'gateway_device_id': device_data.get('gateway_device_id'),
            'serial_number': device_data.get('serial_number'),
            'parentDevice': obj
        }
        CloudflareZeroTrustDeviceData.objects.update_or_create(id=device_data['id'], defaults=defaults_all)  
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