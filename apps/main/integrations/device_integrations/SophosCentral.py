# Import Dependencies
import logging
import requests
from django.utils import timezone

logger = logging.getLogger(__name__)
# Import Models
from ...models import Integration, Device, SophosCentralDeviceData, DeviceComplianceSettings
# Import Functions Scripts
from .ReusedFunctions import *
from apps.main.integrations.device_integrations.ReusedFunctions import complianceSettings

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
def getSophosDevices(access_token, tenant_id):
    url = 'https://api-us03.central.sophos.com/endpoint/v1/endpoints'
    headers = {
        'Authorization': access_token,
        'X-Tenant-ID': tenant_id
    }
    response = requests.get(url=url, headers=headers)
    return response.json()
######################################## End Get Sophos Central Devices ########################################

######################################## Start Update/Create Sophos Central Devices ########################################
def updateSophosDeviceDatabase(json_data):
    for device_data in json_data['items']:
        hostname = device_data.get('hostname').lower()
        os_platform = device_data.get('os', {}).get('name')
        clean_data = cleanAPIData(os_platform)
        defaults = {
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
        }
        obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
        obj.integration.add(Integration.objects.get(integration_type="Sophos Central"))

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
            "id": device_data.get('id'),
            "type": device_data.get('type'),
            "hostname": hostname,
            "os_isServer": device_data.get('os', {}).get('isServer'),
            "os_platform": device_data.get('os', {}).get('platform'),
            "os_name": device_data.get('os', {}).get('name'),
            "os_majorVersion": device_data.get('os', {}).get('majorVersion'),
            "os_minorVersion": device_data.get('os', {}).get('minorVersion'),
            "os_build": device_data.get('os', {}).get('build'),
            "associatedPerson_name": device_data.get('associatedPerson', {}).get('name'),
            "associatedPerson_viaLogin": device_data.get('associatedPerson', {}).get('viaLogin'),
            "associatedPerson_id": device_data.get('associatedPerson', {}).get('id'),
            "tamperProtectionEnabled": device_data.get('tamperProtectionEnabled'),
            "lastSeenAt": device_data.get('lastSeenAt'),
            "parentDevice": obj
        }
        SophosCentralDeviceData.objects.update_or_create(id=device_data.get('id'), defaults=defaults_all)
######################################## End Update/Create Sophos Central Devices ########################################

######################################## Start Sync Sophos Central ######################################## 
def syncSophos():
    data = Integration.objects.get(integration_type="Sophos Central")
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    updateSophosDeviceDatabase(getSophosDevices(getSophosAccessToken(client_id, client_secret), tenant_id))
    data.last_synced_at = timezone.now()
    data.save()
    return True
######################################## End Sync Sophos Central ########################################
