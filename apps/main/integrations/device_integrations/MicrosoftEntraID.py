# Import Dependencies
from django.utils import timezone
# Import Models
from apps.main.models import Integration, Device, MicrosoftEntraIDDeviceData, DeviceComplianceSettings
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import cleanAPIData, complianceSettings, _fetch_paginated_data
from apps.code_packages.microsoft import getMicrosoftGraphAccessToken

######################################## Start Get Microsoft Entra ID Devices ########################################
def getMicrosoftEntraIDDevices(access_token):
    """Fetch all enabled Microsoft Entra ID devices."""
    url = 'https://graph.microsoft.com/v1.0/devices'
    headers = {'Authorization': access_token}
    return _fetch_paginated_data(url, headers)

######################################## End Get Microsoft Entra ID Devices ########################################

######################################## Start Update/Create Microsoft Entra ID Devices ########################################
def updateMicrosoftEntraIDDeviceDatabase(json_data):
    integration = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="Device")
    for device_data in json_data:
        hostname = device_data['displayName'].lower()
        os_platform = device_data['operatingSystem']
        try:
            manufacturer = (device_data['manufacturer'].lower()).title()
        except (KeyError, TypeError, AttributeError):
            manufacturer = None

        clean_data = cleanAPIData(os_platform)

        defaults = {
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
            'manufacturer': manufacturer,
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
            "id": device_data['id'],
            "deletedDateTime": device_data.get('deletedDateTime'),
            "accountEnabled": device_data.get('accountEnabled'),
            "approximateLastSignInDateTime": device_data.get('approximateLastSignInDateTime'),
            "complianceExpirationDateTime": device_data.get('complianceExpirationDateTime'),
            "createdDateTime": device_data.get('createdDateTime'),
            "deviceCategory": device_data.get('deviceCategory'),
            "deviceId": device_data.get('deviceId'),
            "deviceMetadata": device_data.get('deviceMetadata'),
            "deviceOwnership": device_data.get('deviceOwnership'),
            "deviceVersion": device_data.get('deviceVersion'),
            "displayName": hostname,
            "domainName": device_data.get('domainName'),
            "enrollmentProfileName": device_data.get('enrollmentProfileName'),
            "enrollmentType": device_data.get('enrollmentType'),
            "externalSourceName": device_data.get('externalSourceName'),
            "isCompliant": device_data.get('isCompliant'),
            "isManaged": device_data.get('isManaged'),
            "isRooted": device_data.get('isRooted'),
            "managementType": device_data.get('managementType'),
            "manufacturer": device_data.get('manufacturer'),
            "mdmAppId": device_data.get('mdmAppId'),
            "model": device_data.get('model'),
            "onPremisesLastSyncDateTime": device_data.get('onPremisesLastSyncDateTime'),
            "onPremisesSyncEnabled": device_data.get('onPremisesSyncEnabled'),
            "operatingSystem": device_data.get('operatingSystem'),
            "operatingSystemVersion": device_data.get('operatingSystemVersion'),
            "profileType": device_data.get('profileType'),
            "registrationDateTime": device_data.get('registrationDateTime'),
            "sourceType": device_data.get('sourceType'),
            "trustType": device_data.get('trustType'),
            "parentDevice": obj
        }
        MicrosoftEntraIDDeviceData.objects.update_or_create(id=device_data['id'], defaults=defaults_all)
######################################## End Update/Create Microsoft Entra ID Devices ########################################

######################################## Start Sync Microsoft Entra ID ########################################
def syncMicrosoftEntraIDDevice():
    data = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="Device")
    if not data.client_id or not data.client_secret or not data.tenant_id:
        raise Exception("Microsoft Entra ID integration is not properly configured. Missing client_id, client_secret, or tenant_id.")
    
    access_token = getMicrosoftGraphAccessToken(data.client_id, data.client_secret, data.tenant_id, ["https://graph.microsoft.com/.default"])
    if isinstance(access_token, dict) and 'error' in access_token:
        error_msg = str(access_token['error'])
        raise Exception(f"Failed to get access token: {error_msg}")
    
    updateMicrosoftEntraIDDeviceDatabase(getMicrosoftEntraIDDevices(access_token))
    data.last_synced_at = timezone.now()
    data.save()
    return True
######################################## End Sync Microsoft Entra ID ########################################