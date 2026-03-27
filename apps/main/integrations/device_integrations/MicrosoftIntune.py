# Import Dependencies
from django.utils import timezone
# Import Models
from apps.main.models import Integration, Device, MicrosoftIntuneDeviceData, DeviceComplianceSettings
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import cleanAPIData, complianceSettings, _fetch_paginated_data
from apps.code_packages.microsoft import getMicrosoftGraphAccessToken

######################################## Start Get Microsoft Intune Devices ########################################
def getMicrosoftIntuneDevices(access_token):
    """Fetch all enabled Microsoft Intune devices."""
    url = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
    headers = {'Authorization': access_token}
    return _fetch_paginated_data(url, headers)

######################################## End Get Microsoft Intune Devices ########################################

######################################## Start Update/Create Microsoft Intune Devices ########################################

def updateMicrosoftIntuneDeviceDatabase(json_data):
    integration = Integration.objects.get(integration_type="Microsoft Intune")
    for device_data in json_data:
        hostname = (device_data.get('deviceName') or '').lower()
        os_platform = device_data.get('operatingSystem', '')
        manufacturer = (device_data.get('manufacturer') or '').title()
        if not hostname:
            continue
        clean_data = cleanAPIData(os_platform)

        if clean_data[0] == "Android":
            hostname = (device_data.get('id') or '').lower()

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
            "id": device_data.get('id'),
            "userId": device_data.get('userId'),
            "deviceName": hostname,
            "managedDeviceOwnerType": device_data.get('managedDeviceOwnerType'),
            "enrolledDateTime": device_data.get('enrolledDateTime'),
            "lastSyncDateTime": device_data.get('lastSyncDateTime'),
            "operatingSystem": device_data.get('operatingSystem'),
            "complianceState": device_data.get('complianceState'),
            "jailBroken": device_data.get('jailBroken'),
            "managementAgent": device_data.get('managementAgent'),
            "osVersion": device_data.get('osVersion'),
            "easActivated": device_data.get('easActivated'),
            "easDeviceId": device_data.get('easDeviceId'),
            "easActivationDateTime": device_data.get('easActivationDateTime'),
            "azureADRegistered": device_data.get('azureADRegistered'),
            "deviceEnrollmentType": device_data.get('deviceEnrollmentType'),
            "activationLockBypassCode": device_data.get('activationLockBypassCode'),
            "emailAddress": device_data.get('emailAddress'),
            "azureADDeviceId": device_data.get('azureADDeviceId'),
            "deviceRegistrationState": device_data.get('deviceRegistrationState'),
            "deviceCategoryDisplayName": device_data.get('deviceCategoryDisplayName'),
            "isSupervised": device_data.get('isSupervised'),
            "exchangeLastSuccessfulSyncDateTime": device_data.get('exchangeLastSuccessfulSyncDateTime'),
            "exchangeAccessState": device_data.get('exchangeAccessState'),
            "exchangeAccessStateReason": device_data.get('exchangeAccessStateReason'),
            "remoteAssistanceSessionUrl": device_data.get('remoteAssistanceSessionUrl'),
            "remoteAssistanceSessionErrorDetails": device_data.get('remoteAssistanceSessionErrorDetails'),
            "isEncrypted": device_data.get('isEncrypted'),
            "userPrincipalName": device_data.get('userPrincipalName'),
            "model": device_data.get('model'),
            "manufacturer": device_data.get('manufacturer'),
            "imei": device_data.get('imei'),
            "complianceGracePeriodExpirationDateTime": device_data.get('complianceGracePeriodExpirationDateTime'),
            "serialNumber": device_data.get('serialNumber'),
            "phoneNumber": device_data.get('phoneNumber'),
            "androidSecurityPatchLevel": device_data.get('androidSecurityPatchLevel'),
            "userDisplayName": device_data.get('userDisplayName'),
            "configurationManagerClientEnabledFeatures": device_data.get('configurationManagerClientEnabledFeatures'),
            "wiFiMacAddress": device_data.get('wiFiMacAddress'),
            "deviceHealthAttestationState": device_data.get('deviceHealthAttestationState'),
            "subscriberCarrier": device_data.get('subscriberCarrier'),
            "meid": device_data.get('meid'),
            "totalStorageSpaceInBytes": device_data.get('totalStorageSpaceInBytes'),
            "freeStorageSpaceInBytes": device_data.get('freeStorageSpaceInBytes'),
            "managedDeviceName": device_data.get('managedDeviceName'),
            "partnerReportedThreatState": device_data.get('partnerReportedThreatState'),
            "requireUserEnrollmentApproval": device_data.get('requireUserEnrollmentApproval'),
            "managementCertificateExpirationDate": device_data.get('managementCertificateExpirationDate'),
            "iccid": device_data.get('iccid'),
            "udid": device_data.get('udid'),
            "notes": device_data.get('notes'),
            "ethernetMacAddress": device_data.get('ethernetMacAddress'),
            "physicalMemoryInBytes": device_data.get('physicalMemoryInBytes'),
            "enrollmentProfileName": device_data.get('enrollmentProfileName'),
            "parentDevice": obj
        }
        MicrosoftIntuneDeviceData.objects.update_or_create(id=device_data.get('id'), defaults=defaults_all)
######################################## End Update/Create Microsoft Intune Devices ########################################

######################################## Start Sync Microsoft Intune ########################################
def syncMicrosoftIntuneDevice():
    data = Integration.objects.get(integration_type="Microsoft Intune")
    if not data.client_id or not data.client_secret or not data.tenant_id:
        raise Exception("Microsoft Intune integration is not properly configured. Missing client_id, client_secret, or tenant_id.")
    
    access_token = getMicrosoftGraphAccessToken(data.client_id, data.client_secret, data.tenant_id, ["https://graph.microsoft.com/.default"])
    if isinstance(access_token, dict) and 'error' in access_token:
        error_msg = str(access_token['error'])
        raise Exception(f"Failed to get access token: {error_msg}")
    
    updateMicrosoftIntuneDeviceDatabase(getMicrosoftIntuneDevices(access_token))
    data.last_synced_at = timezone.now()
    data.save()
    return True
######################################## End Sync Microsoft Intune ########################################