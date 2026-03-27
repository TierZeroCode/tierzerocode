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

_DEVICE_UPDATE_FIELDS = ['osPlatform', 'endpointType', 'manufacturer']

_INTUNE_UPDATE_FIELDS = [
    'userId', 'deviceName', 'managedDeviceOwnerType', 'enrolledDateTime', 'lastSyncDateTime',
    'operatingSystem', 'complianceState', 'jailBroken', 'managementAgent', 'osVersion',
    'easActivated', 'easDeviceId', 'easActivationDateTime', 'azureADRegistered',
    'deviceEnrollmentType', 'activationLockBypassCode', 'emailAddress', 'azureADDeviceId',
    'deviceRegistrationState', 'deviceCategoryDisplayName', 'isSupervised',
    'exchangeLastSuccessfulSyncDateTime', 'exchangeAccessState', 'exchangeAccessStateReason',
    'remoteAssistanceSessionUrl', 'remoteAssistanceSessionErrorDetails', 'isEncrypted',
    'userPrincipalName', 'model', 'manufacturer', 'imei',
    'complianceGracePeriodExpirationDateTime', 'serialNumber', 'phoneNumber',
    'androidSecurityPatchLevel', 'userDisplayName', 'configurationManagerClientEnabledFeatures',
    'wiFiMacAddress', 'deviceHealthAttestationState', 'subscriberCarrier', 'meid',
    'totalStorageSpaceInBytes', 'freeStorageSpaceInBytes', 'managedDeviceName',
    'partnerReportedThreatState', 'requireUserEnrollmentApproval',
    'managementCertificateExpirationDate', 'iccid', 'udid', 'notes',
    'ethernetMacAddress', 'physicalMemoryInBytes', 'enrollmentProfileName', 'parentDevice',
]

######################################## Start Update/Create Microsoft Intune Devices ########################################

def _build_intune_detail_fields(device_data, hostname, parent_device):
    """Build the field dict for a MicrosoftIntuneDeviceData record."""
    return {
        'id': device_data.get('id'),
        'userId': device_data.get('userId'),
        'deviceName': hostname,
        'managedDeviceOwnerType': device_data.get('managedDeviceOwnerType'),
        'enrolledDateTime': device_data.get('enrolledDateTime'),
        'lastSyncDateTime': device_data.get('lastSyncDateTime'),
        'operatingSystem': device_data.get('operatingSystem'),
        'complianceState': device_data.get('complianceState'),
        'jailBroken': device_data.get('jailBroken'),
        'managementAgent': device_data.get('managementAgent'),
        'osVersion': device_data.get('osVersion'),
        'easActivated': device_data.get('easActivated'),
        'easDeviceId': device_data.get('easDeviceId'),
        'easActivationDateTime': device_data.get('easActivationDateTime'),
        'azureADRegistered': device_data.get('azureADRegistered'),
        'deviceEnrollmentType': device_data.get('deviceEnrollmentType'),
        'activationLockBypassCode': device_data.get('activationLockBypassCode'),
        'emailAddress': device_data.get('emailAddress'),
        'azureADDeviceId': device_data.get('azureADDeviceId'),
        'deviceRegistrationState': device_data.get('deviceRegistrationState'),
        'deviceCategoryDisplayName': device_data.get('deviceCategoryDisplayName'),
        'isSupervised': device_data.get('isSupervised'),
        'exchangeLastSuccessfulSyncDateTime': device_data.get('exchangeLastSuccessfulSyncDateTime'),
        'exchangeAccessState': device_data.get('exchangeAccessState'),
        'exchangeAccessStateReason': device_data.get('exchangeAccessStateReason'),
        'remoteAssistanceSessionUrl': device_data.get('remoteAssistanceSessionUrl'),
        'remoteAssistanceSessionErrorDetails': device_data.get('remoteAssistanceSessionErrorDetails'),
        'isEncrypted': device_data.get('isEncrypted'),
        'userPrincipalName': device_data.get('userPrincipalName'),
        'model': device_data.get('model'),
        'manufacturer': device_data.get('manufacturer'),
        'imei': device_data.get('imei'),
        'complianceGracePeriodExpirationDateTime': device_data.get('complianceGracePeriodExpirationDateTime'),
        'serialNumber': device_data.get('serialNumber'),
        'phoneNumber': device_data.get('phoneNumber'),
        'androidSecurityPatchLevel': device_data.get('androidSecurityPatchLevel'),
        'userDisplayName': device_data.get('userDisplayName'),
        'configurationManagerClientEnabledFeatures': device_data.get('configurationManagerClientEnabledFeatures'),
        'wiFiMacAddress': device_data.get('wiFiMacAddress'),
        'deviceHealthAttestationState': device_data.get('deviceHealthAttestationState'),
        'subscriberCarrier': device_data.get('subscriberCarrier'),
        'meid': device_data.get('meid'),
        'totalStorageSpaceInBytes': device_data.get('totalStorageSpaceInBytes'),
        'freeStorageSpaceInBytes': device_data.get('freeStorageSpaceInBytes'),
        'managedDeviceName': device_data.get('managedDeviceName'),
        'partnerReportedThreatState': device_data.get('partnerReportedThreatState'),
        'requireUserEnrollmentApproval': device_data.get('requireUserEnrollmentApproval'),
        'managementCertificateExpirationDate': device_data.get('managementCertificateExpirationDate'),
        'iccid': device_data.get('iccid'),
        'udid': device_data.get('udid'),
        'notes': device_data.get('notes'),
        'ethernetMacAddress': device_data.get('ethernetMacAddress'),
        'physicalMemoryInBytes': device_data.get('physicalMemoryInBytes'),
        'enrollmentProfileName': device_data.get('enrollmentProfileName'),
        'parentDevice': parent_device,
    }

def updateMicrosoftIntuneDeviceDatabase(json_data):
    """Update Intune device records using bulk operations."""
    integration = Integration.objects.get(integration_type="Microsoft Intune")

    # --- Phase 1: Process all API data ---
    processed = []
    for device_data in json_data:
        hostname = (device_data.get('deviceName') or '').lower()
        if not hostname:
            continue
        os_platform = device_data.get('operatingSystem', '')
        manufacturer = (device_data.get('manufacturer') or '').title()
        clean_data = cleanAPIData(os_platform)

        if clean_data[0] == "Android":
            hostname = (device_data.get('id') or '').lower()

        processed.append({
            'hostname': hostname,
            'os_platform': clean_data[0],
            'endpoint_type': clean_data[1],
            'manufacturer': manufacturer,
            'device_data': device_data,
        })

    if not processed:
        return

    incoming_hostnames = {p['hostname'] for p in processed}
    incoming_ids = {p['device_data'].get('id') for p in processed if p['device_data'].get('id')}

    # --- Phase 2: Fetch existing state in bulk ---
    existing_devices = {d.hostname: d for d in Device.objects.filter(hostname__in=incoming_hostnames)}
    existing_details = set(MicrosoftIntuneDeviceData.objects.filter(id__in=incoming_ids).values_list('id', flat=True))

    # --- Phase 3: Build create/update lists ---
    devices_to_create = []
    devices_to_update = []
    details_to_create = []
    details_to_update = []

    for p in processed:
        hostname = p['hostname']

        if hostname in existing_devices:
            obj = existing_devices[hostname]
            obj.osPlatform = p['os_platform']
            obj.endpointType = p['endpoint_type']
            obj.manufacturer = p['manufacturer']
            devices_to_update.append(obj)
        else:
            obj = Device(hostname=hostname, osPlatform=p['os_platform'], endpointType=p['endpoint_type'], manufacturer=p['manufacturer'])
            devices_to_create.append(obj)

    # --- Phase 4: Bulk write Device records ---
    if devices_to_create:
        Device.objects.bulk_create(devices_to_create, ignore_conflicts=True)
    if devices_to_update:
        Device.objects.bulk_update(devices_to_update, _DEVICE_UPDATE_FIELDS, batch_size=500)

    # Re-fetch to get PKs for newly created devices
    all_devices = {d.hostname: d for d in Device.objects.filter(hostname__in=incoming_hostnames)}

    # --- Phase 5: Build and write vendor detail records ---
    for p in processed:
        parent = all_devices.get(p['hostname'])
        if not parent:
            continue
        detail_id = p['device_data'].get('id')
        fields = _build_intune_detail_fields(p['device_data'], p['hostname'], parent)

        if detail_id in existing_details:
            detail_obj = MicrosoftIntuneDeviceData(pk=detail_id, **{k: v for k, v in fields.items() if k != 'id'})
            details_to_update.append(detail_obj)
        else:
            details_to_create.append(MicrosoftIntuneDeviceData(**fields))

    if details_to_create:
        MicrosoftIntuneDeviceData.objects.bulk_create(details_to_create, ignore_conflicts=True)
    if details_to_update:
        MicrosoftIntuneDeviceData.objects.bulk_update(details_to_update, _INTUNE_UPDATE_FIELDS, batch_size=500)

    # --- Phase 6: Bulk set M2M integration links ---
    DeviceIntegrationThrough = Device.integration.through
    existing_links = set(
        DeviceIntegrationThrough.objects.filter(
            integration=integration,
            device__hostname__in=incoming_hostnames
        ).values_list('device_id', flat=True)
    )
    new_links = [
        DeviceIntegrationThrough(device=dev, integration=integration)
        for dev in all_devices.values()
        if dev.pk not in existing_links
    ]
    if new_links:
        DeviceIntegrationThrough.objects.bulk_create(new_links, ignore_conflicts=True)

    # --- Phase 7: Bulk compliance check ---
    devices_for_compliance = Device.objects.filter(hostname__in=incoming_hostnames).prefetch_related('integration')
    compliance_updates = []
    for device in devices_for_compliance:
        settings = complianceSettings(device.osPlatform)
        if settings:
            required = {k for k, v in settings.items() if v}
            current = {i.integration_type for i in device.integration.all()}
            device.compliant = required.issubset(current)
        else:
            device.compliant = True
        compliance_updates.append(device)
    if compliance_updates:
        Device.objects.bulk_update(compliance_updates, ['compliant'], batch_size=500)

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
