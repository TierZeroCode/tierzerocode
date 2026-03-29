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

_DEVICE_UPDATE_FIELDS = ['osPlatform', 'endpointType', 'manufacturer']

_ENTRA_DEVICE_UPDATE_FIELDS = [
    'deletedDateTime', 'accountEnabled', 'approximateLastSignInDateTime',
    'complianceExpirationDateTime', 'createdDateTime', 'deviceCategory', 'deviceId',
    'deviceMetadata', 'deviceOwnership', 'deviceVersion', 'displayName', 'domainName',
    'enrollmentProfileName', 'enrollmentType', 'externalSourceName', 'isCompliant',
    'isManaged', 'isRooted', 'managementType', 'manufacturer', 'mdmAppId', 'model',
    'onPremisesLastSyncDateTime', 'onPremisesSyncEnabled', 'operatingSystem',
    'operatingSystemVersion', 'profileType', 'registrationDateTime', 'sourceType',
    'trustType', 'parentDevice',
]

######################################## Start Update/Create Microsoft Entra ID Devices ########################################

def _build_entra_detail_fields(device_data, hostname, parent_device):
    """Build the field dict for a MicrosoftEntraIDDeviceData record."""
    return {
        'id': device_data['id'],
        'deletedDateTime': device_data.get('deletedDateTime'),
        'accountEnabled': device_data.get('accountEnabled'),
        'approximateLastSignInDateTime': device_data.get('approximateLastSignInDateTime'),
        'complianceExpirationDateTime': device_data.get('complianceExpirationDateTime'),
        'createdDateTime': device_data.get('createdDateTime'),
        'deviceCategory': device_data.get('deviceCategory'),
        'deviceId': device_data.get('deviceId'),
        'deviceMetadata': device_data.get('deviceMetadata'),
        'deviceOwnership': device_data.get('deviceOwnership'),
        'deviceVersion': device_data.get('deviceVersion'),
        'displayName': hostname,
        'domainName': device_data.get('domainName'),
        'enrollmentProfileName': device_data.get('enrollmentProfileName'),
        'enrollmentType': device_data.get('enrollmentType'),
        'externalSourceName': device_data.get('externalSourceName'),
        'isCompliant': device_data.get('isCompliant'),
        'isManaged': device_data.get('isManaged'),
        'isRooted': device_data.get('isRooted'),
        'managementType': device_data.get('managementType'),
        'manufacturer': device_data.get('manufacturer'),
        'mdmAppId': device_data.get('mdmAppId'),
        'model': device_data.get('model'),
        'onPremisesLastSyncDateTime': device_data.get('onPremisesLastSyncDateTime'),
        'onPremisesSyncEnabled': device_data.get('onPremisesSyncEnabled'),
        'operatingSystem': device_data.get('operatingSystem'),
        'operatingSystemVersion': device_data.get('operatingSystemVersion'),
        'profileType': device_data.get('profileType'),
        'registrationDateTime': device_data.get('registrationDateTime'),
        'sourceType': device_data.get('sourceType'),
        'trustType': device_data.get('trustType'),
        'parentDevice': parent_device,
    }

def updateMicrosoftEntraIDDeviceDatabase(json_data):
    """Update Entra ID device records using bulk operations."""
    integration = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="Device")

    # --- Phase 1: Process all API data ---
    ownership_filter = integration.device_ownership_filter
    processed = []
    for device_data in json_data:
        # Apply device ownership filter
        if ownership_filter and ownership_filter != 'All':
            device_ownership = device_data.get('deviceOwnership', '')
            if device_ownership != ownership_filter:
                continue

        hostname = (device_data.get('displayName') or '').lower()
        if not hostname:
            continue
        os_platform = device_data.get('operatingSystem', '')
        manufacturer = (device_data.get('manufacturer') or '').title() or None
        clean_data = cleanAPIData(os_platform)

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
    incoming_ids = {p['device_data']['id'] for p in processed}

    # --- Phase 2: Fetch existing state in bulk ---
    existing_devices = {d.hostname: d for d in Device.objects.filter(hostname__in=incoming_hostnames)}
    existing_details = set(MicrosoftEntraIDDeviceData.objects.filter(id__in=incoming_ids).values_list('id', flat=True))

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
        detail_id = p['device_data']['id']
        fields = _build_entra_detail_fields(p['device_data'], p['hostname'], parent)

        if detail_id in existing_details:
            detail_obj = MicrosoftEntraIDDeviceData(pk=detail_id, **{k: v for k, v in fields.items() if k != 'id'})
            details_to_update.append(detail_obj)
        else:
            details_to_create.append(MicrosoftEntraIDDeviceData(**fields))

    if details_to_create:
        MicrosoftEntraIDDeviceData.objects.bulk_create(details_to_create, ignore_conflicts=True)
    if details_to_update:
        MicrosoftEntraIDDeviceData.objects.bulk_update(details_to_update, _ENTRA_DEVICE_UPDATE_FIELDS, batch_size=500)

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
