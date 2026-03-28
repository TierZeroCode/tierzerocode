# Import Dependencies
from django.utils import timezone
# Import Models
from apps.main.models import Integration, Device, MicrosoftDefenderforEndpointDeviceData, DeviceComplianceSettings
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import cleanAPIData, complianceSettings, _fetch_paginated_data, bulk_sync_devices
import json
from apps.code_packages.microsoft import getMicrosoftGraphAccessToken

def _truncate_string(value, max_length=200):
    """Truncate string to max_length if it exceeds the limit."""
    if value is None:
        return None
    str_value = str(value)
    if len(str_value) > max_length:
        return str_value[:max_length]
    return str_value

######################################## Start Get Microsoft Defender for Endpoint Devices ########################################
def getMicrosoftDefenderforEndpointDevices(access_token):
    """Fetch all enabled Microsoft Defender for Endpoint devices."""
    url = 'https://api.securitycenter.microsoft.com/api/machines'
    headers = {'Authorization': access_token}
    return _fetch_paginated_data(url, headers)
######################################## End Get Microsoft Defender for Endpoint Devices ########################################

######################################## Start Update/Create Microsoft Defender for Endpoint Devices ########################################

_DEFENDER_UPDATE_FIELDS = [
    'mergedIntoMachineId', 'isPotentialDuplication', 'isExcluded', 'exclusionReason',
    'computerDnsName', 'firstSeen', 'lastSeen', 'osPlatform', 'osVersion', 'osProcessor',
    'version', 'lastIpAddress', 'lastExternalIpAddress', 'agentVersion', 'osBuild',
    'healthStatus', 'deviceValue', 'rbacGroupId', 'rbacGroupName', 'riskScore',
    'exposureLevel', 'isAadJoined', 'aadDeviceId', 'onboardingStatus', 'osArchitecture',
    'managedBy', 'managedByStatus', 'vmMetadata', 'parentDevice',
]

def _build_defender_detail(device_data, hostname, parent):
    vm_metadata = device_data.get('vmMetadata')
    if vm_metadata is not None and isinstance(vm_metadata, dict):
        vm_metadata = json.dumps(vm_metadata)
    elif vm_metadata is not None:
        vm_metadata = str(vm_metadata)
    return {
        'id': _truncate_string(device_data.get('id'), 200),
        'mergedIntoMachineId': _truncate_string(device_data.get('mergedIntoMachineId'), 200),
        'isPotentialDuplication': device_data.get('isPotentialDuplication'),
        'isExcluded': device_data.get('isExcluded'),
        'exclusionReason': _truncate_string(device_data.get('exclusionReason'), 200),
        'computerDnsName': _truncate_string(hostname, 200),
        'firstSeen': _truncate_string(device_data.get('firstSeen'), 200),
        'lastSeen': _truncate_string(device_data.get('lastSeen'), 200),
        'osPlatform': _truncate_string(device_data.get('osPlatform'), 200),
        'osVersion': _truncate_string(device_data.get('osVersion'), 200),
        'osProcessor': _truncate_string(device_data.get('osProcessor'), 200),
        'version': _truncate_string(device_data.get('version'), 200),
        'lastIpAddress': _truncate_string(device_data.get('lastIpAddress'), 200),
        'lastExternalIpAddress': _truncate_string(device_data.get('lastExternalIpAddress'), 200),
        'agentVersion': _truncate_string(device_data.get('agentVersion'), 200),
        'osBuild': int(device_data['osBuild']) if device_data.get('osBuild') is not None else None,
        'healthStatus': _truncate_string(device_data.get('healthStatus'), 200),
        'deviceValue': _truncate_string(device_data.get('deviceValue'), 200),
        'rbacGroupId': int(device_data['rbacGroupId']) if device_data.get('rbacGroupId') is not None else None,
        'rbacGroupName': _truncate_string(device_data.get('rbacGroupName'), 200),
        'riskScore': _truncate_string(device_data.get('riskScore'), 200),
        'exposureLevel': _truncate_string(device_data.get('exposureLevel'), 200),
        'isAadJoined': device_data.get('isAadJoined'),
        'aadDeviceId': _truncate_string(device_data.get('aadDeviceId'), 200),
        'onboardingStatus': _truncate_string(device_data.get('onboardingStatus'), 200),
        'osArchitecture': _truncate_string(device_data.get('osArchitecture'), 200),
        'managedBy': _truncate_string(device_data.get('managedBy'), 200),
        'managedByStatus': _truncate_string(device_data.get('managedByStatus'), 200),
        'vmMetadata': vm_metadata,
        'parentDevice': parent,
    }

def updateMicrosoftDefenderforEndpointDeviceDatabase(json_data):
    integration = Integration.objects.get(integration_type="Microsoft Defender for Endpoint")
    processed = []
    for device_data in json_data:
        if device_data.get('onboardingStatus') != 'Onboarded' or device_data.get('healthStatus') == 'Inactive':
            continue
        computer_dns_name = device_data.get('computerDnsName')
        if not computer_dns_name or not device_data.get('osPlatform') or not device_data.get('id'):
            continue
        hostname = (computer_dns_name.split('.', 1)[0]).lower()
        clean_data = cleanAPIData(device_data['osPlatform'])
        processed.append({
            'hostname': hostname, 'os_platform': clean_data[0],
            'endpoint_type': clean_data[1], 'device_data': device_data,
            'detail_id': device_data.get('id'),
        })
    bulk_sync_devices(integration, processed, MicrosoftDefenderforEndpointDeviceData, _DEFENDER_UPDATE_FIELDS, _build_defender_detail)

######################################## End Update/Create Microsoft Defender for Endpoint Devices ########################################

######################################## Start Sync Microsoft Defender for Endpoint ########################################
def syncMicrosoftDefenderforEndpointDevice():
    data = Integration.objects.get(integration_type = "Microsoft Defender for Endpoint")
    if not data.client_id or not data.client_secret or not data.tenant_id:
        raise Exception("Microsoft Defender for Endpoint integration is not properly configured. Missing client_id, client_secret, or tenant_id.")
    
    access_token = getMicrosoftGraphAccessToken(data.client_id, data.client_secret, data.tenant_id, ["https://api.securitycenter.microsoft.com/.default"])
    if isinstance(access_token, dict) and 'error' in access_token:
        error_msg = str(access_token['error'])
        raise Exception(f"Failed to get access token: {error_msg}")
    
    updateMicrosoftDefenderforEndpointDeviceDatabase(getMicrosoftDefenderforEndpointDevices(access_token))
    data.last_synced_at = timezone.now()
    data.save()
    return True
######################################## End Sync Microsoft Defender for Endpoint ########################################