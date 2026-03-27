# Import Dependencies
import requests, time, json
from django.utils import timezone
# Import Models
from apps.main.models import Integration, Device, MicrosoftDefenderforEndpointDeviceData, DeviceComplianceSettings
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import *
from apps.code_packages.microsoft import getMicrosoftGraphAccessToken
from apps.main.integrations.device_integrations.ReusedFunctions import complianceSettings

def _truncate_string(value, max_length=200):
    """Truncate string to max_length if it exceeds the limit."""
    if value is None:
        return None
    str_value = str(value)
    if len(str_value) > max_length:
        return str_value[:max_length]
    return str_value

def _fetch_paginated_data(url, headers, max_retries=5, retry_delay=1):
    """Generic function to fetch paginated data with retry logic."""
    results = []
    while url:
        for attempt in range(max_retries):
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                results.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
                break
            elif response.status_code == 429:  # Throttling error
                retry_after = int(response.headers.get('Retry-After', retry_delay))
                time.sleep(retry_after)
            else:
                raise Exception(f"Failed to fetch data: {response.status_code} - {response.text}")
        else:
            raise Exception("Max retries exceeded while fetching data.")
    return results

######################################## Start Get Microsoft Defender for Endpoint Devices ########################################
def getMicrosoftDefenderforEndpointDevices(access_token):
    """Fetch all enabled Microsoft Defender for Endpoint devices."""
    url = 'https://api.securitycenter.microsoft.com/api/machines'
    headers = {'Authorization': access_token}
    return _fetch_paginated_data(url, headers)
######################################## End Get Microsoft Defender for Endpoint Devices ########################################

######################################## Start Update/Create Microsoft Defender for Endpoint Devices ########################################
def updateMicrosoftDefenderforEndpointDeviceDatabase(json_data):
    integration = Integration.objects.get(integration_type="Microsoft Defender for Endpoint")
    for device_data in json_data:
        if device_data.get('onboardingStatus') == 'Onboarded' and not device_data.get('healthStatus') == 'Inactive':
            computer_dns_name = device_data.get('computerDnsName')
            if not computer_dns_name:
                continue
            hostname = (computer_dns_name.split('.', 1)[0]).lower()
            os_platform = device_data.get('osPlatform')
            if not os_platform:
                continue
            clean_data = cleanAPIData(os_platform)
            
            defaults = {
                'hostname': hostname,
                'osPlatform': clean_data[0],
                'endpointType': clean_data[1],
            }

            obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
            obj.integration.add(integration)

            # Check compliance: device must have ALL required integrations
            os_platform = clean_data[0]
            compliance_settings = complianceSettings(os_platform)
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

            # Handle vmMetadata - serialize dict to JSON string if needed
            vm_metadata = device_data.get('vmMetadata')
            if vm_metadata is not None and isinstance(vm_metadata, dict):
                vm_metadata = json.dumps(vm_metadata)
            elif vm_metadata is not None:
                vm_metadata = str(vm_metadata)
            
            defaults_all = {
                "id": _truncate_string(device_data.get('id'), 200),
                "mergedIntoMachineId": _truncate_string(device_data.get('mergedIntoMachineId'), 200),
                "isPotentialDuplication": device_data.get('isPotentialDuplication'),
                "isExcluded": device_data.get('isExcluded'),
                "exclusionReason": _truncate_string(device_data.get('exclusionReason'), 200),
                "computerDnsName": _truncate_string(hostname, 200),
                "firstSeen": _truncate_string(device_data.get('firstSeen'), 200),
                "lastSeen": _truncate_string(device_data.get('lastSeen'), 200),
                "osPlatform": _truncate_string(device_data.get('osPlatform'), 200),
                "osVersion": _truncate_string(device_data.get('osVersion'), 200),
                "osProcessor": _truncate_string(device_data.get('osProcessor'), 200),
                "version": _truncate_string(device_data.get('version'), 200),
                "lastIpAddress": _truncate_string(device_data.get('lastIpAddress'), 200),
                "lastExternalIpAddress": _truncate_string(device_data.get('lastExternalIpAddress'), 200),
                "agentVersion": _truncate_string(device_data.get('agentVersion'), 200),
                "osBuild": device_data.get('osBuild'),
                "healthStatus": _truncate_string(device_data.get('healthStatus'), 200),
                "deviceValue": _truncate_string(device_data.get('deviceValue'), 200),
                "rbacGroupId": device_data.get('rbacGroupId'),
                "rbacGroupName": _truncate_string(device_data.get('rbacGroupName'), 200),
                "riskScore": _truncate_string(device_data.get('riskScore'), 200),
                "exposureLevel": _truncate_string(device_data.get('exposureLevel'), 200),
                "isAadJoined": device_data.get('isAadJoined'),
                "aadDeviceId": _truncate_string(device_data.get('aadDeviceId'), 200),
                # "defenderAvStatus": _truncate_string(device_data.get('defenderAvStatus'), 200),
                "onboardingStatus": _truncate_string(device_data.get('onboardingStatus'), 200),
                "osArchitecture": _truncate_string(device_data.get('osArchitecture'), 200),
                "managedBy": _truncate_string(device_data.get('managedBy'), 200),
                "managedByStatus": _truncate_string(device_data.get('managedByStatus'), 200),
                "vmMetadata": _truncate_string(vm_metadata, 200),
                "parentDevice": obj
            }
            device_id = device_data.get('id')
            if not device_id:
                continue
            MicrosoftDefenderforEndpointDeviceData.objects.update_or_create(id=device_id, defaults=defaults_all)

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