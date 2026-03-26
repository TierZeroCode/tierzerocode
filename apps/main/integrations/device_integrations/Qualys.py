# Import Dependencies
import logging
import requests, json, xmltodict
from datetime import datetime

logger = logging.getLogger(__name__)
# Import Models
from ...models import QualysDevice, Integration, Device, DeviceComplianceSettings
# Import Functions Scripts
from .masterlist import *
from .ReusedFunctions import *

def getQualysAccessToken(client_id, client_secret, tenant_id):
    # Define the authentication endpoint URL
    auth_url = 'https://qualysapi.qualys.com/api/2.0/fo/session/'

    # Define the authentication payload
    headers = {
        'X-Requested-With': 'Tier Zero Code',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    auth_payload = {
        'action': 'login',
        'username': client_id,
        'password': client_secret,
    }

    s = requests.Session()

    try:
        # Make a POST request to the authentication endpoint
        response = s.post(auth_url, headers=headers, data=auth_payload)
        
        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Extract the access token from the response
            session_token = response.cookies['QualysSession']
            # print(session_token)
            
            # Print the access token (or use it for further API requests)
            return s
        else:
            logger.error("Qualys auth failed. Status: %s", response.status_code)
            return None
    except Exception as e:
        logger.error("Qualys auth error: %s", str(e))
        return None

def getQualysLogout(s):
    url = 'https://qualysapi.qualys.com/api/2.0/fo/session/'
    headers = {
        'X-Requested-With': 'Tier Zero Code',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    auth_payload = {
        'action': 'logout',
    }

    # Make a GET request to the provided url, passing the access token in a header
    api_result = s.post(url=url, headers=headers, data=auth_payload)

    if api_result.status_code == 200:
        print("Logout Successful")
    else:
        print("Failed to Logout. Status code:", api_result.status_code)

def getQualysDevices(s):
    url = 'https://qualysapi.qualys.com/api/2.0/fo/asset/host/?action=list'
    headers = {
        'X-Requested-With': 'Tier Zero Code',
        'Content-Type': 'application/json',
    }
    auth_payload = {
        'action': 'list',
    }

    # Make a GET request to the provided url, passing the access token in a header
    api_result = s.get(url=url, headers=headers)

    if api_result.status_code == 200:
        xml_parse = xmltodict.parse(api_result.text)

        # Print the results in a JSON format
        getQualysLogout(s)
        return (xml_parse)
    else:
        print("Failed to fetch assets. Status code:", api_result.status_code)
        getQualysLogout(s)
        return None

def updateQualysDeviceDatabase(json_data):
    host_list = json_data.get("HOST_LIST_OUTPUT", {}).get("RESPONSE", {}).get("HOST_LIST", {}).get("HOST", [])
    for host_data in host_list:
        # device_id = host_data.get("ID")
        hostname = host_data.get("DNS_DATA", {}).get("HOSTNAME").lower()
        os_platform = host_data.get("OS")
        # first_found_date = host_data.get("FIRST_FOUND_DATE")
        # ip_address = host_data.get("IP")

        clean_data = cleanAPIData(os_platform)     
        
        defaults = {
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
        }
        
        device, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
        device.integration.add(Integration.objects.get(integration_type="Qualys"))
        
        # Check compliance: device must have ALL required integrations
        compliance_settings = complianceSettings(clean_data[0])
        if compliance_settings:
            # Get all required integrations (where value is True)
            required_integrations = [name for name, is_required in compliance_settings.items() if is_required]
            # Get device's current integrations
            device_integrations = set(device.integration.values_list('integration_type', flat=True))
            # Device is compliant if it has all required integrations
            device.compliant = all(integration_name in device_integrations for integration_name in required_integrations)
        else:
            # No compliance requirements = compliant
            device.compliant = True
        device.save()

def syncQualys():
    data = Integration.objects.get(integration_type = "Qualys")
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    updateQualysDeviceDatabase(getQualysDevices(getQualysAccessToken(client_id, client_secret, tenant_id)))
    data.last_synced_at = datetime.now()
    data.save()
    return True
