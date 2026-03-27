# Import Dependencies
import logging
import requests, json, xmltodict
from django.utils import timezone

logger = logging.getLogger(__name__)
# Import Models
from ...models import QualysDevice, Integration, Device, DeviceComplianceSettings
# Import Functions Scripts
from .ReusedFunctions import cleanAPIData, complianceSettings, bulk_sync_devices

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

    if api_result.status_code != 200:
        logger.error("Qualys logout failed. Status: %s", api_result.status_code)

def getQualysDevices(s):
    url = 'https://qualysapi.qualys.com/api/2.0/fo/asset/host/?action=list'
    headers = {
        'X-Requested-With': 'Tier Zero Code',
        'Content-Type': 'application/json',
    }

    try:
        api_result = s.get(url=url, headers=headers)

        if api_result.status_code == 200:
            xml_parse = xmltodict.parse(api_result.text)
            return xml_parse
        else:
            logger.error("Qualys failed to fetch assets. Status: %s", api_result.status_code)
            return None
    finally:
        getQualysLogout(s)

def updateQualysDeviceDatabase(json_data):
    integration = Integration.objects.get(integration_type="Qualys")
    host_list = json_data.get("HOST_LIST_OUTPUT", {}).get("RESPONSE", {}).get("HOST_LIST", {}).get("HOST", [])
    processed = []
    for host_data in host_list:
        hostname_raw = (host_data.get("DNS_DATA") or {}).get("HOSTNAME")
        if not hostname_raw:
            continue
        hostname = hostname_raw.lower()
        clean_data = cleanAPIData(host_data.get("OS"))
        processed.append({
            'hostname': hostname, 'os_platform': clean_data[0],
            'endpoint_type': clean_data[1], 'device_data': host_data,
            'detail_id': None,  # Qualys has no vendor detail table in current sync
        })
    # Qualys has no vendor detail table — skip detail phases
    bulk_sync_devices(integration, processed)

def syncQualys():
    data = Integration.objects.get(integration_type = "Qualys")
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    updateQualysDeviceDatabase(getQualysDevices(getQualysAccessToken(client_id, client_secret, tenant_id)))
    data.last_synced_at = timezone.now()
    data.save()
    return True
