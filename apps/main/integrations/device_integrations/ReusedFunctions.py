# Django Model Imports
import time
import requests
from functools import lru_cache
from apps.main.models import DeviceComplianceSettings


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

def cleanAPIData(os_platform):
    if not os_platform:
        return ['Other', 'Other']
    os_platform_lower = os_platform.lower()
    if 'server' in os_platform_lower and 'windows' in os_platform_lower:
        osPlatform_clean = 'Windows Server'
        endpointType = 'Server'
    elif 'ubuntu' in os_platform_lower:
        osPlatform_clean  = 'Ubuntu'
        endpointType = 'Server'
    elif 'rhel' in os_platform_lower:
        osPlatform_clean  = 'Red Hat Enterprise Linux'
        endpointType = 'Server'
    elif 'centos' in os_platform_lower:
        osPlatform_clean  = 'CentOS'
        endpointType = 'Server'
    elif 'monterey (12)' in os_platform_lower or 'ventura (13)' in os_platform_lower or 'sonoma (14)' in os_platform_lower:
        osPlatform_clean  = 'MacOS'
        endpointType = 'Client'
    elif 'windows' in os_platform_lower:
        osPlatform_clean  = 'Windows'
        endpointType = 'Client'
    elif 'android' in os_platform_lower:
        osPlatform_clean  = 'Android'
        endpointType = 'Mobile'
    elif 'ios' in os_platform_lower or 'ipados' in os_platform_lower or 'iphone' in os_platform_lower or 'ipad' in os_platform_lower:
        osPlatform_clean = 'iOS/iPadOS'
        endpointType = 'Mobile'
    else:
        osPlatform_clean  = 'Other'
        endpointType = 'Other'
    return [osPlatform_clean, endpointType]

@lru_cache(maxsize=32)
def complianceSettings(os_platform):
    try:
        settings = DeviceComplianceSettings.objects.get(os_platform=os_platform)
        return {
            'Cloudflare Zero Trust': settings.cloudflare_zero_trust,
            'CrowdStrike Falcon': settings.crowdstrike_falcon,
            'Microsoft Defender for Endpoint': settings.microsoft_defender_for_endpoint,
            'Microsoft Entra ID': settings.microsoft_entra_id,
            'Microsoft Intune': settings.microsoft_intune,
            'Sophos Central': settings.sophos_central,
            'Qualys': settings.qualys,
            'Tailscale': settings.tailscale,
        }
    except DeviceComplianceSettings.DoesNotExist:
        return {}