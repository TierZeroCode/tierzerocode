# Django Model Imports
from functools import lru_cache
from apps.main.models import DeviceComplianceSettings

def cleanAPIData(os_platform):
    os_platform_lower = (os_platform).lower()
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