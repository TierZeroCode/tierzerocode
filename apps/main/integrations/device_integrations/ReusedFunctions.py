# Django Model Imports
import time
import requests
from functools import lru_cache
from apps.main.models import Device, DeviceComplianceSettings
from apps.logger.views import createLog

_DEVICE_UPDATE_FIELDS = ['osPlatform', 'endpointType', 'manufacturer']


def _sync_log(integration_name, event_code, outcome, additional_data):
    """Log sync events via createLog (logger app) — works without a request object."""
    try:
        createLog(None, event_code, "System Integration", "System Integration Event",
                  "System", True, f"{integration_name} Sync", outcome,
                  additional_data=additional_data)
    except Exception:
        pass  # createLog already has its own fallback


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


def bulk_sync_devices(integration, processed_devices, DetailModel=None, detail_update_fields=None, build_detail_fn=None):
    """
    Shared bulk sync pattern for all device integrations.

    Args:
        integration: Integration model instance
        processed_devices: list of dicts with keys: hostname, os_platform, endpoint_type, manufacturer, device_data
        DetailModel: the vendor-specific detail model class (e.g. CrowdStrikeFalconDeviceData)
        detail_update_fields: list of field names for bulk_update on the detail model
        build_detail_fn: callable(device_data, hostname, parent_device) -> dict of detail fields
    """
    integration_name = integration.integration_type

    if not processed_devices:
        _sync_log(integration_name, "1506", "Info", "No devices to process")
        return

    _sync_log(integration_name, "1506", "Info", f"Starting sync for {len(processed_devices)} devices")

    incoming_hostnames = {p['hostname'] for p in processed_devices}
    incoming_ids = {p['detail_id'] for p in processed_devices if p.get('detail_id')} if DetailModel else set()

    # --- Phase 1: Fetch existing state in bulk ---
    existing_devices = {d.hostname: d for d in Device.objects.filter(hostname__in=incoming_hostnames)}
    existing_details = set(DetailModel.objects.filter(id__in=incoming_ids).values_list('id', flat=True)) if DetailModel and incoming_ids else set()
    _sync_log(integration_name, "1506", "Info", f"Found {len(existing_devices)} existing devices, {len(existing_details)} existing details")

    # --- Phase 2: Build create/update lists for Device ---
    devices_to_create = []
    devices_to_update = []

    for p in processed_devices:
        hostname = p['hostname']
        if hostname in existing_devices:
            obj = existing_devices[hostname]
            obj.osPlatform = p['os_platform']
            obj.endpointType = p['endpoint_type']
            obj.manufacturer = p.get('manufacturer')
            devices_to_update.append(obj)
        else:
            devices_to_create.append(Device(
                hostname=hostname, osPlatform=p['os_platform'],
                endpointType=p['endpoint_type'], manufacturer=p.get('manufacturer'),
            ))

    # --- Phase 3: Bulk write Device records ---
    _sync_log(integration_name, "1506", "Info", f"Creating {len(devices_to_create)}, updating {len(devices_to_update)} Device records")
    if devices_to_create:
        Device.objects.bulk_create(devices_to_create, ignore_conflicts=True)
    if devices_to_update:
        Device.objects.bulk_update(devices_to_update, _DEVICE_UPDATE_FIELDS, batch_size=500)

    # Re-fetch to get PKs for newly created devices
    all_devices = {d.hostname: d for d in Device.objects.filter(hostname__in=incoming_hostnames)}

    # --- Phase 4: Build and write vendor detail records (if DetailModel provided) ---
    if DetailModel and build_detail_fn:
        details_to_create = []
        details_to_update = []

        for p in processed_devices:
            parent = all_devices.get(p['hostname'])
            if not parent:
                _sync_log(integration_name, "1506", "Warning", f"No parent device for hostname {p['hostname']}")
                continue
            detail_id = p.get('detail_id')
            try:
                fields = build_detail_fn(p['device_data'], p['hostname'], parent)
            except Exception as e:
                _sync_log(integration_name, "1506", "Failure", f"Error building detail for {p['hostname']}: {e}")
                continue

            if detail_id and detail_id in existing_details:
                detail_obj = DetailModel(pk=detail_id, **{k: v for k, v in fields.items() if k != 'id'})
                details_to_update.append(detail_obj)
            else:
                details_to_create.append(DetailModel(**fields))

        _sync_log(integration_name, "1506", "Info", f"Creating {len(details_to_create)}, updating {len(details_to_update)} detail records")
        if details_to_create:
            DetailModel.objects.bulk_create(details_to_create, ignore_conflicts=True)
        if details_to_update and detail_update_fields:
            DetailModel.objects.bulk_update(details_to_update, detail_update_fields, batch_size=500)

    # --- Phase 5: Bulk set M2M integration links ---
    _sync_log(integration_name, "1506", "Info", "Setting M2M integration links")
    DeviceIntegrationThrough = Device.integration.through
    existing_links = set(
        DeviceIntegrationThrough.objects.filter(
            integration=integration, device__hostname__in=incoming_hostnames
        ).values_list('device_id', flat=True)
    )
    new_links = [
        DeviceIntegrationThrough(device=dev, integration=integration)
        for dev in all_devices.values()
        if dev.pk not in existing_links
    ]
    if new_links:
        DeviceIntegrationThrough.objects.bulk_create(new_links, ignore_conflicts=True)

    # --- Phase 6: Bulk compliance check ---
    _sync_log(integration_name, "1506", "Info", "Running compliance check")
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

    # --- Phase 7: Remove stale integration links and orphaned devices ---
    _sync_log(integration_name, "1506", "Info", "Cleaning up stale devices")

    # Find devices linked to this integration that were NOT in this sync
    stale_links = DeviceIntegrationThrough.objects.filter(
        integration=integration
    ).exclude(
        device__hostname__in=incoming_hostnames
    )
    stale_device_ids = set(stale_links.values_list('device_id', flat=True))
    stale_count = stale_links.count()

    if stale_count > 0:
        # Remove the M2M links for stale devices
        stale_links.delete()
        _sync_log(integration_name, "1506", "Info", f"Removed {stale_count} stale integration links")

        # Delete devices that now have zero integrations
        from django.db.models import Count
        orphaned = Device.objects.filter(
            id__in=stale_device_ids
        ).annotate(
            integration_count=Count('integration')
        ).filter(
            integration_count=0
        )
        orphaned_count = orphaned.count()
        if orphaned_count > 0:
            orphaned.delete()
            _sync_log(integration_name, "1506", "Info", f"Deleted {orphaned_count} orphaned devices (no integrations remaining)")

    _sync_log(integration_name, "1506", "Success", f"Sync complete — {len(processed_devices)} devices processed")
