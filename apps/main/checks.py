from apps.main.models import DeviceComplianceSettings, Integration
from django.contrib.auth.models import User

# Configuration for required integrations and settings
#X6969
REQUIRED_SYSTEM_DEVICE_INTEGRATIONS = ['Microsoft Entra ID', 'Qualys', 'Sophos Central', 'Microsoft Intune', 'Microsoft Defender for Endpoint', 'CrowdStrike Falcon', 'Cloudflare Zero Trust', 'Tailscale']
REQUIRED_SYSTEM_DEVICE_INTEGRATIONS_SHORT = ['Entra ID', 'Qualys', 'Sophos', 'Intune', 'Defender', 'CrowdStrike', 'Cloudflare', 'Tailscale']
REQUIRED_SYSTEM_USER_INTEGRATIONS = ['Microsoft Entra ID']
REQUIRED_SYSTEM_USER_INTEGRATIONS_SHORT = ['Entra ID']
REQUIRED_OS_PLATFORMS = ['Android', 'iOS/iPadOS', 'MacOS', 'Red Hat Enterprise Linux', 'CentOS', 'Ubuntu', 'Windows', 'Windows Server', 'Other']

def checkSystemDeviceIntegrations():
	"""Check if all required system integrations exist."""
	existing_device_integrations = set(Integration.objects.filter(integration_context="Device").values_list('integration_type', flat=True))
	required_device_integrations = set(REQUIRED_SYSTEM_DEVICE_INTEGRATIONS)
	return required_device_integrations.issubset(existing_device_integrations)

def checkSystemUserIntegrations():
	"""Check if all required system integrations exist."""
	existing_user_integrations = set(Integration.objects.filter(integration_context="User").values_list('integration_type', flat=True))
	required_user_integrations = set(REQUIRED_SYSTEM_USER_INTEGRATIONS)
	return required_user_integrations.issubset(existing_user_integrations)

def checkDeviceComplianceSettings():
	"""Check if all required device compliance settings exist."""
	existing_device_compliance_settings = set(DeviceComplianceSettings.objects.values_list('os_platform', flat=True))
	required_device_compliance_settings = set(REQUIRED_OS_PLATFORMS)
	return required_device_compliance_settings.issubset(existing_device_compliance_settings)

def _get_image_paths(integration_name):
	"""Helper function to generate image paths for integrations."""
	base_name = integration_name.replace(" ", "_").lower()
	return {
		'navbar': f'main/img/navbar_icons/webp/{base_name}_logo_nav.webp',
		'integration': f'main/img/integration_images/webp/{base_name}_logo.webp'
	}

def systemDeviceInitialSetup():
	"""Create missing system integrations with default values."""
	for integration_name in REQUIRED_SYSTEM_DEVICE_INTEGRATIONS:
		if Integration.objects.filter(integration_type=integration_name, integration_context="Device").exists():
			continue
		
		image_paths = _get_image_paths(integration_name)
		Integration.objects.create(
			integration_type=integration_name,
			enabled=False,
			integration_type_short=REQUIRED_SYSTEM_DEVICE_INTEGRATIONS_SHORT[REQUIRED_SYSTEM_DEVICE_INTEGRATIONS.index(integration_name)],
			integration_context='Device',
			image_navbar_path=image_paths['navbar'],
			image_integration_path=image_paths['integration']
		)

def systemUserInitialSetup():
	"""Create missing system integrations with default values."""
	for integration_name in REQUIRED_SYSTEM_USER_INTEGRATIONS:
		if Integration.objects.filter(integration_type=integration_name, integration_context="User").exists():
			continue
		
		image_paths = _get_image_paths(integration_name)
		Integration.objects.create(
			integration_type=integration_name,
			enabled=False,
			integration_type_short=REQUIRED_SYSTEM_USER_INTEGRATIONS_SHORT[REQUIRED_SYSTEM_USER_INTEGRATIONS.index(integration_name)],
			integration_context='User',
			image_navbar_path=image_paths['navbar'],
			image_integration_path=image_paths['integration']
		)

def deviceComplianceSettingsInitialSetup():
	"""Create missing device compliance settings with default values."""
	for os_platform in REQUIRED_OS_PLATFORMS:
		if DeviceComplianceSettings.objects.filter(os_platform=os_platform).exists():
			continue
		DeviceComplianceSettings.objects.create(os_platform=os_platform)