# Standard library imports
import logging
import re, json
from datetime import date, datetime

logger = logging.getLogger(__name__)

# Third-party imports
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count, Prefetch, Q
from django.forms.models import model_to_dict
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, render, redirect
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

# Local imports
from .integrations.user_integrations.MicrosoftEntraID import (
    getMicrosoftEntraIDGuests, getMicrosoftEntraIDGroups,
    getMicrosoftEntraIDApps, getMicrosoftEntraTenantDetails,
)
from .models import Control, ControlFramework, Device, DeviceComplianceSettings, Integration, Notification, SignInSummary, UserData, PersonaGroup, Persona, PersonaTag
from ..code_packages.microsoft import getMicrosoftGraphAccessToken, testMicrosoftGraphConnection

############################################################################################

# Reused Data Sets
#X6969
integration_names = ['Cloudflare Zero Trust', 'CrowdStrike Falcon', 'Microsoft Defender for Endpoint', 'Microsoft Entra ID', 'Microsoft Intune', 'Sophos Central', 'Qualys', 'Tailscale']
user_integration_names = ['Microsoft Entra ID', 'Active Directory']
#X6969
integration_names_short = ['Cloudflare', 'CrowdStrike', 'Defender', 'Entra ID', 'Intune', 'Sophos', 'Qualys', 'Tailscale']
user_integration_names_short = ['Entra ID', 'Active Directory']

VALID_DEVICE_INTEGRATION_SLUGS = {'microsoft-entra-id', 'microsoft-intune', 'microsoft-defender-for-endpoint', 'crowdstrike-falcon', 'tailscale', 'cloudflare-zero-trust', 'qualys', 'sophos-central'}
VALID_USER_INTEGRATION_SLUGS = {'microsoft-entra-id', 'active-directory'}

# Maps URL slugs to the exact integration_type strings stored in the database.
# Using .replace("-", " ").title() is insufficient because .title() lowercases
# interior capitals (e.g. "ID" → "Id", "CrowdStrike" → "Crowdstrike").
SLUG_TO_INTEGRATION_TYPE = {
	'cloudflare-zero-trust': 'Cloudflare Zero Trust',
	'crowdstrike-falcon': 'CrowdStrike Falcon',
	'microsoft-defender-for-endpoint': 'Microsoft Defender for Endpoint',
	'microsoft-entra-id': 'Microsoft Entra ID',
	'microsoft-intune': 'Microsoft Intune',
	'sophos-central': 'Sophos Central',
	'qualys': 'Qualys',
	'tailscale': 'Tailscale',
	'active-directory': 'Active Directory',
}
os_platforms = ['Android', 'iOS/iPadOS', 'MacOS', 'Ubuntu', 'Windows', 'Windows Server', 'Other']
endpoint_types = ['Client', 'Mobile', 'Server', 'Other']

############################################################################################

def genErrors(request, Emessages):
	for message in Emessages:
		messages.warning(request, message)
		
def checkDeviceComplianceSettings(request):
	for os_platform in os_platforms:
		if DeviceComplianceSettings.objects.filter(os_platform = os_platform).exists():
			return True
	return False
	
def getEnabledIntegrations():
	return Integration.objects.filter(enabled=True, integration_context="Device")

def getEnabledUserIntegrations():
	return Integration.objects.filter(enabled=True, integration_context="User")

def _compliance_settings_to_dict(settings):
	"""Build {integration_type: value} from a DeviceComplianceSettings instance. Used by complianceSettings and masterList bulk load."""
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

def complianceSettings(os_platform):
	try:
		settings = DeviceComplianceSettings.objects.get(os_platform=os_platform)
		return _compliance_settings_to_dict(settings)
	except DeviceComplianceSettings.DoesNotExist:
		return {}

def _model_to_display_dict(instance):
	"""Convert a model instance to a dict with camelCase keys turned into 'Title Case' for display. Returns {} if instance is None.
	Datetime/date values are converted to ISO strings to avoid OverflowError in Django's localtime when rendering
	edge-case values (e.g. year 1, year 9999) from APIs like Microsoft Intune."""
	if instance is None:
		return {}
	d = model_to_dict(instance)
	result = {}
	for k, v in d.items():
		key = re.sub(r'([a-z])([A-Z])', r'\1 \2', k).title()
		if isinstance(v, (datetime, date)):
			try:
				result[key] = v.isoformat()
			except (OverflowError, ValueError):
				result[key] = str(v)
		else:
			result[key] = v
	return result

# (integration_type, related_name on Device, filter field matching device.hostname, context key)
INTEGRATION_DEVICE_FETCH = (
	('CrowdStrike Falcon', 'integrationCrowdStrikeFalcon', 'hostname', 'crowdstrike_device'),
	('Microsoft Defender for Endpoint', 'integrationMicrosoftDefenderForEndpoint', 'computerDnsName', 'defender_device'),
	('Microsoft Entra ID', 'integrationMicrosoftEntraID', 'displayName', 'entra_device'),
	('Microsoft Intune', 'integrationIntune', 'deviceName', 'intune_device'),
	('Sophos Central', 'integrationSophos', 'hostname', 'sophos_device'),
	('Tailscale', 'integrationTailscale', 'hostname', 'tailscale_device'),
)

############################################################################################

# Mapping for short integration names
integration_short_map = dict(zip(integration_names, integration_names_short))
user_integration_short_map = dict(zip(user_integration_names, user_integration_names_short))

@login_required
def add_persona_group(request):
    """Add a new persona group"""
    if request.method == 'POST':
        try:
            persona_id = request.POST.get('persona_id', '').strip()
            group_name = request.POST.get('group_name', '').strip()
            object_id = request.POST.get('object_id', '').strip()
            current_tab = request.POST.get('current_tab', 'persona-groups')
            
            if not persona_id:
                messages.error(request, 'Persona selection is required.')
            elif not group_name:
                messages.error(request, 'Group name is required.')
            else:
                try:
                    persona = Persona.objects.get(id=persona_id)
                except Persona.DoesNotExist:
                    messages.error(request, 'Selected persona does not exist.')
                    return redirect(reverse('general-settings') + f'#{current_tab}')
                
                PersonaGroup.objects.create(
                    persona=persona,
                    group_name=group_name,
                    object_id=object_id if object_id else None
                )
                messages.success(request, f'Persona group "{group_name}" added successfully.')
        except Exception as e:
            messages.error(request, f'Error adding persona group: {str(e)}')
    
    # Preserve the tab in the redirect
    current_tab = request.POST.get('current_tab', 'persona-groups')
    return redirect(reverse('general-settings') + f'#{current_tab}')

@login_required
def delete_persona_group(request, id):
    """Delete a persona group"""
    try:
        persona_group = PersonaGroup.objects.get(id=id)
        group_name = persona_group.group_name
        persona_group.delete()
        messages.success(request, f'Persona group "{group_name}" deleted successfully.')
    except PersonaGroup.DoesNotExist:
        messages.error(request, 'Persona group not found.')
    except Exception as e:
        messages.error(request, f'Error deleting persona group: {str(e)}')
    
    # Preserve the tab in the redirect - check GET parameter or default
    current_tab = request.GET.get('tab', 'persona-groups')
    return redirect(reverse('general-settings') + f'#{current_tab}')

############################################################################################

############################################################################################

def _calculate_auth_method_counts(users_queryset):
	"""Helper function to calculate authentication method counts for a user queryset."""
	# Define reusable Q filters for phishing-resistant methods
	Q_PASSKEY = Q(passKeyDeviceBound_authentication_method=True) | Q(passKeyDeviceBoundAuthenticator_authentication_method=True)
	Q_WHFB = Q(windowsHelloforBusiness_authentication_method=True)
	Q_PHISHING_RESISTANT = Q_PASSKEY | Q_WHFB
	Q_AUTHENTICATOR = Q(microsoftAuthenticatorPasswordless_authentication_method=True) | Q(microsoftAuthenticatorPush_authentication_method=True)
	Q_PHONE = Q(mobilePhone_authentication_method=True)
	Q_PHISHABLE = Q_PHONE | Q_AUTHENTICATOR
	
	total_users = users_queryset.count()
	
	# Phishing Resistant users (have passkey OR WHfB, regardless of other methods)
	# Priority: Passkey > WHfB (if user has both, count as Passkey)
	count_passkey_users = users_queryset.filter(Q_PASSKEY).count()
	count_whfb_users = users_queryset.filter(Q_WHFB).count()
	count_phishing_resistant_users = users_queryset.filter(Q_PHISHING_RESISTANT).count()
	
	# Phishable users (have phone OR authenticator, but NOT phishing resistant)
	# Priority: Phone > Authenticator (if user has both, count as Phone)
	count_phone_users = users_queryset.filter(Q_PHONE).exclude(Q_PHISHING_RESISTANT).count()
	count_authenticator_users = users_queryset.filter(Q_AUTHENTICATOR).exclude(Q_PHISHING_RESISTANT).count()
	count_phishable_users = users_queryset.filter(Q_PHISHABLE).exclude(Q_PHISHING_RESISTANT).count()
	
	# Single Factor users (none of the above methods)
	# Calculate as: total - phishing_resistant - phishable to ensure all users are accounted for
	count_single_factor_users = max(0, total_users - count_phishing_resistant_users - count_phishable_users)
	
	return {
		'total_users': total_users,
		'passkey_users': count_passkey_users,
		'whfb_users': count_whfb_users,
		'phishing_resistant_users': count_phishing_resistant_users,
		'phone_users': count_phone_users,
		'authenticator_users': count_authenticator_users,
		'phishable_users': count_phishable_users,
		'single_factor_users': count_single_factor_users,
	}

@login_required
def index(request):
	access_token = None
	try:
		# Cache the Integration object to avoid 3 separate database queries
		integration = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User")
		
		# Validate integration fields are not None
		if not integration.client_id or not integration.client_secret or not integration.tenant_id:
			raise ValueError("Integration credentials are missing")
		
		# Pass scope as a list (MSAL requires a list, not a string)
		access_token = getMicrosoftGraphAccessToken(integration.client_id, integration.client_secret, integration.tenant_id, ["https://graph.microsoft.com/.default"])
		# Check if access_token is an error dictionary
		if isinstance(access_token, dict) and 'error' in access_token:
			raise Exception(f"Failed to get access token: {access_token['error']}")

		guests = getMicrosoftEntraIDGuests(access_token)
		groups = getMicrosoftEntraIDGroups(access_token)
		apps = getMicrosoftEntraIDApps(access_token)
		devices = Device.objects.count()
		managed = Device.objects.filter(integrationMicrosoftEntraID__isManaged=True).count()
	except Exception as e:
		logger.error("Error in index view: %s", e)
		guests, groups, apps, devices, managed = 0, 0, 0, 0, 0

	# Calculate authentication method counts for privileged users (sk1)
	sk1_privileged_users = UserData.objects.filter(isAdmin=True)
	sk1_counts = _calculate_auth_method_counts(sk1_privileged_users)

	# Calculate authentication method counts for all users (sk2)
	sk2_users = UserData.objects.all()
	sk2_counts = _calculate_auth_method_counts(sk2_users)

	# Get tenant details
	tenant_id = tenant_name = tenant_domain = None
	try:
		if access_token:
			tenant_details = getMicrosoftEntraTenantDetails(access_token)
			if tenant_details and tenant_details.get('value') and len(tenant_details['value']) > 0:
				organization = tenant_details['value'][0]
				tenant_id = organization.get('id')
				tenant_name = organization.get('displayName')
				# Extract the default domain from verifiedDomains array using next() for efficiency
				verified_domains = organization.get('verifiedDomains', [])
				tenant_domain = next((domain.get('name') for domain in verified_domains if domain.get('isDefault', False)), None)
	except Exception:
		pass
	
	# Cache user count to avoid duplicate query
	count_users = UserData.objects.count()
	
	context = {
		'page': 'dashboard',
		'notifications': Notification.objects.order_by('-created_at')[:10],
		'count_users': count_users,
		'count_guests': guests,
		'count_groups': groups,
		'count_apps': apps,
		'count_devices': devices,
		'count_managed': managed,

		'sk1_count_privileged_users': sk1_counts['total_users'],
		'sk1_count_privileged_single_factor_users': sk1_counts['single_factor_users'],
		'sk1_count_privileged_phone_users': sk1_counts['phone_users'],
		'sk1_count_privileged_authenticator_users': sk1_counts['authenticator_users'],
		'sk1_count_privileged_phishable_users': sk1_counts['phishable_users'],
		'sk1_count_privileged_passkey_users': sk1_counts['passkey_users'],
		'sk1_count_privileged_whfb_users': sk1_counts['whfb_users'],
		'sk1_count_privileged_phishing_resistant_users': sk1_counts['phishing_resistant_users'],

		'sk2_count_users': sk2_counts['total_users'],
		'sk2_count_single_factor_users': sk2_counts['single_factor_users'],
		'sk2_count_phone_users': sk2_counts['phone_users'],
		'sk2_count_authenticator_users': sk2_counts['authenticator_users'],
		'sk2_count_phishable_users': sk2_counts['phishable_users'],
		'sk2_count_passkey_users': sk2_counts['passkey_users'],
		'sk2_count_whfb_users': sk2_counts['whfb_users'],
		'sk2_count_phishing_resistant_users': sk2_counts['phishing_resistant_users'],

		'tenant_id': tenant_id,
		'tenant_name': tenant_name,
		'tenant_domain': tenant_domain,

		# CA+MFA sign-in analysis (from last sync)
		'signin_summary': SignInSummary.objects.filter(id=1).first(),

		# CA+MFA sign-in analysis (from last sync)
		# Integration coverage for device compliance Sankey
		'device_compliance_compliant': Device.objects.filter(compliant=True).count(),
		'device_compliance_noncompliant': Device.objects.filter(compliant=False).count(),
		'enabled_device_integrations': list(Integration.objects.filter(enabled=True, integration_context="Device").values_list('integration_type_short', flat=True)),
		'device_integration_counts': list(
			Device.objects.filter(integration__enabled=True, integration__integration_context="Device")
			.values('integration__integration_type_short')
			.annotate(count=Count('id'))
		),

		# Device summary for OS breakdown, endpoint type, compliance percentages
		'device_os_counts': {
			(item['osPlatform'] or 'Other').replace(' ', '_').replace('/', '_'): item['count']
			for item in Device.objects.values('osPlatform').annotate(count=Count('id'))
		},
		'device_total': Device.objects.count(),
		'device_desktop_count': Device.objects.filter(endpointType='Client').count(),
		'device_mobile_count': Device.objects.filter(endpointType='Mobile').count(),
		'device_server_count': Device.objects.filter(endpointType='Server').count(),
	}
	return render(request, 'main/index.html', context)

############################################################################################

@login_required
def indexDevice(request):
	# Fetch all enabled integrations in a single query
	enabled_integrations = getEnabledIntegrations()

	# Count of devices for each integration in a single annotated query
	integration_device_counts = [["Master List Endpoints", Device.objects.count()]]
	integration_counts = (
		Device.objects.filter(integration__enabled=True, integration__integration_context="Device")
		.values('integration__integration_type', 'integration__image_navbar_path')
		.annotate(count=Count('id'))
	)
	counts_by_type = {item['integration__integration_type']: item for item in integration_counts}
	for integration_name in integration_names:
		item = counts_by_type.get(integration_name)
		if item:
			integration_device_counts.append([integration_name, item['count'], item['integration__image_navbar_path']])

	# Count each os platform and endpoint type
	os_platform_counts = Device.objects.values('osPlatform').annotate(count=Count('osPlatform'))
	endpoint_type_counts = Device.objects.values('endpointType').annotate(count=Count('endpointType'))

	osPlatformData = [next((item['count'] for item in os_platform_counts if item['osPlatform'] == os_platform), 0) for os_platform in os_platforms]
	endpointTypeData = [next((item['count'] for item in endpoint_type_counts if item['endpointType'] == endpoint_type), 0) for endpoint_type in endpoint_types]

	count_all_true = Device.objects.filter(compliant=True).count()
	count_any_false = Device.objects.filter(compliant=False).count()
 
	context = {
		'page': 'device-dashboard',
		'enabled_integrations': enabled_integrations,
		'enabled_user_integrations': getEnabledIntegrations(),
		'notifications': Notification.objects.order_by('-created_at')[:10],
		'endpoint_device_counts': integration_device_counts,
		'osPlatformLabels': os_platforms,
		'osPlatformData': osPlatformData,
		'endpointTypeLabels': endpoint_types,
		'endpointTypeData': endpointTypeData,
		'compliantLabels': ['Compliant', 'Non-Compliant'],
		'compliantData': [count_all_true, count_any_false],
    }
	return render(request, 'main/index-device.html', context)

@login_required
def indexUser(request):
	# Scoped to cloud and hybrid (Entra ID-synced) users only — on-prem-only AD users excluded
	users = UserData.objects.filter(integration__integration_type='Microsoft Entra ID').distinct()
 
   # Aggregate counts for highest and lowest authentication strengths
	auth_strength_counts = UserData.objects.aggregate(
        count_phishing_resistant=Count('id', filter=Q(highest_authentication_strength='Phishing Resistant')),
        count_passwordless=Count('id', filter=Q(highest_authentication_strength='Passwordless')),
        count_mfa=Count('id', filter=Q(highest_authentication_strength='MFA')),
        count_deprecated=Count('id', filter=Q(highest_authentication_strength='Deprecated')),
        count_none=Count('id', filter=Q(highest_authentication_strength='None')),
        count_low_phishing_resistant=Count('id', filter=Q(lowest_authentication_strength='Phishing Resistant')),
        count_low_passwordless=Count('id', filter=Q(lowest_authentication_strength='Passwordless')),
        count_low_mfa=Count('id', filter=Q(lowest_authentication_strength='MFA')),
        count_low_deprecated=Count('id', filter=Q(lowest_authentication_strength='Deprecated')),
        count_low_none=Count('id', filter=Q(lowest_authentication_strength='None')),
    )
   
   # Count passwordless and non-passwordless users
	passwordless_capable_count = UserData.objects.filter(
        Q(highest_authentication_strength__in=['Passwordless', 'Phishing Resistant'])
    ).count()
	non_passwordless_capable_count = UserData.objects.exclude(
        highest_authentication_strength__in=['Passwordless', 'Phishing Resistant']
    ).count()
 
	# Fetch all personas in one query, then build the map
	persona_lookup = {p.id: p.persona_name for p in Persona.objects.all()}
	persona_counts = UserData.objects.values('persona').annotate(count=Count('id'))
	persona_map = {}
	for item in persona_counts:
		persona_id = item['persona']
		if persona_id and persona_id in persona_lookup:
			persona_map[persona_lookup[persona_id]] = item['count']
		else:
			persona_map['Unknown'] = persona_map.get('Unknown', 0) + item['count']
	
	# Add counts to persona objects
	personas = Persona.objects.all()
	for persona in personas:
		persona.user_count = persona_map.get(persona.persona_name, 0)
 
	# Count duplicate and unknown personas
	count_duplicate_persona = UserData.objects.filter(persona__persona_name='DUPLICATE').count() or 0
	count_unknown_persona = UserData.objects.filter(persona__persona_name='Unknown').count() or 0
	persona_duplicate = Persona.objects.filter(persona_name='DUPLICATE').first()
	persona_unknown = Persona.objects.filter(persona_name='Unknown').first()
 
	context = {
		'page': 'user-dashboard',
		# 'enabled_integrations': getEnabledUserIntegrations(),
		'notifications': Notification.objects.order_by('-created_at')[:10],
		'count_duplicate_persona': count_duplicate_persona,
		'count_unknown_persona': count_unknown_persona,
		'persona_duplicate': persona_duplicate,
		'persona_unknown': persona_unknown,
        'auth_method_labels': ['Phishing Resistant', 'Passwordless', 'MFA', 'Deprecated', 'None'],
        'auth_method_data': [
            auth_strength_counts['count_phishing_resistant'],
            auth_strength_counts['count_passwordless'],
            auth_strength_counts['count_mfa'],
            auth_strength_counts['count_deprecated'],
            auth_strength_counts['count_none'],
        ],
        'auth_method_low_labels': ['Phishing Resistant', 'Passwordless', 'MFA', 'Deprecated', 'None'],
        'auth_method_low_data': [
            auth_strength_counts['count_low_phishing_resistant'],
            auth_strength_counts['count_low_passwordless'],
            auth_strength_counts['count_low_mfa'],
            auth_strength_counts['count_low_deprecated'],
            auth_strength_counts['count_low_none'],
        ],
        'count_passwordless_capable_labels': ['Passwordless', 'Non-Passwordless'],
        'count_passwordless_capable_data': [passwordless_capable_count, non_passwordless_capable_count],

		'personas': personas,
		'persona_groups': PersonaGroup.objects.all(),

		'count_total_users': users.count(),

		'auth_method_adoption_labels': ['Windows Hello for Business', 'Passkey Device', 'Passkey Authenticator', 'MS Authenticator Passwordless', 'MS Authenticator Push', 'Software OTP', 'Mobile Phone'],
		'auth_method_adoption_data': list(users.aggregate(
			whfb=Count('id', filter=Q(windowsHelloforBusiness_authentication_method=True)),
			passkey=Count('id', filter=Q(passKeyDeviceBound_authentication_method=True)),
			passkey_auth=Count('id', filter=Q(passKeyDeviceBoundAuthenticator_authentication_method=True)),
			ms_auth_pl=Count('id', filter=Q(microsoftAuthenticatorPasswordless_authentication_method=True)),
			ms_auth_push=Count('id', filter=Q(microsoftAuthenticatorPush_authentication_method=True)),
			sw_otp=Count('id', filter=Q(softwareOneTimePasscode_authentication_method=True)),
			mobile=Count('id', filter=Q(mobilePhone_authentication_method=True)),
		).values()),
    }
	return render(request, 'main/index-user.html', context)

############################################################################################

@login_required
def personaMetrics(request, persona_id):
	persona_obj = get_object_or_404(Persona, id=persona_id)
	persona_name = persona_obj.persona_name
	users = UserData.objects.filter(persona=persona_obj, integration__integration_type='Microsoft Entra ID').distinct()
   # Aggregate counts for highest and lowest authentication strengths
	auth_strength_counts = users.aggregate(
        count_phishing_resistant=Count('id', filter=Q(highest_authentication_strength='Phishing Resistant')),
        count_passwordless=Count('id', filter=Q(highest_authentication_strength='Passwordless')),
        count_mfa=Count('id', filter=Q(highest_authentication_strength='MFA')),
        count_deprecated=Count('id', filter=Q(highest_authentication_strength='Deprecated')),
        count_none=Count('id', filter=Q(highest_authentication_strength='None')),
        count_low_phishing_resistant=Count('id', filter=Q(lowest_authentication_strength='Phishing Resistant')),
        count_low_passwordless=Count('id', filter=Q(lowest_authentication_strength='Passwordless')),
        count_low_mfa=Count('id', filter=Q(lowest_authentication_strength='MFA')),
        count_low_deprecated=Count('id', filter=Q(lowest_authentication_strength='Deprecated')),
        count_low_none=Count('id', filter=Q(lowest_authentication_strength='None')),
    )

	passwordless_capable_count = users.filter(
        Q(highest_authentication_strength__in=['Passwordless', 'Phishing Resistant'])
    ).count()
	non_passwordless_capable_count = users.exclude(
        highest_authentication_strength__in=['Passwordless', 'Phishing Resistant']
    ).count()

	user_list = []
	for user_data in users:		
		user_list.append([user_data, user_data.passKeyDeviceBound_authentication_method, user_data.passKeyDeviceBoundAuthenticator_authentication_method, user_data.windowsHelloforBusiness_authentication_method, user_data.microsoftAuthenticatorPasswordless_authentication_method, user_data.microsoftAuthenticatorPush_authentication_method, user_data.softwareOneTimePasscode_authentication_method, user_data.temporaryAccessPass_authentication_method, user_data.mobilePhone_authentication_method, user_data.email_authentication_method, user_data.securityQuestion_authentication_method])
 
	context = {
		'page': 'user-dashboard',
		'enabled_integrations': getEnabledIntegrations(),
		'notifications': Notification.objects.order_by('-created_at')[:10],
		'persona': persona_obj,
		'persona_name': persona_name,
		'persona_count': users.count(),
		'percent_mfa': "{:.2f}".format(((auth_strength_counts['count_phishing_resistant'] + auth_strength_counts['count_passwordless'] + auth_strength_counts['count_mfa'] + auth_strength_counts['count_deprecated']) / users.count()) * 100 if users.count() > 0 else 0),
		'count_mfa': auth_strength_counts['count_phishing_resistant'] + auth_strength_counts['count_passwordless'] + auth_strength_counts['count_mfa'] + auth_strength_counts['count_deprecated'],
		'percent_phishing_resistant': "{:.2f}".format(((auth_strength_counts['count_phishing_resistant']) / users.count()) * 100 if users.count() > 0 else 0),
		'count_phishing_resistant': auth_strength_counts['count_phishing_resistant'],
		'percent_passwordless': "{:.2f}".format(((auth_strength_counts['count_phishing_resistant'] + auth_strength_counts['count_passwordless']) / users.count()) * 100 if users.count() > 0 else 0),
		'count_passwordless': (auth_strength_counts['count_phishing_resistant'] + auth_strength_counts['count_passwordless']),
		'auth_method_labels': ['Phishing Resistant', 'Passwordless', 'MFA', 'Deprecated', 'None'],
        'auth_method_data': [
            auth_strength_counts['count_phishing_resistant'],
            auth_strength_counts['count_passwordless'],
            auth_strength_counts['count_mfa'],
            auth_strength_counts['count_deprecated'],
            auth_strength_counts['count_none'],
        ],
        'auth_method_low_labels': ['Phishing Resistant', 'Passwordless', 'MFA', 'Deprecated', 'None'],
        'auth_method_low_data': [
            auth_strength_counts['count_low_phishing_resistant'],
            auth_strength_counts['count_low_passwordless'],
            auth_strength_counts['count_low_mfa'],
            auth_strength_counts['count_low_deprecated'],
            auth_strength_counts['count_low_none'],
        ],
		'auth_method_adoption_labels': ['Windows Hello for Business', 'Passkey Device', 'Passkey Authenticator', 'MS Authenticator Passwordless', 'MS Authenticator Push', 'Software OTP', 'Mobile Phone'],
		'auth_method_adoption_data': [
			users.filter(windowsHelloforBusiness_authentication_method=True).count(),
			users.filter(passKeyDeviceBound_authentication_method=True).count(),
			users.filter(passKeyDeviceBoundAuthenticator_authentication_method=True).count(),
			users.filter(microsoftAuthenticatorPasswordless_authentication_method=True).count(),
			users.filter(microsoftAuthenticatorPush_authentication_method=True).count(),
			users.filter(softwareOneTimePasscode_authentication_method=True).count(),
			users.filter(mobilePhone_authentication_method=True).count(),
		],
        'count_passwordless_capable_labels': ['Passwordless', 'Non-Passwordless'],
        'count_passwordless_capable_data': [passwordless_capable_count, non_passwordless_capable_count],

		'auth_strengths': ['None', 'MFA', 'Passwordless', 'Phishing Resistant', 'Deprecated'],
        'personas': list(Persona.objects.values_list('persona_name', flat=True).order_by('priority')),
		'user_list':user_list,
    }
	return render(request, 'main/persona-metrics.html', context)

############################################################################################

@login_required
def reports(request):
	from apps.authhandler.models import SSOIntegration

	compliance_total = Device.objects.count()
	compliance_compliant = Device.objects.filter(compliant=True).count()
	compliance_noncompliant = Device.objects.filter(compliant=False).count()
	compliance_percent = round(compliance_compliant / compliance_total * 100) if compliance_total > 0 else 0

	total_users = UserData.objects.count()
	mfa_enrolled = UserData.objects.exclude(highest_authentication_strength='None').exclude(highest_authentication_strength__isnull=True).count()
	mfa_percent = round((mfa_enrolled / total_users * 100) if total_users > 0 else 0)
	phishing_resistant_users = UserData.objects.filter(highest_authentication_strength='Phishing Resistant').count()
	users_no_mfa = UserData.objects.filter(highest_authentication_strength='None').count() + UserData.objects.filter(highest_authentication_strength__isnull=True).count()
	users_deprecated_auth = UserData.objects.filter(highest_authentication_strength='Deprecated').count()

	managed_devices = Device.objects.exclude(integration=None).count()
	active_integrations = Integration.objects.filter(enabled=True).count()
	sso_enabled = SSOIntegration.objects.filter(enabled=True).exists()

	controls = Control.objects.filter(enabled=True).select_related('framework').order_by('control_id')
	frameworks = ControlFramework.objects.all()

	# CISO aggregates
	controls_total = controls.count()
	controls_passing = controls.filter(status='passing').count()
	controls_warning = controls.filter(status='warning').count()
	controls_failing = controls.filter(status='failing').count()
	controls_not_measured = controls.filter(status__in=['not_measured', '']).count() + controls.filter(status__isnull=True).count()
	controls_pass_pct = round(controls_passing / controls_total * 100) if controls_total > 0 else 0

	from itertools import groupby as _groupby

	_CATEGORY_LABELS = {
		'AAL': 'Authenticator Assurance Level',
		'ALM': 'Authenticator Lifecycle Management',
		'PHR': 'Phishing-Resistant Authentication',
		'PWD': 'Password Controls',
	}

	framework_stats = []
	controls_grouped = []
	for fw in frameworks.order_by('display_order', 'name'):
		fw_controls_qs = controls.filter(framework=fw)
		fw_total = fw_controls_qs.count()
		if fw_total == 0:
			continue
		fw_passing = fw_controls_qs.filter(status='passing').count()
		fw_warning = fw_controls_qs.filter(status='warning').count()
		fw_failing = fw_controls_qs.filter(status='failing').count()
		fw_not_measured = fw_total - fw_passing - fw_warning - fw_failing
		fw_pass_pct = round(fw_passing / fw_total * 100) if fw_total > 0 else 0
		fw_fail_pct = round(fw_failing / fw_total * 100) if fw_total > 0 else 0
		fw_nm_pct = round(fw_not_measured / fw_total * 100) if fw_total > 0 else 0

		framework_stats.append({
			'framework': fw,
			'total': fw_total,
			'passing': fw_passing,
			'warning': fw_warning,
			'failing': fw_failing,
			'not_measured': fw_not_measured,
			'pass_pct': fw_pass_pct,
			'fail_pct': fw_fail_pct,
			'nm_pct': fw_nm_pct,
		})

		fw_controls_list = list(fw_controls_qs.order_by('control_id'))
		categories = []
		for cat_key, cat_iter in _groupby(fw_controls_list, key=lambda c: c.control_id.split('-')[0] if '-' in c.control_id else 'OTHER'):
			cat_list = list(cat_iter)
			cat_passing = sum(1 for c in cat_list if c.status == 'passing')
			cat_warning = sum(1 for c in cat_list if c.status == 'warning')
			cat_failing = sum(1 for c in cat_list if c.status == 'failing')
			categories.append({
				'name': cat_key,
				'label': _CATEGORY_LABELS.get(cat_key, cat_key),
				'total': len(cat_list),
				'passing': cat_passing,
				'warning': cat_warning,
				'failing': cat_failing,
				'not_measured': len(cat_list) - cat_passing - cat_warning - cat_failing,
				'controls': cat_list,
			})

		controls_grouped.append({
			'framework': fw,
			'total': fw_total,
			'passing': fw_passing,
			'warning': fw_warning,
			'failing': fw_failing,
			'not_measured': fw_not_measured,
			'pass_pct': fw_pass_pct,
			'categories': categories,
		})

	failing_controls = controls.filter(status='failing').order_by('framework__display_order', 'framework__name', 'control_id')

	context = {
		'page': 'reports',
		'compliance_total': compliance_total,
		'compliance_compliant': compliance_compliant,
		'compliance_noncompliant': compliance_noncompliant,
		'compliance_percent': compliance_percent,
		'total_users': total_users,
		'mfa_enrolled': mfa_enrolled,
		'mfa_percent': mfa_percent,
		'phishing_resistant_users': phishing_resistant_users,
		'users_no_mfa': users_no_mfa,
		'users_deprecated_auth': users_deprecated_auth,
		'managed_devices': managed_devices,
		'active_integrations': active_integrations,
		'sso_enabled': sso_enabled,
		'notifications': Notification.objects.all().order_by('-created_at')[:10],
		'controls': controls,
		'frameworks': frameworks,
		'controls_total': controls_total,
		'controls_passing': controls_passing,
		'controls_warning': controls_warning,
		'controls_failing': controls_failing,
		'controls_not_measured': controls_not_measured,
		'controls_pass_pct': controls_pass_pct,
		'framework_stats': framework_stats,
		'controls_grouped': controls_grouped,
		'failing_controls': failing_controls,
	}
	return render(request, 'main/reports.html', context)

############################################################################################

@login_required
def evaluate_controls_view(request):
	"""Run all control evaluators and redirect back to reports."""
	if not request.user.is_superuser:
		return redirect('reports')

	from apps.main.controls import evaluators

	controls = Control.objects.filter(
		enabled=True,
		use_manual=False,
		evaluator__isnull=False,
	).exclude(evaluator='')

	import re as _re

	def _extract_pct(val):
		"""Return float percentage from strings like '85%' or '142/150 (85%)', else None."""
		if not val:
			return None
		m = _re.search(r'(\d+(?:\.\d+)?)\s*%', str(val))
		return float(m.group(1)) if m else None

	evaluated = 0
	for ctrl in controls:
		func = getattr(evaluators, ctrl.evaluator, None)
		if func is None:
			continue
		try:
			current_value, status = func()
			# If evaluator says failing, check whether we meet the configured target.
			if status == 'failing' and ctrl.target:
				target_pct = _extract_pct(ctrl.target)
				current_pct = _extract_pct(current_value)
				if target_pct is not None and current_pct is not None and current_pct >= target_pct:
					status = 'passing'
			ctrl.current_value = current_value
			ctrl.status = status
			ctrl.save(update_fields=['current_value', 'status', 'updated_at'])
			evaluated += 1
		except Exception:
			ctrl.current_value = 'Error'
			ctrl.status = 'not_measured'
			ctrl.save(update_fields=['current_value', 'status', 'updated_at'])

	messages.success(request, f'{evaluated} control(s) evaluated.')
	return redirect(reverse('reports') + '#controls')


@login_required
def seed_controls_view(request):
	"""Run seed_controls logic and redirect back to reports."""
	if not request.user.is_superuser:
		return redirect('reports')

	from django.core.management import call_command
	from django.contrib import messages
	import io

	out = io.StringIO()
	try:
		call_command('seed_controls', stdout=out)
		output = out.getvalue()
		messages.success(request, f'Controls seeded successfully. {output.strip().split(chr(10))[-1]}')
	except Exception as e:
		messages.error(request, f'Seed failed: {str(e)}')

	return redirect(reverse('reports') + '#controls')


@login_required
def update_control_view(request, control_id):
	"""AJAX endpoint — update a control's target and/or manual override fields."""
	import json as _json
	if not request.user.is_superuser:
		return JsonResponse({'error': 'Forbidden'}, status=403)
	if request.method != 'POST':
		return JsonResponse({'error': 'POST required'}, status=405)

	ctrl = Control.objects.filter(control_id=control_id).first()
	if not ctrl:
		return JsonResponse({'error': 'Not found'}, status=404)

	try:
		data = _json.loads(request.body)
	except Exception:
		return JsonResponse({'error': 'Invalid JSON'}, status=400)

	update_fields = ['updated_at']

	if 'target' in data:
		ctrl.target = (data['target'] or '').strip()[:200]
		update_fields.append('target')

	if 'use_manual' in data:
		ctrl.use_manual = bool(data['use_manual'])
		update_fields.append('use_manual')

	if 'manual_status' in data:
		val = data['manual_status']
		ctrl.manual_status = val if val in ('passing', 'failing', 'not_measured') else None
		update_fields.append('manual_status')

	if 'manual_value' in data:
		ctrl.manual_value = (data['manual_value'] or '').strip()[:200] or None
		update_fields.append('manual_value')

	if 'manual_notes' in data:
		ctrl.manual_notes = (data['manual_notes'] or '').strip() or None
		update_fields.append('manual_notes')

	# When manual override is active, apply manual values to live status/current_value
	if ctrl.use_manual:
		ctrl.status = ctrl.manual_status or 'not_measured'
		ctrl.current_value = ctrl.manual_value or '-'
		update_fields += ['status', 'current_value']
	elif 'target' in data and ctrl.current_value and ctrl.current_value not in ('Error', '-', ''):
		# Recalculate status immediately when target changes on an auto-evaluated control.
		import re as _re2
		def _pct(v):
			m = _re2.search(r'(\d+(?:\.\d+)?)\s*%', str(v))
			return float(m.group(1)) if m else None
		target_pct = _pct(ctrl.target)
		current_pct = _pct(ctrl.current_value)
		if target_pct is not None and current_pct is not None:
			ctrl.status = 'passing' if current_pct >= target_pct else 'failing'
			update_fields.append('status')

	ctrl.save(update_fields=list(set(update_fields)))

	return JsonResponse({
		'ok': True,
		'control_id': ctrl.control_id,
		'target': ctrl.target,
		'use_manual': ctrl.use_manual,
		'manual_status': ctrl.manual_status,
		'manual_value': ctrl.manual_value,
		'manual_notes': ctrl.manual_notes,
		'status': ctrl.status,
		'current_value': ctrl.current_value,
	})

############################################################################################

_DATA_SOURCE_LOGOS = {
	'Microsoft Entra ID':                'main/img/integration_images/webp/microsoft_entra_id_logo.webp',
	'Microsoft Intune':                  'main/img/integration_images/webp/microsoft_intune_logo.webp',
	'Microsoft Defender for Endpoint':   'main/img/integration_images/webp/microsoft_defender_for_endpoint_logo.webp',
	'CrowdStrike Falcon':                'main/img/integration_images/webp/crowdstrike_falcon_logo.webp',
	'Cloudflare Zero Trust':             'main/img/integration_images/webp/cloudflare_zero_trust_logo.webp',
	'Sophos Central':                    'main/img/integration_images/webp/sophos_central_logo.webp',
	'Qualys':                            'main/img/integration_images/webp/qualys_logo.webp',
	'Tailscale':                         'main/img/integration_images/webp/tailscale_logo.webp',
	'Active Directory':                  'main/img/integration_images/webp/active_directory_logo.webp',
}


@login_required
def control_detail(request, control_id):
	"""Show detailed view of a single control with underlying data."""
	from apps.main.controls import evaluators

	ctrl = Control.objects.select_related('framework').filter(control_id=control_id).first()
	if not ctrl:
		from django.http import Http404
		raise Http404(f'Control {control_id} not found')

	# Get detail data if evaluator exists
	detail_data = None
	detail_func_name = f'{ctrl.evaluator}_detail' if ctrl.evaluator else None
	if detail_func_name:
		detail_func = getattr(evaluators, detail_func_name, None)
		if detail_func:
			try:
				detail_data = detail_func()
			except Exception as e:
				detail_data = {'error': str(e)}

	# Strip private queryset keys — only metadata goes to template
	if detail_data:
		detail_data = {k: v for k, v in detail_data.items() if not k.startswith('_')}

	# Build data source tiles (name + logo path)
	data_source_tiles = [
		{'name': name, 'logo': _DATA_SOURCE_LOGOS.get(name)}
		for name in (ctrl.data_sources or [])
	]

	context = {
		'page': 'reports',
		'ctrl': ctrl,
		'detail': detail_data,
		'data_source_tiles': data_source_tiles,
		'notifications': Notification.objects.all().order_by('-created_at')[:10],
	}
	return render(request, 'main/control-detail.html', context)

############################################################################################

@login_required
def control_findings_ajax(request, control_id):
    """Return paginated user rows for a control's findings table as JSON."""
    from django.http import JsonResponse
    from apps.main.controls import evaluators

    ctrl = Control.objects.filter(control_id=control_id).first()
    if not ctrl:
        return JsonResponse({'error': 'Not found'}, status=404)

    which = request.GET.get('type', 'failing')
    try:
        page = max(0, int(request.GET.get('page', 0)))
        size = int(request.GET.get('size', 10))
        if size not in (10, 25, 50, 100, 250, 500):
            size = 10
    except (ValueError, TypeError):
        page, size = 0, 10

    detail_func_name = f'{ctrl.evaluator}_detail' if ctrl.evaluator else None
    if not detail_func_name:
        return JsonResponse({'rows': [], 'total': 0, 'page': 0, 'size': size, 'pages': 0})

    detail_func = getattr(evaluators, detail_func_name, None)
    if not detail_func:
        return JsonResponse({'rows': [], 'total': 0, 'page': 0, 'size': size, 'pages': 0})

    try:
        detail_data = detail_func()
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    if which == 'failing':
        qs = detail_data.get('_fail_qs')
        fields = detail_data.get('_fail_fields', ())
        total = detail_data.get('failing_count', 0)
    else:
        qs = detail_data.get('_pass_qs')
        fields = detail_data.get('_pass_fields', ())
        total = detail_data.get('passing_count', 0)

    if qs is None or not fields:
        return JsonResponse({'rows': [], 'total': total, 'page': page, 'size': size, 'pages': 0,
                             'has_persona': False, 'has_admin': False})

    offset = page * size
    rows = list(qs.values(*fields)[offset:offset + size])

    # Normalize values for JSON serialisation
    for row in rows:
        for k, v in list(row.items()):
            if v is None:
                row[k] = None

    pages = (total + size - 1) // size if size > 0 else 0
    return JsonResponse({
        'rows': rows,
        'total': total,
        'page': page,
        'size': size,
        'pages': pages,
        'has_persona': 'persona__persona_name' in fields,
        'has_admin': 'isAdmin' in fields,
    })

############################################################################################

@login_required
def control_export_noncompliant(request, control_id):
    """Export non-compliant records for a control as XLSX."""
    import openpyxl
    from django.http import HttpResponse
    from apps.main.controls import evaluators

    ctrl = Control.objects.filter(control_id=control_id).first()
    if not ctrl:
        from django.http import Http404
        raise Http404(f'Control {control_id} not found')

    detail_data = None
    detail_func_name = f'{ctrl.evaluator}_detail' if ctrl.evaluator else None
    if detail_func_name:
        detail_func = getattr(evaluators, detail_func_name, None)
        if detail_func:
            detail_data = detail_func()

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = f'{ctrl.control_id} Non-Compliant'

    ws.append([f'Control: {ctrl.control_id} — {ctrl.domain}'])
    ws.append([f'Status: {ctrl.get_status_display()}'])
    ws.append([f'Target: {ctrl.target}', f'Current: {ctrl.current_value or "-"}'])
    ws.append([])

    fail_qs = detail_data.get('_fail_qs') if detail_data else None
    fail_fields = detail_data.get('_fail_fields', ()) if detail_data else ()
    users = list(fail_qs.values(*fail_fields)) if fail_qs is not None and fail_fields else None

    if users:
            # Build headers from first record's keys
            headers = []
            header_map = {
                'upn': 'UPN',
                'given_name': 'First Name',
                'surname': 'Last Name',
                'highest_authentication_strength': 'Highest Auth Strength',
                'isAdmin': 'Admin',
                'persona__persona_name': 'Persona',
                'passKeyDeviceBound_authentication_method': 'FIDO2 Key',
                'passKeyDeviceBoundAuthenticator_authentication_method': 'Passkey (Sync)',
                'windowsHelloforBusiness_authentication_method': 'WHfB',
                'microsoftAuthenticatorPasswordless_authentication_method': 'Auth Passwordless',
                'microsoftAuthenticatorPush_authentication_method': 'Auth Push',
                'softwareOneTimePasscode_authentication_method': 'Software OTP',
                'mobilePhone_authentication_method': 'Mobile Phone',
                'temporaryAccessPass_authentication_method': 'TAP',
                'email_authentication_method': 'Email',
            }
            keys = list(users[0].keys())
            for key in keys:
                headers.append(header_map.get(key, key))

            ws.append(headers)

            # Style header row
            from openpyxl.styles import Font, PatternFill
            header_font = Font(bold=True, color='FFFFFF')
            header_fill = PatternFill(start_color='CC3333', end_color='CC3333', fill_type='solid')
            for cell in ws[ws.max_row]:
                cell.font = header_font
                cell.fill = header_fill

            # Add data rows
            for user in users:
                row = []
                for key in keys:
                    val = user.get(key)
                    if isinstance(val, bool):
                        val = 'Yes' if val else 'No'
                    elif val is None:
                        val = '-'
                    row.append(val)
                ws.append(row)

            # Auto-fit column widths
            for col in ws.columns:
                max_length = 0
                col_letter = col[0].column_letter
                for cell in col:
                    if cell.value:
                        max_length = max(max_length, len(str(cell.value)))
                ws.column_dimensions[col_letter].width = min(max_length + 2, 40)

    elif detail_data and detail_data.get('policies'):  # policy-based controls (e.g. aal_12)
        # AAL-05: export policies instead
        ws.append(['Policy Name', 'State', 'Sign-in Frequency', 'Frequency Type', 'Days', 'Persistent Browser', 'Has Session Control'])
        from openpyxl.styles import Font, PatternFill
        header_font = Font(bold=True, color='FFFFFF')
        header_fill = PatternFill(start_color='CC3333', end_color='CC3333', fill_type='solid')
        for cell in ws[ws.max_row]:
            cell.font = header_font
            cell.fill = header_fill

        for p in detail_data['policies']:
            ws.append([
                p.get('display_name', ''),
                p.get('state', ''),
                p.get('sign_in_frequency_value', '-'),
                p.get('sign_in_frequency_type', '-'),
                p.get('sign_in_frequency_days', '-'),
                p.get('persistent_browser_mode', '-'),
                'Yes' if p.get('has_session_control') else 'No',
            ])

        for col in ws.columns:
            max_length = 0
            col_letter = col[0].column_letter
            for cell in col:
                if cell.value:
                    max_length = max(max_length, len(str(cell.value)))
            ws.column_dimensions[col_letter].width = min(max_length + 2, 50)
    else:
        ws.append(['No non-compliant data available for this control.'])

    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    from django.utils import timezone
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    response['Content-Disposition'] = f'attachment; filename="{ctrl.control_id}_noncompliant_{timestamp}.xlsx"'
    wb.save(response)
    return response

############################################################################################

@login_required
def generalSettings(request):
	from .utils import ComplianceSettingsManager
	from django.contrib.auth.models import User
	from apps.authhandler.models import SSOIntegration

	# Get compliance settings (used in template for compliance forms)
	compliance_settings = ComplianceSettingsManager.get_all_compliance_settings()

	# Get identity settings data (only for superusers)
	users = None
	integrationStatuses = []
	if request.user.is_superuser:
		users = User.objects.only(
			'id', 'first_name', 'last_name', 'email', 'is_superuser', 'is_active', 'last_login'
		).all()
		try:
			integration = SSOIntegration.objects.get(integration_type='Microsoft Entra ID')
			has_domain = bool(integration.tenant_domain)
			integrationStatuses.append([
				integration.integration_type, integration.image_integration_path,
				integration.enabled, has_domain, integration.id, integration.client_id,
				integration.tenant_id, integration.tenant_domain, integration.last_synced_at,
			])
		except SSOIntegration.DoesNotExist:
			pass

	context = {
		'page': "general-settings",
		'enabled_integrations': getEnabledIntegrations(),
		'notifications': Notification.objects.order_by('-created_at')[:10],
		'devicecomps': compliance_settings,
		'persona_groups': PersonaGroup.objects.all().order_by('group_name'),
		'personas': Persona.objects.prefetch_related('tags').order_by('priority', 'persona_name'),
		'persona_tags': PersonaTag.objects.all(),
		'users': users,
		'integrationStatuses': integrationStatuses,
		'is_superuser': request.user.is_superuser,
	}

	return render(request, 'main/general-settings.html', context)

@login_required
def update_compliance(request, id):
	if request.method == 'POST':
		from .utils import ComplianceSettingsManager
		
		# Parse the form data to extract integration settings
		integration_settings = {}
		integration_mapping = {
			'Cloudflare Zero Trust': 'Cloudflare Zero Trust',
			'CrowdStrike Falcon': 'CrowdStrike Falcon',
			'Microsoft Defender for Endpoint': 'Microsoft Defender for Endpoint',
			'Microsoft Entra ID': 'Microsoft Entra ID',
			'Microsoft Intune': 'Microsoft Intune',
			'Sophos Central': 'Sophos Central',
			'Qualys': 'Qualys',
			'Tailscale': 'Tailscale'
		}
		
		for integration_name, field_name in integration_mapping.items():
			# Check if the integration is enabled (checkbox was checked)
			is_enabled = request.POST.get(field_name) == 'on'
			integration_settings[integration_name] = is_enabled
		
		# Update the compliance settings using the manager
		success = ComplianceSettingsManager.update_compliance_settings(id, integration_settings)
		
		if success:
			messages.success(request, 'Compliance settings updated successfully!')
		else:
			messages.error(request, 'Failed to update compliance settings.')
	
	return redirect('general-settings')

############################################################################################

@login_required
def deviceData(request, id):
	prefetch_relations = [
		'integrationCloudflareZeroTrust', 'integrationCrowdStrikeFalcon', 'integrationMicrosoftDefenderForEndpoint',
		'integrationMicrosoftEntraID', 'integrationIntune', 'integrationSophos', 'integrationQualys', 'integrationTailscale',
	]
	device = get_object_or_404(Device.objects.prefetch_related(*prefetch_relations), id=id)

	integrations = device.integration.all()
	integration_types = [i.integration_type for i in integrations]

	integration_device_data = {ctx_key: None for _, __, ___, ctx_key in INTEGRATION_DEVICE_FETCH}
	for itype, related_name, filter_field, ctx_key in INTEGRATION_DEVICE_FETCH:
		if itype not in integration_types:
			continue
		qs = getattr(device, related_name)
		rec = qs.filter(**{filter_field: device.hostname}).first()
		integration_device_data[ctx_key] = _model_to_display_dict(rec)

	context = {
		'page': 'device-data',
		'enabled_integrations': getEnabledIntegrations(),
		'enabled_user_integrations': getEnabledUserIntegrations(),
		'notifications': Notification.objects.order_by('-created_at')[:10],
		'device': device,
		'ints': integrations,
		**integration_device_data,
	}
	return render(request, 'main/device-data.html', context)

############################################################################################

@login_required
def masterList(request):
	"""Render the master list shell — data loaded via AJAX from device_master_list_api."""
	context = {
		'page': "master-list",
		'enabled_integrations': list(getEnabledIntegrations()),
		'enabled_user_integrations': getEnabledUserIntegrations(),
		'notifications': Notification.objects.order_by('-created_at')[:10],
		'os_platforms': os_platforms,
		'endpoint_types': endpoint_types,
	}
	return render(request, 'main/master-list.html', context)

@login_required
def device_master_list_api(request):
	"""DataTables server-side API for device master list."""
	draw = int(request.GET.get('draw', 1))
	start = int(request.GET.get('start', 0))
	length = int(request.GET.get('length', 25))
	search_value = request.GET.get('search[value]', '')

	# Filters
	os_platform_filter = request.GET.getlist('os_platform[]')
	endpoint_type_filter = request.GET.getlist('endpoint_type[]')
	compliance_filter = request.GET.get('compliance', '')

	# Sorting
	order_column = request.GET.get('order[0][column]', '0')
	order_dir = request.GET.get('order[0][dir]', 'asc')
	sort_columns = ['hostname', 'compliant', 'osPlatform', 'endpointType']
	if order_column.isdigit() and int(order_column) < len(sort_columns):
		sort_field = sort_columns[int(order_column)]
		if order_dir == 'desc':
			sort_field = f'-{sort_field}'
	else:
		sort_field = 'hostname'

	# Base query with prefetch
	devices = Device.objects.prefetch_related(
		Prefetch('integration', queryset=Integration.objects.filter(enabled=True, integration_context="Device").only('id', 'integration_type'))
	).order_by(sort_field)

	# Apply filters
	if os_platform_filter:
		devices = devices.filter(osPlatform__in=os_platform_filter)
	if endpoint_type_filter:
		devices = devices.filter(endpointType__in=endpoint_type_filter)
	if compliance_filter:
		if compliance_filter == 'True':
			devices = devices.filter(compliant=True)
		elif compliance_filter == 'False':
			devices = devices.filter(compliant=False)
	if search_value:
		devices = devices.filter(hostname__icontains=search_value)

	total = Device.objects.count()
	filtered = devices.count()

	# Paginate
	paginator = Paginator(devices, length)
	page = paginator.get_page((start // length) + 1)

	# Load compliance settings + enabled integrations once
	compliance_by_platform = {
		s.os_platform: _compliance_settings_to_dict(s)
		for s in DeviceComplianceSettings.objects.all()
	}
	enabled_integrations = list(getEnabledIntegrations())

	# Build response
	data = []
	for device in page.object_list:
		compliance_settings_dict = compliance_by_platform.get(device.osPlatform, {})
		integration_ids = {i.id for i in device.integration.all()}

		row = [
			f'<a href="/device/{device.id}">{device.hostname}</a>',
			'&#9989;' if device.compliant else '&#10060;',
			device.osPlatform or '',
			device.endpointType or '',
		]

		for integration in enabled_integrations:
			cs = compliance_settings_dict.get(integration.integration_type)
			if cs is False or cs is None:
				row.append('&#x29B8;')
			else:
				row.append('&#9989;' if integration.id in integration_ids else '&#10060;')

		data.append(row)

	return JsonResponse({
		'draw': draw,
		'recordsTotal': total,
		'recordsFiltered': filtered,
		'data': data,
	})

############################################################################################

@login_required
def userMasterList(request):
	# Scoped to cloud and hybrid (Entra ID-synced) users only — on-prem-only AD users excluded
	user_data_list = UserData.objects.filter(integration__integration_type='Microsoft Entra ID').distinct()
	user_list = []
	for user_data in user_data_list:		
		user_list.append([user_data, user_data.passKeyDeviceBound_authentication_method, user_data.passKeyDeviceBoundAuthenticator_authentication_method, user_data.windowsHelloforBusiness_authentication_method, user_data.microsoftAuthenticatorPasswordless_authentication_method, user_data.microsoftAuthenticatorPush_authentication_method, user_data.softwareOneTimePasscode_authentication_method, user_data.temporaryAccessPass_authentication_method, user_data.mobilePhone_authentication_method, user_data.email_authentication_method, user_data.securityQuestion_authentication_method])

	context = {
		'page':"master-list-user",
		'notifications': Notification.objects.order_by('-created_at')[:10],
		'auth_strengths': ['None', 'MFA', 'Passwordless', 'Phishing Resistant', 'Deprecated'],
		'personas': Persona.objects.all().order_by('priority', 'persona_name'),
		'user_list':user_list,
	}
	return render( request, 'main/user-master-list.html', context)

############################################################################################

@login_required
def user_master_list_api(request):
    # DataTables parameters
    draw = int(request.GET.get('draw', 1))
    start = int(request.GET.get('start', 0))
    length = int(request.GET.get('length', 10))
    search_value = request.GET.get('search[value]', '')
    
    # Sorting parameters
    order_column = request.GET.get('order[0][column]', '0')
    order_dir = request.GET.get('order[0][dir]', 'asc')
    
    # Column mapping for sorting (must match the order in your table headers)
    columns = ['upn', 'persona__persona_name', 'created_at_timestamp', 'last_logon_timestamp', 
               'highest_authentication_strength', 'lowest_authentication_strength',
               'passKeyDeviceBound_authentication_method', 'passKeyDeviceBoundAuthenticator_authentication_method',
               'windowsHelloforBusiness_authentication_method', 'microsoftAuthenticatorPasswordless_authentication_method',
               'microsoftAuthenticatorPush_authentication_method', 'softwareOneTimePasscode_authentication_method',
               'temporaryAccessPass_authentication_method', 'mobilePhone_authentication_method',
               'email_authentication_method', 'securityQuestion_authentication_method']

    # Filtering
    highest_auth = request.GET.getlist('highest_auth[]')
    lowest_auth = request.GET.getlist('lowest_auth[]')
    personas = request.GET.getlist('personas[]')

    users = UserData.objects.select_related('persona').filter(integration__integration_type='Microsoft Entra ID').distinct()

    # Apply sorting
    if order_column.isdigit() and int(order_column) < len(columns):
        sort_field = columns[int(order_column)]
        if order_dir == 'desc':
            sort_field = f'-{sort_field}'
        users = users.order_by(sort_field)
    else:
        users = users.order_by('upn')  # Default sorting

    # Apply filters
    if highest_auth:
        users = users.filter(highest_authentication_strength__in=highest_auth)
    if lowest_auth:
        users = users.filter(lowest_authentication_strength__in=lowest_auth)
    if personas:
        users = users.filter(persona__persona_name__in=personas)
    if search_value:
        users = users.filter(upn__icontains=search_value)

    total = users.count()

    # Pagination
    paginator = Paginator(users, length)
    page_number = (start // length) + 1
    page = paginator.get_page(page_number)

    data = []
    for user_data in page.object_list:
        row = [
            user_data.upn or "",
            user_data.persona.persona_name if user_data.persona else "",
            user_data.created_at_timestamp.strftime("%Y-%m-%d %H:%M:%S") if user_data.created_at_timestamp else "",
            user_data.last_logon_timestamp.strftime("%Y-%m-%d %H:%M:%S") if user_data.last_logon_timestamp else "",
            user_data.highest_authentication_strength,
            user_data.lowest_authentication_strength,
            "&#9989;" if user_data.passKeyDeviceBound_authentication_method else "&#10060;",
            "&#9989;" if user_data.passKeyDeviceBoundAuthenticator_authentication_method else "&#10060;",
            "&#9989;" if user_data.windowsHelloforBusiness_authentication_method else "&#10060;",
            "&#9989;" if user_data.microsoftAuthenticatorPasswordless_authentication_method else "&#10060;",
            "&#9989;" if user_data.microsoftAuthenticatorPush_authentication_method else "&#10060;",
            "&#9989;" if user_data.softwareOneTimePasscode_authentication_method else "&#10060;",
            "&#9989;" if user_data.temporaryAccessPass_authentication_method else "&#10060;",
            "&#9989;" if user_data.mobilePhone_authentication_method else "&#10060;",
            "&#9989;" if user_data.email_authentication_method else "&#10060;",
            "&#9989;" if user_data.securityQuestion_authentication_method else "&#10060;",
        ]
        data.append(row)

    return JsonResponse({
        "draw": draw,
        "recordsTotal": total,
        "recordsFiltered": total,
        "data": data,
    })

@login_required
def user_master_list_export_api(request):
    """API endpoint for exporting all user data without pagination"""
    # Filtering
    highest_auth = request.GET.getlist('highest_auth[]')
    lowest_auth = request.GET.getlist('lowest_auth[]')
    personas = request.GET.getlist('personas[]')
    search_value = request.GET.get('search[value]', '')

    users = UserData.objects.all().order_by('upn')

    if highest_auth:
        users = users.filter(highest_authentication_strength__in=highest_auth)
    if lowest_auth:
        users = users.filter(lowest_authentication_strength__in=lowest_auth)
    if personas:
        users = users.filter(persona__persona_name__in=personas)
    if search_value:
        users = users.filter(upn__icontains=search_value)

    # Use select_related to avoid N+1 queries when accessing persona
    users = users.select_related('persona')

    data = []
    for user_data in users:
        try:
            # Handle null values safely
            created_at = user_data.created_at_timestamp.strftime("%Y-%m-%d %H:%M:%S") if user_data.created_at_timestamp else ""
            last_logon = user_data.last_logon_timestamp.strftime("%Y-%m-%d %H:%M:%S") if user_data.last_logon_timestamp else ""
            
            row = [
                user_data.upn or "",  # Handle null UPN
                user_data.persona.persona_name if user_data.persona else "",  # Handle null persona
                created_at,
                last_logon,
                user_data.highest_authentication_strength or "",
                user_data.lowest_authentication_strength or "",
                "Yes" if user_data.passKeyDeviceBound_authentication_method else "No",
                "Yes" if user_data.passKeyDeviceBoundAuthenticator_authentication_method else "No",
                "Yes" if user_data.windowsHelloforBusiness_authentication_method else "No",
                "Yes" if user_data.microsoftAuthenticatorPasswordless_authentication_method else "No",
                "Yes" if user_data.microsoftAuthenticatorPush_authentication_method else "No",
                "Yes" if user_data.softwareOneTimePasscode_authentication_method else "No",
                "Yes" if user_data.temporaryAccessPass_authentication_method else "No",
                "Yes" if user_data.mobilePhone_authentication_method else "No",
                "Yes" if user_data.email_authentication_method else "No",
                "Yes" if user_data.securityQuestion_authentication_method else "No",
            ]
            data.append(row)
        except Exception as e:
            # Log the error and continue with other users
            logger.error("Error processing user %s: %s", user_data.upn, str(e))
            continue

    return JsonResponse({
        "data": data,
    })

############################################################################################

@login_required
def endpointList(request, integration):
	if integration not in VALID_DEVICE_INTEGRATION_SLUGS:
		return HttpResponseBadRequest("Invalid integration")

	integration_type = SLUG_TO_INTEGRATION_TYPE[integration]
	endpoints = Device.objects.filter(integration__integration_type=integration_type)

	endpoint_list = []
	for endpoint in endpoints:
		endpoint_list.append([endpoint.hostname, endpoint.osPlatform, endpoint.endpointType, endpoint.created_at])

	context = {
		'page':integration,
		'enabled_integrations': getEnabledIntegrations(),
		'enabled_user_integrations': getEnabledUserIntegrations(),
		'notifications': Notification.objects.order_by('-created_at')[:10],
		'integration':integration_type,
		'endpoint_list':endpoint_list,
	}
	return render(request, 'main/endpoint-list.html', context)

############################################################################################

@login_required
def integrations(request):
	# Bulk fetch all integrations in two queries instead of N+1
	device_integrations = {i.integration_type: i for i in Integration.objects.filter(integration_context="Device")}
	user_integrations = {i.integration_type: i for i in Integration.objects.filter(integration_context="User")}

	deviceIntegrationStatuses = []
	for integration_name in integration_names:
		integration = device_integrations.get(integration_name)
		if integration:
			has_secret = bool(integration.client_secret)
			deviceIntegrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, has_secret, integration.id, integration.client_id, integration.tenant_id, integration.tenant_domain, integration.last_synced_at, integration.last_connection_test_at, integration.device_ownership_filter or 'All'])

	userIntegrationStatuses = []
	for integration_name in user_integration_names:
		integration = user_integrations.get(integration_name)
		if integration:
			has_secret = bool(integration.client_secret)
			userIntegrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, has_secret, integration.id, integration.client_id, integration.tenant_id, integration.tenant_domain, integration.last_synced_at, integration.last_connection_test_at, integration.integration_config or {}])
	context = {
		'page':'integrations',
		'notifications': Notification.objects.order_by('-created_at')[:10],
		'enabled_integrations': getEnabledIntegrations(),
		'enabled_user_integrations': getEnabledUserIntegrations(),
		'deviceIntegrationStatuses':deviceIntegrationStatuses,
		'userIntegrationStatuses':userIntegrationStatuses,
	}
	return render( request, 'main/integrations.html', context)

############################################################################################

@login_required
@require_POST
def enableIntegration(request, id):
	if not request.user.is_superuser:
		return HttpResponseForbidden("Unauthorized")
	integration_update = Integration.objects.get(id=id)
	integration_update.enabled = True
	integration_update.save()

	return redirect('integrations')

############################################################################################

@login_required
@require_POST
def disableIntegration(request, id):
	if not request.user.is_superuser:
		return HttpResponseForbidden("Unauthorized")
	integration_update = Integration.objects.get(id=id)
	integration_update.enabled = False
	integration_update.save()

	return redirect('integrations')

############################################################################################

@login_required
@require_POST
def updateIntegration(request, id):
	if not request.user.is_superuser:
		return HttpResponseForbidden("Unauthorized")
	integration_update = Integration.objects.get(id=id)
	integration_update.client_id = request.POST.get('client_id', '')
	if request.POST.get('client_secret'):
		integration_update.client_secret = request.POST['client_secret']
	integration_update.tenant_id = request.POST.get('tenant_id', '')
	integration_update.tenant_domain = request.POST.get('tenant_domain', '')
	if 'device_ownership_filter' in request.POST:
		integration_update.device_ownership_filter = request.POST['device_ownership_filter']
	if integration_update.integration_type == 'Active Directory':
		integration_update.integration_config = {
			'port': int(request.POST.get('ad_port', 636) or 636),
			'use_ssl': request.POST.get('ad_use_ssl') == 'on',
		}
	integration_update.save()

	return redirect('integrations')

############################################################################################

@login_required
def create_backup(request):
	"""Export all application data as a downloadable JSON file."""
	if not request.user.is_superuser:
		return redirect('general-settings')

	import json
	from django.http import HttpResponse
	from django.core import serializers
	from apps.main.models import (
		Device, DeviceComplianceSettings, Integration,
		CloudflareZeroTrustDeviceData, CrowdStrikeFalconDeviceData,
		MicrosoftEntraIDDeviceData, MicrosoftIntuneDeviceData,
		SophosCentralDeviceData, MicrosoftDefenderforEndpointDeviceData,
		QualysDevice, TailscaleDeviceData,
		Persona, PersonaGroup, UserData, SignInSummary, Notification
	)
	from apps.authhandler.models import SSOIntegration
	from apps.logger.views import createLog
	from django.utils import timezone

	models_to_backup = [
		('integrations', Integration),
		('sso_integrations', SSOIntegration),
		('compliance_settings', DeviceComplianceSettings),
		('personas', Persona),
		('persona_groups', PersonaGroup),
	]

	backup_data = {
		'metadata': {
			'version': '1.0',
			'created_at': timezone.now().isoformat(),
			'created_by': request.user.email,
		},
		'data': {}
	}

	integration_fields = ('integration_type', 'enabled', 'tenant_id', 'client_id', 'integration_context', 'device_ownership_filter')
	for key, model in models_to_backup:
		if model is Integration:
			backup_data['data'][key] = json.loads(serializers.serialize('json', model.objects.all(), fields=integration_fields))
		else:
			backup_data['data'][key] = json.loads(serializers.serialize('json', model.objects.all()))

	# Log the backup event
	createLog('BACKUP', 'Backup', 'Create', 'Success',
		request.user.email, request.META.get('REMOTE_ADDR', ''),
		request.META.get('HTTP_USER_AGENT', ''), '', '',
		f'Backup created by {request.user.email}')

	timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
	response = HttpResponse(
		json.dumps(backup_data, indent=2, default=str),
		content_type='application/json'
	)
	response['Content-Disposition'] = f'attachment; filename="tierzerocode_backup_{timestamp}.json"'
	return response


@login_required
def restore_backup(request):
	"""Restore application data from an uploaded JSON backup file."""
	if not request.user.is_superuser:
		return redirect('general-settings')

	if request.method != 'POST':
		return redirect(reverse('general-settings') + '#backup')

	import json
	from django.core import serializers
	from django.contrib import messages
	from django.db import transaction
	from apps.main.models import (
		Device, DeviceComplianceSettings, Integration,
		CloudflareZeroTrustDeviceData, CrowdStrikeFalconDeviceData,
		MicrosoftEntraIDDeviceData, MicrosoftIntuneDeviceData,
		SophosCentralDeviceData, MicrosoftDefenderforEndpointDeviceData,
		QualysDevice, TailscaleDeviceData,
		Persona, PersonaGroup, UserData, SignInSummary, Notification
	)
	from apps.authhandler.models import SSOIntegration
	from apps.logger.views import createLog

	uploaded_file = request.FILES.get('backup_file')
	if not uploaded_file:
		messages.error(request, 'No backup file provided.')
		return redirect(reverse('general-settings') + '#backup')

	if not uploaded_file.name.endswith('.json'):
		messages.error(request, 'Invalid file format. Please upload a .json backup file.')
		return redirect(reverse('general-settings') + '#backup')

	try:
		backup_data = json.loads(uploaded_file.read().decode('utf-8'))
	except (json.JSONDecodeError, UnicodeDecodeError):
		messages.error(request, 'Invalid JSON file. The backup file appears to be corrupted.')
		return redirect(reverse('general-settings') + '#backup')

	if 'metadata' not in backup_data or 'data' not in backup_data:
		messages.error(request, 'Invalid backup format. Missing metadata or data sections.')
		return redirect(reverse('general-settings') + '#backup')

	# Map keys to models — order matters for FK dependencies
	model_map = [
		('integrations', Integration),
		('sso_integrations', SSOIntegration),
		('compliance_settings', DeviceComplianceSettings),
		('personas', Persona),
		('persona_groups', PersonaGroup),
	]

	restore_mode = request.POST.get('restore_mode', 'merge')

	try:
		with transaction.atomic():
			restored_counts = {}
			for key, model in model_map:
				if key not in backup_data['data']:
					continue

				serialized_data = json.dumps(backup_data['data'][key])
				objects = list(serializers.deserialize('json', serialized_data))

				if restore_mode == 'replace':
					model.objects.all().delete()

				count = 0
				for obj in objects:
					obj.save()
					count += 1
				restored_counts[key] = count

			total = sum(restored_counts.values())

			createLog('RESTORE', 'Backup', 'Restore', 'Success',
				request.user.email, request.META.get('REMOTE_ADDR', ''),
				request.META.get('HTTP_USER_AGENT', ''), '', '',
				f'Backup restored by {request.user.email}. Mode: {restore_mode}. Records: {total}')

			messages.success(request, f'Backup restored successfully. {total} records processed.')

	except Exception as e:
		messages.error(request, f'Restore failed: {str(e)}')
		createLog('RESTORE', 'Backup', 'Restore', 'Failure',
			request.user.email, request.META.get('REMOTE_ADDR', ''),
			request.META.get('HTTP_USER_AGENT', ''), '', '',
			f'Backup restore failed: {str(e)}')

	return redirect(reverse('general-settings') + '#backup')

############################################################################################

@login_required
def error500(request):
	return render( request, 'main/pages-500.html')

def custom_404(request, exception):
	return render(request, 'main/pages-404.html', status=404)

def custom_403(request, exception):
	return render(request, 'main/pages-403.html', status=403)

############################################################################################

from apps.main.tasks import (
	deviceIntegrationSyncTask,
	microsoftEntraIDUserSyncTask,
	activeDirectoryUserSyncTask,
	entraUsersSyncTask,
	entraSignInsSyncTask,
	entraCaPoliciesSyncTask,
	entraTenantConfigSyncTask,
	entraAuthMethodsPolicySyncTask,
	entraPasswordPolicySyncTask,
)


_ENTRA_PHASE_TASKS = [
	(entraUsersSyncTask, "Microsoft Entra ID — Users Sync"),
	(entraSignInsSyncTask, "Microsoft Entra ID — Sign-In Logs Sync"),
	(entraCaPoliciesSyncTask, "Microsoft Entra ID — CA Policies Sync"),
	(entraTenantConfigSyncTask, "Microsoft Entra ID — Tenant Security Config Sync"),
	(entraAuthMethodsPolicySyncTask, "Microsoft Entra ID — Auth Methods Policy Sync"),
	(entraPasswordPolicySyncTask, "Microsoft Entra ID — Password Policy Sync"),
]

@login_required
def syncDevices(request, integration):
	if integration not in VALID_DEVICE_INTEGRATION_SLUGS:
		return HttpResponseBadRequest("Invalid integration")
	user_email = request.session.get('user_email', 'unknown') if hasattr(request, 'session') else 'unknown'
	ip_address = request.META.get('REMOTE_ADDR', 'unknown') if hasattr(request, 'META') else 'unknown'
	user_agent = request.META.get('HTTP_USER_AGENT', 'unknown') if hasattr(request, 'META') else 'unknown'
	browser = request.META.get('HTTP_USER_AGENT', 'unknown') if hasattr(request, 'META') else 'unknown'
	operating_system = request.META.get('HTTP_USER_AGENT', 'unknown') if hasattr(request, 'META') else 'unknown'
	integration_clean = SLUG_TO_INTEGRATION_TYPE[integration]
	print (f'Syncing {integration_clean} Devices')
	messages.info(request, f'{integration_clean} Device Integration Sync in Progress')
	notification = Notification.objects.create(
		title=f"{integration_clean} Device Integration Sync",
		status="Queued",
		created_at=timezone.now(),
		updated_at=timezone.now(),
	)
	result = deviceIntegrationSyncTask.enqueue(user_email, ip_address, user_agent, browser, operating_system, integration, integration_clean, notification.id)
	logger.info("Task enqueued: %s", result.id)
	logger.info("Redirecting to Integrations")
	return redirect('/integrations')

@login_required
def syncUsers(request, integration):
	if integration not in VALID_USER_INTEGRATION_SLUGS:
		return HttpResponseBadRequest("Invalid integration")
	user_email = request.session.get('user_email', 'unknown') if hasattr(request, 'session') else 'unknown'
	ip_address = request.META.get('REMOTE_ADDR', 'unknown') if hasattr(request, 'META') else 'unknown'
	user_agent = request.META.get('HTTP_USER_AGENT', 'unknown') if hasattr(request, 'META') else 'unknown'
	browser = request.META.get('HTTP_USER_AGENT', 'unknown') if hasattr(request, 'META') else 'unknown'
	operating_system = request.META.get('HTTP_USER_AGENT', 'unknown') if hasattr(request, 'META') else 'unknown'
	#X6969
	if integration == 'microsoft-entra-id':
		print ("Syncing Microsoft Entra ID Users — fanning out to per-phase tasks")
		messages.info(request, 'Microsoft Entra ID — sync started: 6 phase tasks enqueued')
		for task_fn, title in _ENTRA_PHASE_TASKS:
			notification = Notification.objects.create(
				title=title,
				status="Queued",
				created_at=timezone.now(),
				updated_at=timezone.now(),
			)
			result = task_fn.enqueue(user_email, ip_address, user_agent, browser, operating_system, notification.id)
			logger.info("Entra phase task enqueued: %s -> notification %s, job %s", title, notification.id, result.id)
	elif integration == 'active-directory':
		print ("Syncing Active Directory Users")
		messages.info(request, 'Active Directory User Integration Sync in Progress')
		notification = Notification.objects.create(
			title="Active Directory User Integration Sync",
			status="Queued",
			created_at=timezone.now(),
			updated_at=timezone.now(),
		)
		result = activeDirectoryUserSyncTask.enqueue(user_email, ip_address, user_agent, browser, operating_system, notification.id)
		logger.info("Task enqueued: %s", result.id)
	logger.info("Redirecting to Integrations")
	return redirect('/integrations')

@login_required
def testConnection(request, id):
	integration = Integration.objects.get(id=id)
	if integration.integration_type == 'Microsoft Entra ID':
		required_permissions = ['Directory.Read.All', 'Device.Read.All', 'Directory.ReadWrite.All']
		scope = ["https://graph.microsoft.com/.default"]
	elif integration.integration_type == 'Microsoft Intune':
		required_permissions = ['DeviceManagementManagedDevices.Read.All']
		scope = ["https://graph.microsoft.com/.default"]
	else:
		required_permissions = []
		scope = []
	access_token = getMicrosoftGraphAccessToken(integration.client_id, integration.client_secret, integration.tenant_id, scope)
	if isinstance(access_token, dict) and 'error' in access_token:
		messages.error(request, f'{integration.integration_type} Connection Test Failed: {access_token["error"]}')
		return redirect('/integrations')
	connection_test = testMicrosoftGraphConnection(access_token, required_permissions, tenant_id=integration.tenant_id)
	if connection_test['has_required_permissions']:
		messages.success(request, f'{integration.integration_type} Connection Test Passed')
		integration.last_connection_test_at = datetime.now()
		integration.save()
		return redirect('/integrations')
	else:
		messages.error(request, f'{integration.integration_type} Connection Test Failed. Please check your integration settings or permissions.')
		return redirect('/integrations')

############################################################################################
# API Views for Settings Management
############################################################################################

@login_required
def compliance_summary_api(request):
    """API endpoint to get compliance settings summary"""
    from .utils import ComplianceSettingsManager
    
    try:
        summary = ComplianceSettingsManager.get_compliance_summary()
        return JsonResponse({
            'success': True,
            'data': summary
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
def compliance_report_api(request):
    """API endpoint to get comprehensive compliance report"""
    from .utils import DeviceComplianceChecker
    
    try:
        report = DeviceComplianceChecker.get_compliance_report()
        return JsonResponse({
            'success': True,
            'data': report
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
def bulk_update_compliance_api(request):
    """API endpoint to bulk update compliance settings"""
    from .utils import ComplianceSettingsManager
    
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'error': 'Method not allowed'
        }, status=405)
    
    try:
        data = request.POST
        integration_settings = {}
        
        # Parse the integration settings from the request
        integration_mapping = {
            'cloudflare_zero_trust': 'Cloudflare Zero Trust',
            'crowdstrike_falcon': 'CrowdStrike Falcon',
            'microsoft_defender_for_endpoint': 'Microsoft Defender for Endpoint',
            'microsoft_entra_id': 'Microsoft Entra ID',
            'microsoft_intune': 'Microsoft Intune',
            'sophos_central': 'Sophos Central',
            'qualys': 'Qualys',
            'tailscale': 'Tailscale'
        }
        
        for field_name, integration_name in integration_mapping.items():
            if field_name in data:
                integration_settings[integration_name] = data[field_name] == 'true'
        
        if not integration_settings:
            return JsonResponse({
                'success': False,
                'error': 'No integration settings provided'
            }, status=400)
        
        updated_count = ComplianceSettingsManager.bulk_update_compliance_settings(integration_settings)
        
        return JsonResponse({
            'success': True,
            'message': f'Updated {updated_count} platform settings',
            'updated_count': updated_count
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
def reset_compliance_settings_api(request):
    """API endpoint to reset all compliance settings to defaults"""
    from .utils import ComplianceSettingsManager
    
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'error': 'Method not allowed'
        }, status=405)
    
    try:
        updated_count = ComplianceSettingsManager.reset_compliance_settings_to_defaults()
        
        return JsonResponse({
            'success': True,
            'message': f'Reset {updated_count} platform settings to defaults',
            'updated_count': updated_count
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@require_POST
def delete_notification(request, id):
    """Delete a notification"""
    try:
        notification = Notification.objects.get(id=id)
        notification.delete()
        messages.success(request, 'Notification deleted successfully.')
    except Notification.DoesNotExist:
        messages.error(request, 'Notification not found.')
    except Exception as e:
        messages.error(request, f'Error deleting notification: {str(e)}')

    return redirect('index')

@login_required
@require_POST
def clear_all_notifications(request):
    """Delete all notifications."""
    Notification.objects.all().delete()
    messages.success(request, 'All notifications cleared.')
    return redirect('index')

@login_required
def add_persona(request):
    """Add a new persona"""
    if request.method == 'POST':
        try:
            persona_name = request.POST.get('persona_name', '').strip()
            priority = request.POST.get('priority', '').strip()
            current_tab = request.POST.get('current_tab', 'personas')
            
            if not persona_name:
                messages.error(request, 'Persona name is required.')
            else:
                # Convert priority to integer if provided
                priority_int = None
                if priority:
                    try:
                        priority_int = int(priority)
                    except ValueError:
                        messages.error(request, 'Priority must be a valid number.')
                        return redirect(reverse('general-settings') + f'#{current_tab}')
                
                aal_level_val = request.POST.get('aal_level', '1')
                try:
                    aal_level_int = int(aal_level_val)
                    if aal_level_int not in (1, 2, 3):
                        aal_level_int = 1
                except ValueError:
                    aal_level_int = 1

                Persona.objects.create(
                    persona_name=persona_name,
                    priority=priority_int,
                    aal_level=aal_level_int
                )
                messages.success(request, f'Persona "{persona_name}" added successfully.')
        except Exception as e:
            messages.error(request, f'Error adding persona: {str(e)}')
    
    # Preserve the tab in the redirect
    current_tab = request.POST.get('current_tab', 'personas')
    return redirect(reverse('general-settings') + f'#{current_tab}')

@login_required
def delete_persona(request, id):
    """Delete a persona"""
    try:
        persona = Persona.objects.get(id=id)
        persona_name = persona.persona_name
        persona.delete()
        messages.success(request, f'Persona "{persona_name}" deleted successfully.')
    except Persona.DoesNotExist:
        messages.error(request, 'Persona not found.')
    except Exception as e:
        messages.error(request, f'Error deleting persona: {str(e)}')
    
    # Preserve the tab in the redirect - check GET parameter or default
    current_tab = request.GET.get('tab', 'personas')
    return redirect(reverse('general-settings') + f'#{current_tab}')


@login_required
def add_persona_tag(request):
    """Create a new PersonaTag."""
    if request.method == 'POST':
        name = request.POST.get('tag_name', '').strip()
        if not name:
            messages.error(request, 'Tag name is required.')
        else:
            _, created = PersonaTag.objects.get_or_create(name=name)
            if created:
                messages.success(request, f'Tag "{name}" added.')
            else:
                messages.info(request, f'Tag "{name}" already exists.')
    return redirect(reverse('general-settings') + '#personas')


@login_required
def delete_persona_tag(request, tag_id):
    """Delete a PersonaTag (removes it from all personas). Default tags cannot be deleted."""
    try:
        tag = PersonaTag.objects.get(pk=tag_id)
        if tag.is_default:
            messages.error(request, f'Tag "{tag.name}" is a default tag and cannot be deleted.')
        else:
            tag.delete()
            messages.success(request, f'Tag "{tag.name}" deleted.')
    except PersonaTag.DoesNotExist:
        messages.error(request, 'Tag not found.')
    return redirect(reverse('general-settings') + '#personas')


@login_required
def toggle_persona_tag(request, persona_id):
    """AJAX: add or remove a tag on a persona. Returns JSON."""
    from django.http import JsonResponse
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    try:
        persona = Persona.objects.get(pk=persona_id)
        tag = PersonaTag.objects.get(pk=request.POST.get('tag_id'))
        if persona.tags.filter(pk=tag.pk).exists():
            persona.tags.remove(tag)
            action = 'removed'
        else:
            persona.tags.add(tag)
            action = 'added'
        return JsonResponse({'action': action, 'tag_id': tag.pk, 'tag_name': tag.name})
    except (Persona.DoesNotExist, PersonaTag.DoesNotExist):
        return JsonResponse({'error': 'Not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

############################################################################################