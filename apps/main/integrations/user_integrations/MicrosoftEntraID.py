# Import Dependencies
import msal, requests, threading
from django.utils import timezone
from datetime import datetime
from django.contrib import messages
from django.utils.timezone import make_aware
# Import Models
from apps.main.models import Integration, UserData, Persona, PersonaGroup, Notification, SignInSummary, ConditionalAccessPolicy, TenantSecurityConfig, TenantAuthMethodsPolicy, PasswordPolicy
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import _fetch_paginated_data
from apps.code_packages.microsoft import getMicrosoftGraphAccessToken

AUTHENTICATION_STRENGTHS = {
    "Phishing Resistant": {'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeySynced', 'windowsHelloForBusiness'},
    "Passwordless": {'microsoftAuthenticatorPasswordless'},
    "MFA": {'microsoftAuthenticatorPush', 'softwareOneTimePasscode', 'temporaryAccessPass'},
    "Deprecated": {'mobilePhone', 'email', 'securityQuestion'},
    "None": set()
}

def getMicrosoftEntraIDUsers(access_token):
    """Fetch all enabled Microsoft Entra ID users."""
    url = "https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,id,employeeId,givenName,surname,accountEnabled,jobTitle,department,createdDateTime,signInActivity,onPremisesSyncEnabled&$filter=accountEnabled eq true and userType eq 'Member'"
    headers = {'Authorization': access_token}
    return _fetch_paginated_data(url, headers)

def getMicrosoftEntraIDGuests(access_token):
    """Fetch all enabled Microsoft Entra ID guests."""
    # Check if access_token is an error dictionary
    if isinstance(access_token, dict) and 'error' in access_token:
        raise Exception(f"Failed to get access token: {access_token['error']}")
    
    url = "https://graph.microsoft.com/v1.0/users/$count?$filter=userType eq 'guest'"
    headers = {'Authorization': access_token, 'ConsistencyLevel': 'eventual'}
    response = requests.get(url, headers=headers)
    # $count endpoint returns the count as text/plain (just a number) or as JSON
    # Handle both cases
    try:
        result = response.json()
        # If it's a dict with 'value', return that; if it's just a number, return it
        if isinstance(result, dict) and 'value' in result:
            return result['value']
        elif isinstance(result, (int, float)):
            return int(result)
        else:
            return int(response.text)
    except (ValueError, TypeError):
        # If JSON parsing fails, it's likely text/plain
        return int(response.text)

def getMicrosoftEntraIDGroups(access_token):
    """Fetch all enabled Microsoft Entra ID groups."""
    # url = "https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,id,employeeId,givenName,surname,accountEnabled,jobTitle,department,createdDateTime,signInActivity&$filter=accountEnabled eq true and userType eq 'Guest'"
    url = "https://graph.microsoft.com/v1.0/groups/$count"
    # headers = {'Authorization': access_token}
    headers = {'Authorization': access_token, 'ConsistencyLevel': 'eventual'}
    # return _fetch_paginated_data(url, headers)
    response = requests.get(url, headers=headers)
    # $count endpoint returns the count as text/plain (just a number) or as JSON
    # Handle both cases
    try:
        result = response.json()
        # If it's a dict with 'value', return that; if it's just a number, return it
        if isinstance(result, dict) and 'value' in result:
            return result['value']
        elif isinstance(result, (int, float)):
            return int(result)
        else:
            return int(response.text)
    except (ValueError, TypeError):
        # If JSON parsing fails, it's likely text/plain
        return int(response.text)

def getMicrosoftEntraIDApps(access_token):
    """Fetch all enabled Microsoft Entra ID apps."""
    # Check if access_token is an error dictionary
    if isinstance(access_token, dict) and 'error' in access_token:
        raise Exception(f"Failed to get access token: {access_token['error']}")
    
    url = "https://graph.microsoft.com/v1.0/applications?$count=true&$top=1"
    headers = {'Authorization': access_token, 'ConsistencyLevel': 'eventual'}
    response = requests.get(url, headers=headers)
    # Extract @odata.count from the response
    try:
        result = response.json()
        # Get @odata.count property from the response
        if isinstance(result, dict) and '@odata.count' in result:
            return int(result['@odata.count'])
        else:
            # Fallback: if no @odata.count, return 0
            return 0
    except (ValueError, TypeError, KeyError):
        # If parsing fails, return 0
        return 0

def getMicrosoftEntraTenantDetails(access_token):
    """Fetch tenant details."""
    # Check if access_token is an error dictionary
    if isinstance(access_token, dict) and 'error' in access_token:
        raise Exception(f"Failed to get access token: {access_token['error']}")
    
    url = "https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains"
    headers = {'Authorization': access_token}
    response = requests.get(url, headers=headers)
    try:
        result = response.json()
        return result
    except (ValueError, TypeError):
        return None

def getMicrosoftEntraIDUserAuthenticationMethods(access_token):
    """Fetch authentication methods for all users."""
    # Check if access_token is an error dictionary
    if isinstance(access_token, dict) and 'error' in access_token:
        raise Exception(f"Failed to get access token: {access_token['error']}")
    
    url = f'https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?$select=userPrincipalName,isAdmin,isSsprRegistered,isSsprEnabled,isSsprCapable,isMfaRegistered,isMfaCapable,isPasswordlessCapable,methodsRegistered'
    headers = {'Authorization': access_token}
    return _fetch_paginated_data(url, headers)

def getPersonaGroupMembership(access_token, object_id):
    """Fetch members of a specific persona group."""
    # Check if access_token is an error dictionary
    if isinstance(access_token, dict) and 'error' in access_token:
        raise Exception(f"Failed to get access token: {access_token['error']}")
    
    url = f'https://graph.microsoft.com/v1.0/groups/{object_id}/members?$select=userPrincipalName'
    headers = {'Authorization': access_token}
    return _fetch_paginated_data(url, headers)

def getPersonaGroupMemberships(access_token):
    """Fetch all persona group memberships for mapping personas."""
    persona_groups = PersonaGroup.objects.select_related('persona').all()
    all_members = []
    
    for group in persona_groups:
        if not group.object_id:  # Skip groups without object_id
            continue
        group_members = getPersonaGroupMembership(access_token, group.object_id)
        for member in group_members:
            member["persona_group"] = group  # Store the PersonaGroup object
            member["group_display_name"] = group.group_name
        all_members.extend(group_members)

    return all_members

def determine_authentication_strength(auth_method_types):
    """Determine the highest and lowest authentication strengths."""
    highest_strength = "None"
    lowest_strength = "None"

    for strength, methods in AUTHENTICATION_STRENGTHS.items():
        if auth_method_types & methods:
            highest_strength = strength
            break

    for strength, methods in reversed(AUTHENTICATION_STRENGTHS.items()):
        if auth_method_types & methods:
            lowest_strength = strength
            break

    return highest_strength, lowest_strength

def _parse_timestamp(timestamp_str):
    """Parse ISO 8601 timestamp string to timezone-aware datetime."""
    if not timestamp_str:
        return None
    
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return make_aware(dt) if dt.tzinfo is None else dt
    except Exception:
        return None

def _get_user_persona_group(matching_groups):
    """Determine user persona group from matching groups.
    Returns:
    - PersonaGroup object if exactly one match
    - 'DUPLICATE' if more than one match
    - None if no matches
    """
    if len(matching_groups) > 1:
        return 'DUPLICATE'  # Return special indicator for duplicates
    if matching_groups:
        return matching_groups[0].get("persona_group")  # Return the PersonaGroup object
    return None

def _build_authentication_fields(auth_method_types):
    """Build authentication method fields dynamically."""
    # Map API field names to database field names
    field_mapping = {
        'windowsHelloForBusiness': 'windowsHelloforBusiness',  # API returns this, DB expects this
        'microsoftAuthenticatorPush': 'microsoftAuthenticatorPush',
        'microsoftAuthenticatorPasswordless': 'microsoftAuthenticatorPasswordless',
        'softwareOneTimePasscode': 'softwareOneTimePasscode',
        'temporaryAccessPass': 'temporaryAccessPass',
        'email': 'email',
        'mobilePhone': 'mobilePhone',
        'securityQuestion': 'securityQuestion',
        'passKeyDeviceBound': 'passKeyDeviceBound',
        'passKeyDeviceBoundAuthenticator': 'passKeyDeviceBoundAuthenticator',
        'passKeySynced': 'passKeySynced',  # Passkey (Synced) — platform/cloud-synced passkeys
    }
    
    auth_fields = {}
    for api_method, db_field in field_mapping.items():
        field_name = f"{db_field}_authentication_method"
        auth_fields[field_name] = api_method in auth_method_types
    return auth_fields

# Fields to update on existing UserData records (excludes upn, auto fields, and M2M)
_USER_UPDATE_FIELDS = [
    'uid', 'network_id', 'persona', 'persona_group', 'given_name', 'surname',
    'job_title', 'department', 'last_logon_timestamp', 'created_at_timestamp',
    'highest_authentication_strength', 'lowest_authentication_strength',
    'isAdmin', 'isMfaCapable', 'isMfaRegistered', 'isPasswordlessCapable',
    'isSsprEnabled', 'isSsprRegistered', 'onPremisesSyncEnabled',
    'passKeyDeviceBound_authentication_method', 'passKeyDeviceBoundAuthenticator_authentication_method',
    'passKeySynced_authentication_method',
    'windowsHelloforBusiness_authentication_method', 'microsoftAuthenticatorPasswordless_authentication_method',
    'microsoftAuthenticatorPush_authentication_method', 'softwareOneTimePasscode_authentication_method',
    'temporaryAccessPass_authentication_method', 'mobilePhone_authentication_method',
    'email_authentication_method', 'securityQuestion_authentication_method',
]

def _process_user_data(user_data, auth_by_upn, memberships_by_upn, persona_duplicate, persona_unknown):
    """Process individual user data and return user fields dict, or None to skip."""
    if not user_data.get('userPrincipalName'):
        return None

    if user_data.get('accountEnabled') == "false":
        return None

    if not user_data.get('employeeId'):
        user_data['employeeId'] = 'none'

    last_logon = _parse_timestamp(user_data.get('signInActivity', {}).get('lastSuccessfulSignInDateTime'))
    created_at = _parse_timestamp(user_data.get('createdDateTime'))

    upn_lower = user_data['userPrincipalName'].lower()

    user_authentication_data = auth_by_upn.get(upn_lower, {})
    matching_groups = memberships_by_upn.get(upn_lower, [])
    persona_group_result = _get_user_persona_group(matching_groups)

    if persona_group_result == 'DUPLICATE':
        persona = persona_duplicate
        persona_group = None
    elif persona_group_result:
        persona_group = persona_group_result
        persona = persona_group.persona if persona_group else None
    else:
        persona = persona_unknown
        persona_group = None

    auth_method_types = set(user_authentication_data.get('methodsRegistered', []))
    highest_strength, lowest_strength = determine_authentication_strength(auth_method_types)

    user_fields = {
        'upn': upn_lower,
        'uid': user_data['id'],
        'network_id': user_data['employeeId'].lower(),
        'persona': persona,
        'persona_group': persona_group,
        'given_name': user_data.get('givenName', ''),
        'surname': user_data.get('surname', ''),
        'job_title': user_data.get('jobTitle', ''),
        'department': user_data.get('department', ''),
        'last_logon_timestamp': last_logon,
        'created_at_timestamp': created_at,
        'highest_authentication_strength': highest_strength,
        'lowest_authentication_strength': lowest_strength,
    }

    capability_fields = ['isAdmin', 'isMfaCapable', 'isMfaRegistered', 'isPasswordlessCapable', 'isSsprEnabled', 'isSsprRegistered']
    for field in capability_fields:
        user_fields[field] = user_authentication_data.get(field, False)

    user_fields['onPremisesSyncEnabled'] = user_data.get('onPremisesSyncEnabled') or False  # null from Graph = cloud-only

    user_fields.update(_build_authentication_fields(auth_method_types))
    return user_fields

def updateMicrosoftEntraIDUserDatabase(users, authentication_data, access_token):
    """Update the local UserData database with Microsoft Entra ID user and authentication data using bulk operations."""
    integration = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User")
    persona_memberships = getPersonaGroupMemberships(access_token)

    # Pre-create personas outside the loop (avoids per-user get_or_create)
    persona_duplicate, _ = Persona.objects.get_or_create(persona_name='DUPLICATE', defaults={'priority': 999})
    persona_unknown, _ = Persona.objects.get_or_create(persona_name='Unknown', defaults={'priority': 998})

    # Build O(1) lookup maps
    auth_by_upn = {
        item['userPrincipalName'].lower(): item
        for item in authentication_data
        if item.get('userPrincipalName')
    }
    memberships_by_upn = {}
    for membership in persona_memberships:
        upn = membership.get('userPrincipalName', '').lower()
        if upn:
            memberships_by_upn.setdefault(upn, []).append(membership)

    # --- Phase 1: Process all API data into field dicts ---
    all_user_fields = []
    for user_data in users:
        fields = _process_user_data(user_data, auth_by_upn, memberships_by_upn, persona_duplicate, persona_unknown)
        if fields:
            all_user_fields.append(fields)

    if not all_user_fields:
        return

    incoming_upns = {f['upn'] for f in all_user_fields}

    # --- Phase 2: Fetch existing state in ONE query ---
    existing_users = {u.upn: u for u in UserData.objects.filter(upn__in=incoming_upns)}

    # --- Phase 3: Split into create vs update ---
    to_create = []
    to_update = []

    for fields in all_user_fields:
        upn = fields['upn']
        if upn in existing_users:
            obj = existing_users[upn]
            for field, value in fields.items():
                if field != 'upn':
                    setattr(obj, field, value)
            to_update.append(obj)
        else:
            to_create.append(UserData(**fields))

    # --- Phase 4: Bulk write — 2 queries instead of N×2 ---
    if to_create:
        UserData.objects.bulk_create(to_create)

    if to_update:
        UserData.objects.bulk_update(to_update, _USER_UPDATE_FIELDS, batch_size=500)

    # --- Phase 5: Bulk set M2M integration links ---
    # Re-fetch all users to get PKs for newly created ones
    all_users = {u.upn: u for u in UserData.objects.filter(upn__in=incoming_upns)}
    UserIntegrationThrough = UserData.integration.through
    existing_links = set(
        UserIntegrationThrough.objects.filter(
            integration=integration,
            userdata__upn__in=incoming_upns
        ).values_list('userdata_id', flat=True)
    )
    new_links = [
        UserIntegrationThrough(userdata=user_obj, integration=integration)
        for user_obj in all_users.values()
        if user_obj.pk not in existing_links
    ]
    if new_links:
        UserIntegrationThrough.objects.bulk_create(new_links, ignore_conflicts=True)

    # --- Phase 6: Bulk delete stale users ---
    UserData.objects.filter(integration=integration).exclude(upn__in=incoming_upns).delete()

def syncSignInSummary(access_token):
    """Fetch sign-in logs and compute CA+MFA summary. Requires AuditLog.Read.All permission."""
    from apps.main.integrations.device_integrations.ReusedFunctions import _sync_log

    try:
        # Fetch successful sign-ins — beta endpoint (authenticationRequirement not available on v1.0)
        url = (
            "https://graph.microsoft.com/beta/auditLogs/signIns"
            "?$filter=status/errorCode eq 0"
            "&$select=conditionalAccessStatus,authenticationRequirement"
            "&$top=999"
        )
        headers = {'Authorization': access_token}

        ca_mfa = 0
        ca_no_mfa = 0
        no_ca_mfa = 0
        no_ca_no_mfa = 0
        total = 0

        while url:
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                _sync_log("Microsoft Entra ID", "1507", "Failure",
                          f"Sign-in logs fetch failed: {response.status_code} - {response.text[:500]}")
                break
            data = response.json()
            for signin in data.get('value', []):
                total += 1
                ca_applied = signin.get('conditionalAccessStatus') == 'success'
                mfa_required = signin.get('authenticationRequirement') == 'multiFactorAuthentication'

                if ca_applied and mfa_required:
                    ca_mfa += 1
                elif ca_applied and not mfa_required:
                    ca_no_mfa += 1
                elif not ca_applied and mfa_required:
                    no_ca_mfa += 1
                else:
                    no_ca_no_mfa += 1

            url = data.get('@odata.nextLink')

        if total > 0:
            SignInSummary.objects.update_or_create(
                id=1,
                defaults={
                    'ca_mfa': ca_mfa,
                    'ca_no_mfa': ca_no_mfa,
                    'no_ca_mfa': no_ca_mfa,
                    'no_ca_no_mfa': no_ca_no_mfa,
                    'total_signins': total,
                }
            )
            _sync_log("Microsoft Entra ID", "1506", "Success",
                      f"Sign-in summary: {total} sign-ins (CA+MFA={ca_mfa}, CA-only={ca_no_mfa}, MFA-only={no_ca_mfa}, Neither={no_ca_no_mfa})")
        else:
            _sync_log("Microsoft Entra ID", "1506", "Warning", "No sign-in records returned from Graph API")

    except Exception as e:
        _sync_log("Microsoft Entra ID", "1507", "Failure", f"Sign-in summary sync error: {str(e)}")

def syncConditionalAccessPolicies(access_token):
    """Fetch Conditional Access policies from Microsoft Graph. Requires Policy.Read.All permission."""
    from apps.main.integrations.device_integrations.ReusedFunctions import _sync_log

    try:
        url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        headers = {'Authorization': access_token}

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            _sync_log("Microsoft Entra ID", "1508", "Failure",
                      f"CA policies fetch failed: {response.status_code} - {response.text[:500]}")
            return

        policies = response.json().get('value', [])
        synced_ids = []

        for policy in policies:
            policy_id = policy.get('id')
            if not policy_id:
                continue

            session_controls = policy.get('sessionControls') or {}
            sign_in_freq = session_controls.get('signInFrequency') or {}
            persistent_browser = session_controls.get('persistentBrowser') or {}

            ConditionalAccessPolicy.objects.update_or_create(
                policy_id=policy_id,
                defaults={
                    'display_name': policy.get('displayName', ''),
                    'state': policy.get('state', 'disabled'),
                    'conditions_users': policy.get('conditions', {}).get('users'),
                    'conditions_applications': policy.get('conditions', {}).get('applications'),
                    'conditions_platforms': policy.get('conditions', {}).get('platforms'),
                    'conditions_locations': policy.get('conditions', {}).get('locations'),
                    'grant_controls': policy.get('grantControls'),
                    'session_controls': session_controls if session_controls else None,
                    'sign_in_frequency_value': sign_in_freq.get('value'),
                    'sign_in_frequency_type': sign_in_freq.get('type'),
                    'sign_in_frequency_enabled': bool(sign_in_freq.get('isEnabled')),
                    'persistent_browser_mode': persistent_browser.get('mode'),
                    'persistent_browser_enabled': bool(persistent_browser.get('isEnabled')),
                    'raw_policy': policy,
                },
            )
            synced_ids.append(policy_id)

        # Remove policies that no longer exist in Entra ID
        ConditionalAccessPolicy.objects.exclude(policy_id__in=synced_ids).delete()

        _sync_log("Microsoft Entra ID", "1508", "Success",
                  f"Synced {len(synced_ids)} Conditional Access policies")

    except Exception as e:
        _sync_log("Microsoft Entra ID", "1509", "Failure",
                  f"CA policy sync error: {str(e)}")


def syncTenantSecurityConfig(access_token):
    """Fetch tenant security settings from Microsoft Graph.

    Tries multiple endpoints to find password protection config:
    1. GET /settings (directory settings — customized tenants)
    2. GET /beta/settings (beta endpoint — may have more data)
    3. GET /beta/security/authenticationMethodsPolicy (auth method policies)

    If no password protection settings are found in any endpoint, saves
    Entra ID defaults (global banned list is ON by default in all tenants).

    Requires Directory.Read.All permission.
    """
    from apps.main.integrations.device_integrations.ReusedFunctions import _sync_log

    try:
        headers = {'Authorization': access_token}
        found_settings = False

        password_protection_enabled = False
        password_protection_mode = None
        password_protection_on_prem = False
        custom_banned_enabled = False
        custom_banned_list = None
        raw_data = {}

        # Password Rule Settings template ID
        PASSWORD_TEMPLATE_ID = '5cf42378-d67d-4f36-ba46-e8b86229381d'

        def parse_settings_values(settings_list):
            """Extract password protection from directory settings."""
            nonlocal found_settings, password_protection_enabled, password_protection_mode
            nonlocal password_protection_on_prem, custom_banned_enabled, custom_banned_list

            for setting_group in settings_list:
                template_id = setting_group.get('templateId', '')
                display_name = setting_group.get('displayName', '')
                raw_values = setting_group.get('values', [])

                if not raw_values:
                    continue

                values = {v.get('name', ''): v.get('value') for v in raw_values if isinstance(v, dict)}

                # Match by template ID or by content
                if (template_id == PASSWORD_TEMPLATE_ID or
                    'BannedPasswordCheck' in str(values) or
                    'Password Rule' in display_name):

                    found_settings = True
                    password_protection_enabled = str(values.get('EnableBannedPasswordCheck', 'false')).lower() == 'true'
                    password_protection_mode = values.get('BannedPasswordCheckOnPremisesMode', 'Audit')
                    password_protection_on_prem = str(values.get('EnableBannedPasswordCheckOnPremises', 'false')).lower() == 'true'
                    # BannedPasswordList is tab-delimited; custom list is enabled if non-empty
                    raw_list = values.get('BannedPasswordList', '')
                    if raw_list:
                        custom_banned_list = [p.strip() for p in str(raw_list).split('\t') if p.strip()]
                        custom_banned_enabled = len(custom_banned_list) > 0
                    else:
                        custom_banned_enabled = False
                        custom_banned_list = None

        # Try v1.0 /settings
        response = requests.get("https://graph.microsoft.com/v1.0/settings", headers=headers)
        if response.status_code == 200:
            settings_list = response.json().get('value', [])
            raw_data['v1_settings'] = settings_list
            parse_settings_values(settings_list)

        # Try beta /settings if not found yet
        if not found_settings:
            beta_response = requests.get("https://graph.microsoft.com/beta/settings", headers=headers)
            if beta_response.status_code == 200:
                beta_list = beta_response.json().get('value', [])
                raw_data['beta_settings'] = beta_list
                parse_settings_values(beta_list)

        # Try groupSettings (some tenants store it here)
        if not found_settings:
            group_response = requests.get("https://graph.microsoft.com/v1.0/groupSettings", headers=headers)
            if group_response.status_code == 200:
                group_list = group_response.json().get('value', [])
                raw_data['group_settings'] = group_list
                parse_settings_values(group_list)

        # If still no explicit settings found, Entra ID defaults apply:
        # Global banned password list is ENABLED by default in all Entra ID tenants
        # Mode defaults to "Enforce" for cloud-only
        if not found_settings:
            password_protection_enabled = True  # Entra ID default
            password_protection_mode = 'Enforce'  # Cloud-only default
            raw_data['note'] = 'No explicit password protection settings found. Using Entra ID defaults (global banned list enabled, enforce mode for cloud).'

        TenantSecurityConfig.objects.update_or_create(
            id=1,
            defaults={
                'password_protection_enabled': password_protection_enabled,
                'password_protection_mode': password_protection_mode,
                'password_protection_on_premises_enabled': password_protection_on_prem,
                'custom_banned_passwords_enabled': custom_banned_enabled,
                'custom_banned_password_list': custom_banned_list,
                'raw_settings': raw_data,
            },
        )

        source = 'explicit settings' if found_settings else 'Entra ID defaults'
        _sync_log("Microsoft Entra ID", "1510", "Success",
                  f"Tenant security config synced from {source} (password protection: {'enabled' if password_protection_enabled else 'disabled'}, mode: {password_protection_mode})")

    except Exception as e:
        _sync_log("Microsoft Entra ID", "1511", "Failure",
                  f"Tenant security config sync error: {str(e)}")


def syncAuthMethodsPolicy(access_token):
    """Fetch authentication methods policy and SSPR config from Microsoft Graph.

    Calls:
      GET /v1.0/policies/authenticationMethodsPolicy  — per-method enabled state
      GET /beta/policies/selfServicePasswordReset      — SSPR config + security questions

    Requires Policy.Read.All permission.
    """
    from apps.main.integrations.device_integrations.ReusedFunctions import _sync_log

    try:
        headers = {'Authorization': access_token}

        # --- Auth Methods Policy ---
        amp_response = requests.get(
            "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy",
            headers=headers,
        )
        raw_auth_methods = {}
        method_states = {}

        if amp_response.status_code == 200:
            raw_auth_methods = amp_response.json()
            for method in raw_auth_methods.get('authenticationMethodConfigurations', []):
                method_id = method.get('id', '').lower()
                state = method.get('state', 'disabled').lower()
                method_states[method_id] = (state == 'enabled')

        email_otp_enabled = method_states.get('email', True)
        fido2_enabled = method_states.get('fido2', True)
        microsoft_authenticator_enabled = method_states.get('microsoftauthenticator', True)
        sms_enabled = method_states.get('sms', True)
        software_oath_enabled = method_states.get('softwareoath', True)
        temporary_access_pass_enabled = method_states.get('temporaryaccesspass', False)
        x509_certificate_enabled = method_states.get('x509certificate', False)
        windows_hello_business_enabled = method_states.get('windowshelloforbusiness', True)
        passkey_enabled = method_states.get('passkey', True)

        # --- SSPR Policy ---
        sspr_response = requests.get(
            "https://graph.microsoft.com/beta/policies/selfServicePasswordReset",
            headers=headers,
        )
        raw_sspr = {}
        sspr_state = None
        sspr_security_questions_enabled = False
        sspr_methods_required = None
        sspr_allowed_methods = []

        if sspr_response.status_code == 200:
            raw_sspr = sspr_response.json()
            sspr_state = raw_sspr.get('selfServicePasswordResetEnabled', None)
            auth_methods_cfg = raw_sspr.get('authenticationMethods', {})
            sspr_allowed_methods = auth_methods_cfg.get('authenticationMethodTypes', [])
            sspr_methods_required = auth_methods_cfg.get('numberOfMethodsRequired', None)
            sspr_security_questions_enabled = 'securityQuestion' in sspr_allowed_methods

        TenantAuthMethodsPolicy.objects.update_or_create(
            id=1,
            defaults={
                'email_otp_enabled': email_otp_enabled,
                'fido2_enabled': fido2_enabled,
                'microsoft_authenticator_enabled': microsoft_authenticator_enabled,
                'sms_enabled': sms_enabled,
                'software_oath_enabled': software_oath_enabled,
                'temporary_access_pass_enabled': temporary_access_pass_enabled,
                'x509_certificate_enabled': x509_certificate_enabled,
                'windows_hello_business_enabled': windows_hello_business_enabled,
                'passkey_enabled': passkey_enabled,
                'sspr_state': sspr_state,
                'sspr_security_questions_enabled': sspr_security_questions_enabled,
                'sspr_methods_required': sspr_methods_required,
                'sspr_allowed_methods': sspr_allowed_methods,
                'raw_auth_methods': raw_auth_methods,
                'raw_sspr': raw_sspr,
            },
        )

        _sync_log("Microsoft Entra ID", "1512", "Success",
                  f"Auth methods policy synced: email_otp={email_otp_enabled}, "
                  f"sspr_security_questions={sspr_security_questions_enabled}, "
                  f"sspr_state={sspr_state}")

    except Exception as e:
        _sync_log("Microsoft Entra ID", "1513", "Failure",
                  f"Auth methods policy sync error: {str(e)}")


def syncPasswordPolicy(access_token):
    """Sync one Entra ID cloud password policy record from the default domain.

    Entra ID has one effective password policy per tenant. Per-domain validity
    periods differ only in the max-age setting; min length, complexity, and
    lockout are tenant-wide constants. We use the default domain as the source
    of truth and keep a single PasswordPolicy row with source='entra_id'.

    Requires Domain.Read.All or Directory.Read.All permission.
    """
    from apps.main.integrations.device_integrations.ReusedFunctions import _sync_log

    # 2147483647 is the Graph API sentinel for "password never expires"
    _NEVER_EXPIRES = 2147483647

    try:
        headers = {'Authorization': access_token}
        response = requests.get(
            "https://graph.microsoft.com/v1.0/domains"
            "?$select=id,isDefault,isVerified,passwordValidityPeriodInDays,passwordNotificationWindowInDays",
            headers=headers,
        )
        if response.status_code != 200:
            _sync_log("Microsoft Entra ID", "1516", "Failure",
                      f"Password policy fetch failed: {response.status_code} - {response.text[:500]}")
            return

        domains = response.json().get('value', [])
        verified = [d for d in domains if d.get('isVerified')]

        # Prefer the default domain; fall back to first non-.onmicrosoft.com; then any verified
        target = (
            next((d for d in verified if d.get('isDefault')), None)
            or next((d for d in verified if not d.get('id', '').endswith('.onmicrosoft.com')), None)
            or (verified[0] if verified else None)
        )

        if not target:
            _sync_log("Microsoft Entra ID", "1516", "Failure",
                      "Password policy sync: no verified domains found in tenant")
            return

        domain_id = target.get('id', '')
        validity = target.get('passwordValidityPeriodInDays')
        max_age = None if (validity is None or validity >= _NEVER_EXPIRES) else int(validity)
        notification = target.get('passwordNotificationWindowInDays')

        PasswordPolicy.objects.update_or_create(
            policy_identifier=domain_id,
            defaults={
                'source': 'entra_id',
                'name': 'Entra ID Cloud Password Policy',
                # Entra ID enforces 8-char minimum and complexity for all cloud users
                'min_password_length': 8,
                'complexity_enabled': True,
                'max_password_age_days': max_age,
                'password_notification_window_days': int(notification) if notification is not None else None,
                # Fields not applicable to cloud-only policy
                'min_password_age_days': None,
                'password_history_length': None,
                'lockout_threshold': None,
                'lockout_duration_minutes': None,
                'lockout_observation_window_minutes': None,
                'reversible_encryption_enabled': None,
                'precedence': None,
            },
        )

        # Remove stale per-domain records from older syncs that created one row per domain
        PasswordPolicy.objects.filter(source='entra_id').exclude(policy_identifier=domain_id).delete()

        synced = 1

        _sync_log("Microsoft Entra ID", "1516", "Success",
                  f"Password policies synced for {synced} verified domain(s)")

    except Exception as e:
        _sync_log("Microsoft Entra ID", "1517", "Failure",
                  f"Password policy sync error: {str(e)}")


def syncMicrosoftEntraIDUser():
    """Synchronize Microsoft Entra ID users and update the local database."""
    data = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User")
    
    # Validate integration data
    if not data.client_id or not data.client_secret or not data.tenant_id:
        raise Exception("Microsoft Entra ID integration is not properly configured. Missing client_id, client_secret, or tenant_id.")
    
    access_token = getMicrosoftGraphAccessToken(data.client_id, data.client_secret, data.tenant_id, ["https://graph.microsoft.com/.default"])
    
    # Check if access_token is an error dictionary
    if isinstance(access_token, dict) and 'error' in access_token:
        error_msg = str(access_token['error'])
        raise Exception(f"Failed to get access token: {error_msg}")
    
    users = getMicrosoftEntraIDUsers(access_token)
    authentication_data = getMicrosoftEntraIDUserAuthenticationMethods(access_token)
    updateMicrosoftEntraIDUserDatabase(users, authentication_data, access_token)

    # Sync CA+MFA sign-in analysis (requires AuditLog.Read.All)
    syncSignInSummary(access_token)

    # Sync Conditional Access policies (requires Policy.Read.All)
    syncConditionalAccessPolicies(access_token)

    # Sync tenant security configuration (requires Directory.Read.All)
    syncTenantSecurityConfig(access_token)

    # Sync authentication methods policy and SSPR config (requires Policy.Read.All)
    syncAuthMethodsPolicy(access_token)

    # Sync password policy per verified domain (requires Domain.Read.All or Directory.Read.All)
    syncPasswordPolicy(access_token)

    data.last_synced_at = timezone.now()
    data.save()
    return True