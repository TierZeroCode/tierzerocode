# Import Dependencies
import msal, requests, threading
from django.utils import timezone
from datetime import datetime
from django.contrib import messages
from django.utils.timezone import make_aware
# Import Models
from apps.main.models import Integration, UserData, Persona, PersonaGroup, Notification, SignInSummary
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import _fetch_paginated_data
from apps.code_packages.microsoft import getMicrosoftGraphAccessToken

AUTHENTICATION_STRENGTHS = {
    "Phishing Resistant": {'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'windowsHelloForBusiness'},
    "Passwordless": {'microsoftAuthenticatorPasswordless'},
    "MFA": {'microsoftAuthenticatorPush', 'softwareOneTimePasscode', 'temporaryAccessPass'},
    "Deprecated": {'mobilePhone', 'email', 'securityQuestion'},
    "None": set()
}

def getMicrosoftEntraIDUsers(access_token):
    """Fetch all enabled Microsoft Entra ID users."""
    url = "https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,id,employeeId,givenName,surname,accountEnabled,jobTitle,department,createdDateTime,signInActivity&$filter=accountEnabled eq true and userType eq 'Member'"
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
        'passKeyDeviceBoundAuthenticator': 'passKeyDeviceBoundAuthenticator'
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
    'isSsprEnabled', 'isSsprRegistered',
    'passKeyDeviceBound_authentication_method', 'passKeyDeviceBoundAuthenticator_authentication_method',
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
    try:
        # Fetch successful interactive sign-ins from the last 7 days
        url = (
            "https://graph.microsoft.com/v1.0/auditLogs/signIns"
            "?$filter=status/errorCode eq 0 and signInEventTypes/any(t:t eq 'interactiveUser')"
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

        # Upsert the singleton summary row
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
    except Exception:
        pass  # Don't block user sync if sign-in analysis fails

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

    data.last_synced_at = timezone.now()
    data.save()
    return True