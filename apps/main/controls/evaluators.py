"""
Control evaluator functions.

Each function takes no arguments and returns a tuple of (current_value, status).
- current_value: string like '95%' or '142 / 150'
- status: one of 'passing', 'failing', 'not_measured'

The function name must match the Control.evaluator field value.
"""
from django.db.models import Q
from apps.main.models import UserData, Device, Integration, SignInSummary, Persona, ConditionalAccessPolicy
from apps.authhandler.models import SSOIntegration


def alm_01():
    """ALM-01: % of accounts with at least one authenticator registered at enrollment.

    Measures: UserData where at least one authentication method boolean is True.
    Target: 100%
    """
    total = UserData.objects.count()
    if total == 0:
        return ('-', 'not_measured')

    with_auth = UserData.objects.filter(
        Q(passKeyDeviceBound_authentication_method=True) |
        Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
        Q(windowsHelloforBusiness_authentication_method=True) |
        Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
        Q(microsoftAuthenticatorPush_authentication_method=True) |
        Q(softwareOneTimePasscode_authentication_method=True) |
        Q(mobilePhone_authentication_method=True)
    ).distinct().count()

    pct = round(with_auth / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{pct}%', status)


def alm_02():
    """ALM-02: % of MFA registration events that required prior AAL2+ auth.

    This cannot be directly measured from stored data — it requires
    checking Entra ID conditional access policies for security info
    registration. For now, check if any CA policy exists (via SignInSummary
    having CA data) as a proxy.

    Target: 100%
    """
    summary = SignInSummary.objects.first()
    if not summary or summary.total_signins == 0:
        return ('-', 'not_measured')

    # Proxy: if CA is applied to sign-ins, assume MFA reg also requires CA
    # This is a Tier 2 control that needs API data for full measurement
    total_ca = summary.ca_mfa + summary.ca_no_mfa
    total = summary.total_signins
    if total == 0:
        return ('-', 'not_measured')

    pct = round(total_ca / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{pct}%', status)


def aal_04():
    """AAL-04: % of privileged accounts using hardware-bound phishing-resistant auth.

    AAL3 requires cryptographic authenticators with non-exportable private keys.
    Hardware FIDO2 (passKeyDeviceBound) and WHfB with TPM qualify.
    Syncable passkeys (passKeyDeviceBoundAuthenticator) do NOT qualify.

    Targets privileged users: isAdmin=True OR persona name contains
    'Tier 0', 'Tier 1', 'Privileged', or 'Admin' (case-insensitive).

    Target: 100%
    """
    # Identify privileged users
    privileged_personas = Persona.objects.filter(
        Q(persona_name__icontains='Tier 0') |
        Q(persona_name__icontains='Tier 1') |
        Q(persona_name__icontains='Privileged') |
        Q(persona_name__icontains='Admin')
    )

    privileged_users = UserData.objects.filter(
        Q(isAdmin=True) | Q(persona__in=privileged_personas)
    ).distinct()

    total = privileged_users.count()
    if total == 0:
        return ('-', 'not_measured')

    # Hardware-bound phishing-resistant: FIDO2 device-bound OR WHfB
    # Explicitly exclude users who ONLY have syncable passkeys
    with_hardware_auth = privileged_users.filter(
        Q(passKeyDeviceBound_authentication_method=True) |
        Q(windowsHelloforBusiness_authentication_method=True)
    ).distinct().count()

    pct = round(with_hardware_auth / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{with_hardware_auth}/{total} ({pct}%)', status)


def alm_01_detail():
    """Return detailed data for ALM-01: users and their auth method status."""
    total = UserData.objects.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_users': [], 'passing_users': []}

    has_auth_q = (
        Q(passKeyDeviceBound_authentication_method=True) |
        Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
        Q(windowsHelloforBusiness_authentication_method=True) |
        Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
        Q(microsoftAuthenticatorPush_authentication_method=True) |
        Q(softwareOneTimePasscode_authentication_method=True) |
        Q(mobilePhone_authentication_method=True)
    )

    passing = UserData.objects.filter(has_auth_q).distinct().values(
        'upn', 'given_name', 'surname', 'highest_authentication_strength',
        'passKeyDeviceBound_authentication_method',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'windowsHelloforBusiness_authentication_method',
        'microsoftAuthenticatorPasswordless_authentication_method',
        'microsoftAuthenticatorPush_authentication_method',
        'softwareOneTimePasscode_authentication_method',
        'mobilePhone_authentication_method',
    )
    failing = UserData.objects.exclude(has_auth_q).values(
        'upn', 'given_name', 'surname', 'highest_authentication_strength',
    )

    return {
        'total': total,
        'passing_count': passing.count(),
        'failing_count': failing.count(),
        'failing_users': list(failing[:100]),
        'passing_users': list(passing[:100]),
        'logic': 'Users with at least one authentication method registered (passkey, WHfB, MS Authenticator, OTP, or phone).',
        'auth_fields': [
            ('passKeyDeviceBound_authentication_method', 'FIDO2 Security Key'),
            ('passKeyDeviceBoundAuthenticator_authentication_method', 'Passkey (Authenticator)'),
            ('windowsHelloforBusiness_authentication_method', 'Windows Hello for Business'),
            ('microsoftAuthenticatorPasswordless_authentication_method', 'MS Authenticator Passwordless'),
            ('microsoftAuthenticatorPush_authentication_method', 'MS Authenticator Push'),
            ('softwareOneTimePasscode_authentication_method', 'Software OTP'),
            ('mobilePhone_authentication_method', 'Mobile Phone'),
        ],
    }


def alm_02_detail():
    """Return detailed data for ALM-02."""
    summary = SignInSummary.objects.first()
    if not summary:
        return {'total': 0, 'logic': 'No sign-in data available.'}

    return {
        'total': summary.total_signins,
        'ca_mfa': summary.ca_mfa,
        'ca_no_mfa': summary.ca_no_mfa,
        'no_ca_mfa': summary.no_ca_mfa,
        'no_ca_no_mfa': summary.no_ca_no_mfa,
        'ca_applied': summary.ca_mfa + summary.ca_no_mfa,
        'logic': 'Proxy measurement: percentage of sign-ins where Conditional Access was applied. Full measurement requires checking CA policy for security info registration, which needs Microsoft Graph API data not currently stored.',
    }


def aal_04_detail():
    """Return detailed data for AAL-04: privileged users and their hardware auth status."""
    privileged_personas = Persona.objects.filter(
        Q(persona_name__icontains='Tier 0') |
        Q(persona_name__icontains='Tier 1') |
        Q(persona_name__icontains='Privileged') |
        Q(persona_name__icontains='Admin')
    )

    privileged_users = UserData.objects.filter(
        Q(isAdmin=True) | Q(persona__in=privileged_personas)
    ).distinct()

    total = privileged_users.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_users': [], 'passing_users': [], 'logic': 'No privileged users found.'}

    hw_auth_q = Q(passKeyDeviceBound_authentication_method=True) | Q(windowsHelloforBusiness_authentication_method=True)

    passing = privileged_users.filter(hw_auth_q).distinct().values(
        'upn', 'given_name', 'surname', 'isAdmin',
        'passKeyDeviceBound_authentication_method',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'windowsHelloforBusiness_authentication_method',
        'persona__persona_name',
    )
    failing = privileged_users.exclude(hw_auth_q).values(
        'upn', 'given_name', 'surname', 'isAdmin',
        'passKeyDeviceBound_authentication_method',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'windowsHelloforBusiness_authentication_method',
        'microsoftAuthenticatorPush_authentication_method',
        'softwareOneTimePasscode_authentication_method',
        'persona__persona_name',
    )

    return {
        'total': total,
        'passing_count': passing.count(),
        'failing_count': failing.count(),
        'failing_users': list(failing[:100]),
        'passing_users': list(passing[:100]),
        'logic': 'Privileged users (isAdmin=True or persona matching Tier 0/Tier 1/Privileged/Admin) must have hardware-bound phishing-resistant authenticators. FIDO2 device-bound keys and Windows Hello for Business qualify. Syncable passkeys do NOT qualify for AAL3.',
        'qualifying_methods': 'Hardware FIDO2 (passKeyDeviceBound) or Windows Hello for Business (windowsHelloforBusiness)',
        'disqualifying_methods': 'Syncable passkeys (passKeyDeviceBoundAuthenticator) do not meet AAL3 requirements.',
    }


def aal_05():
    """AAL-05: Maximum session lifetime for AAL1 should be <= 30 days.

    Checks all enabled CA policies that have sign-in frequency configured.
    If any policy enforces a session lifetime > 30 days, or if no policy
    enforces session lifetime at all, the control fails.

    Target: <= 30 days
    """
    policies = ConditionalAccessPolicy.objects.filter(
        state='enabled',
        sign_in_frequency_enabled=True,
    )

    if not policies.exists():
        # No session lifetime policy configured
        all_policies = ConditionalAccessPolicy.objects.filter(state='enabled').count()
        if all_policies == 0:
            return ('-', 'not_measured')
        return ('No session policy', 'failing')

    max_days = 0
    for policy in policies:
        days = policy.sign_in_frequency_days
        if days is not None and days > max_days:
            max_days = days

    if max_days <= 30:
        status = 'passing'
    else:
        status = 'failing'

    if max_days == int(max_days):
        return (f'{int(max_days)} days', status)
    return (f'{max_days:.1f} days', status)


def aal_05_detail():
    """Return detailed data for AAL-05: CA policies with session controls."""
    all_policies = ConditionalAccessPolicy.objects.filter(state='enabled')
    session_policies = all_policies.filter(sign_in_frequency_enabled=True)

    policies_data = []
    for p in all_policies:
        policies_data.append({
            'display_name': p.display_name,
            'state': p.state,
            'sign_in_frequency_enabled': p.sign_in_frequency_enabled,
            'sign_in_frequency_value': p.sign_in_frequency_value,
            'sign_in_frequency_type': p.sign_in_frequency_type,
            'sign_in_frequency_days': p.sign_in_frequency_days,
            'persistent_browser_enabled': p.persistent_browser_enabled,
            'persistent_browser_mode': p.persistent_browser_mode,
            'grant_controls': p.grant_controls,
            'has_session_control': p.sign_in_frequency_enabled or p.persistent_browser_enabled,
        })

    max_days = 0
    for p in session_policies:
        days = p.sign_in_frequency_days
        if days is not None and days > max_days:
            max_days = days

    return {
        'total_enabled_policies': all_policies.count(),
        'session_policies_count': session_policies.count(),
        'max_session_days': max_days,
        'policies': policies_data,
        'logic': 'Checks all enabled Conditional Access policies for sign-in frequency settings. AAL1 requires a reauthentication timeout of no more than 30 days. The maximum configured session lifetime across all policies is compared against the 30-day threshold.',
    }
