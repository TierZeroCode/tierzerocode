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


def aal_02():
    """AAL-02: % of AAL2+ accounts with MFA enforced.

    AAL2 requires a multi-factor authenticator or two separate factors
    including "something you have." Any approved authenticator beyond
    password-only qualifies: FIDO2, WHfB, passkey, push, OTP.
    Phone/SMS counts as MFA (though restricted by ALM-06).

    Users with isMfaRegistered=False or no auth method registered = failing.

    Target: 100%
    """
    aal2_users = UserData.objects.filter(
        Q(isAdmin=True) | Q(persona__aal_level__gte=2)
    ).distinct()

    total = aal2_users.count()
    if total == 0:
        return ('-', 'not_measured')

    # Any MFA method registered counts
    any_mfa = (
        Q(passKeyDeviceBound_authentication_method=True) |
        Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
        Q(windowsHelloforBusiness_authentication_method=True) |
        Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
        Q(microsoftAuthenticatorPush_authentication_method=True) |
        Q(softwareOneTimePasscode_authentication_method=True) |
        Q(mobilePhone_authentication_method=True)
    )

    with_mfa = aal2_users.filter(any_mfa).distinct().count()
    pct = round(with_mfa / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{with_mfa}/{total} ({pct}%)', status)


def aal_02_detail():
    """Return detailed data for AAL-02: AAL2+ users and MFA registration status."""
    aal2_users = UserData.objects.filter(
        Q(isAdmin=True) | Q(persona__aal_level__gte=2)
    ).distinct()

    total = aal2_users.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_count': 0, 'failing_users': [], 'passing_users': [], 'logic': 'No AAL2+ users found.'}

    any_mfa = (
        Q(passKeyDeviceBound_authentication_method=True) |
        Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
        Q(windowsHelloforBusiness_authentication_method=True) |
        Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
        Q(microsoftAuthenticatorPush_authentication_method=True) |
        Q(softwareOneTimePasscode_authentication_method=True) |
        Q(mobilePhone_authentication_method=True)
    )

    passing_qs = aal2_users.filter(any_mfa).distinct()
    failing_qs = aal2_users.exclude(any_mfa).distinct()

    passing = list(passing_qs.values(
        'upn', 'given_name', 'surname', 'isAdmin', 'persona__persona_name',
        'persona__aal_level', 'isMfaRegistered', 'isMfaCapable',
        'highest_authentication_strength',
        'passKeyDeviceBound_authentication_method',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'windowsHelloforBusiness_authentication_method',
        'microsoftAuthenticatorPasswordless_authentication_method',
        'microsoftAuthenticatorPush_authentication_method',
        'softwareOneTimePasscode_authentication_method',
        'mobilePhone_authentication_method',
    )[:100])

    failing = list(failing_qs.values(
        'upn', 'given_name', 'surname', 'isAdmin', 'persona__persona_name',
        'persona__aal_level', 'isMfaRegistered', 'isMfaCapable',
        'highest_authentication_strength',
    )[:100])

    return {
        'total': total,
        'passing_count': passing_qs.count(),
        'failing_count': failing_qs.count(),
        'failing_users': failing,
        'passing_users': passing,
        'logic': 'AAL2+ users (persona AAL level >= 2 or isAdmin=True) must have at least one MFA method registered. Any approved authenticator qualifies: FIDO2, WHfB, passkey, MS Authenticator (push or passwordless), software OTP, or phone/SMS. Users with NO second factor registered are non-compliant.',
        'qualifying_methods': 'FIDO2, WHfB, Passkey, MS Authenticator Passwordless, MS Authenticator Push, Software OTP, Phone/SMS (all count as MFA — though phone/SMS is restricted by ALM-06)',
        'disqualifying_methods': 'No MFA method registered — password-only authentication does not meet AAL2',
    }


def aal_03():
    """AAL-03: % of AAL2+ accounts using phishing-resistant MFA.

    AAL2 users (persona aal_level >= 2, or isAdmin) must have at least one
    phishing-resistant authenticator: FIDO2 device-bound key, WHfB, or
    passkey (device-bound authenticator).

    Target: 100% for staff/contractors/partners
    """
    aal2_users = UserData.objects.filter(
        Q(isAdmin=True) | Q(persona__aal_level__gte=2)
    ).distinct()

    total = aal2_users.count()
    if total == 0:
        return ('-', 'not_measured')

    phishing_resistant = (
        Q(passKeyDeviceBound_authentication_method=True) |
        Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
        Q(windowsHelloforBusiness_authentication_method=True)
    )

    with_pr = aal2_users.filter(phishing_resistant).distinct().count()
    pct = round(with_pr / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{with_pr}/{total} ({pct}%)', status)


def aal_03_detail():
    """Return detailed data for AAL-03: AAL2+ users and phishing-resistant auth."""
    aal2_users = UserData.objects.filter(
        Q(isAdmin=True) | Q(persona__aal_level__gte=2)
    ).distinct()

    total = aal2_users.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_count': 0, 'failing_users': [], 'passing_users': [], 'logic': 'No AAL2+ users found.'}

    phishing_resistant = (
        Q(passKeyDeviceBound_authentication_method=True) |
        Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
        Q(windowsHelloforBusiness_authentication_method=True)
    )

    passing_qs = aal2_users.filter(phishing_resistant).distinct()
    failing_qs = aal2_users.exclude(phishing_resistant).distinct()

    passing = list(passing_qs.values(
        'upn', 'given_name', 'surname', 'isAdmin', 'persona__persona_name',
        'persona__aal_level',
        'passKeyDeviceBound_authentication_method',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'windowsHelloforBusiness_authentication_method',
        'highest_authentication_strength',
    )[:100])

    failing = list(failing_qs.values(
        'upn', 'given_name', 'surname', 'isAdmin', 'persona__persona_name',
        'persona__aal_level',
        'highest_authentication_strength',
        'microsoftAuthenticatorPush_authentication_method',
        'softwareOneTimePasscode_authentication_method',
        'mobilePhone_authentication_method',
    )[:100])

    return {
        'total': total,
        'passing_count': passing_qs.count(),
        'failing_count': failing_qs.count(),
        'failing_users': failing,
        'passing_users': passing,
        'logic': 'AAL2+ users (persona AAL level >= 2 or isAdmin=True) must have at least one phishing-resistant authenticator registered. FIDO2 device-bound keys, passkeys (Authenticator), and Windows Hello for Business all qualify as phishing-resistant per NIST SP 800-63B-4.',
        'qualifying_methods': 'FIDO2 device-bound key (passKeyDeviceBound), Passkey via Authenticator (passKeyDeviceBoundAuthenticator), Windows Hello for Business (windowsHelloforBusiness)',
        'disqualifying_methods': 'Push notifications, software OTP, phone/SMS, and email are NOT phishing-resistant — they are vulnerable to real-time phishing proxies',
    }


def aal_04():
    """AAL-04: % of privileged accounts using hardware-bound phishing-resistant auth.

    AAL3 requires cryptographic authenticators with non-exportable private keys.
    Hardware FIDO2 (passKeyDeviceBound) and WHfB with TPM qualify.
    Syncable passkeys (passKeyDeviceBoundAuthenticator) do NOT qualify.

    Targets AAL3 users: isAdmin=True OR persona AAL level >= 3.

    Target: 100%
    """
    privileged_users = UserData.objects.filter(
        Q(isAdmin=True) | Q(persona__aal_level__gte=3)
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
    privileged_users = UserData.objects.filter(
        Q(isAdmin=True) | Q(persona__aal_level__gte=3)
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
        'logic': 'AAL3 users (isAdmin=True or persona AAL level >= 3) must have hardware-bound phishing-resistant authenticators. FIDO2 device-bound keys and Windows Hello for Business qualify. Syncable passkeys do NOT qualify for AAL3.',
        'qualifying_methods': 'Hardware FIDO2 (passKeyDeviceBound) or Windows Hello for Business (windowsHelloforBusiness)',
        'disqualifying_methods': 'Syncable passkeys (passKeyDeviceBoundAuthenticator) do not meet AAL3 requirements.',
    }


def aal_05():
    """AAL-05: ALL enforced CA policies must have a session lifetime <= 30 days.

    Every enforced policy (state='enabled') must have sign-in frequency
    configured. Policies without session controls allow indefinite sessions,
    which violates the NIST requirement for a definite reauthentication timeout.

    Fails if ANY enforced policy is missing a session limit or has one > 30 days.

    Target: <= 30 days
    """
    enforced = ConditionalAccessPolicy.objects.filter(state='enabled')

    if not enforced.exists():
        all_synced = ConditionalAccessPolicy.objects.count()
        if all_synced == 0:
            return ('-', 'not_measured')
        return ('No enforced policies', 'not_measured')

    total_enforced = enforced.count()
    without_session = enforced.filter(
        Q(sign_in_frequency_enabled=False) | Q(sign_in_frequency_value__isnull=True)
    ).count()
    exceeds_30d = 0
    max_days = 0

    for policy in enforced.filter(sign_in_frequency_enabled=True).exclude(sign_in_frequency_value__isnull=True):
        days = policy.sign_in_frequency_days
        if days is not None:
            if days > max_days:
                max_days = days
            if days > 30:
                exceeds_30d += 1

    with_valid_session = total_enforced - without_session
    compliant = with_valid_session - exceeds_30d

    if without_session > 0 or exceeds_30d > 0:
        return (f'{compliant}/{total_enforced} compliant', 'failing')

    display = f'{int(max_days)} days' if max_days == int(max_days) else f'{max_days:.1f} days'
    return (f'{display} max ({total_enforced}/{total_enforced})', 'passing')


def aal_05_detail():
    """Return detailed data for AAL-05: all CA policies with session controls."""
    all_policies = ConditionalAccessPolicy.objects.all()
    enforced_policies = all_policies.filter(state='enabled')

    policies_data = []
    without_session_count = 0
    exceeds_30d_count = 0
    max_days = 0

    for p in all_policies:
        days = p.sign_in_frequency_days
        has_valid_session = p.sign_in_frequency_enabled and p.sign_in_frequency_value is not None

        # Track stats for enforced policies only
        if p.state == 'enabled':
            if not has_valid_session:
                without_session_count += 1
            elif days is not None and days > 30:
                exceeds_30d_count += 1
            if days is not None and days > max_days:
                max_days = days

        policies_data.append({
            'display_name': p.display_name,
            'state': p.state,
            'sign_in_frequency_enabled': p.sign_in_frequency_enabled,
            'sign_in_frequency_value': p.sign_in_frequency_value,
            'sign_in_frequency_type': p.sign_in_frequency_type,
            'sign_in_frequency_days': days,
            'persistent_browser_enabled': p.persistent_browser_enabled,
            'persistent_browser_mode': p.persistent_browser_mode,
            'grant_controls': p.grant_controls,
            'has_session_control': has_valid_session or p.persistent_browser_enabled,
            'is_compliant': p.state != 'enabled' or (has_valid_session and days is not None and days <= 30),
        })

    return {
        'total_all_policies': all_policies.count(),
        'total_enabled_policies': enforced_policies.count(),
        'without_session_count': without_session_count,
        'exceeds_30d_count': exceeds_30d_count,
        'max_session_days': max_days if max_days > 0 else None,
        'policies': policies_data,
        'logic': 'Every enforced policy (state="enabled") must have a sign-in frequency configured at <= 30 days. Policies without session controls allow indefinite sessions, which violates the NIST requirement for a definite reauthentication timeout. Report-only and disabled policies are shown but not evaluated.',
    }


def alm_06():
    """ALM-06: % of users with ONLY SMS/voice as their MFA method.

    Users who have mobilePhone as their only authentication method and
    no stronger alternative registered are at risk. NIST restricts
    PSTN authenticators and requires an alternative be available.

    Target: 0% (declining trend)
    """
    total = UserData.objects.count()
    if total == 0:
        return ('-', 'not_measured')

    # Stronger methods — any of these registered means the user is not SMS-only
    stronger_methods = (
        Q(passKeyDeviceBound_authentication_method=True) |
        Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
        Q(windowsHelloforBusiness_authentication_method=True) |
        Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
        Q(microsoftAuthenticatorPush_authentication_method=True) |
        Q(softwareOneTimePasscode_authentication_method=True)
    )

    # SMS-only: has phone but no stronger method
    sms_only = UserData.objects.filter(
        mobilePhone_authentication_method=True,
    ).exclude(stronger_methods).distinct().count()

    if sms_only == 0:
        return ('0 users', 'passing')

    pct = round(sms_only / total * 100, 1)
    return (f'{sms_only} users ({pct}%)', 'failing')


def alm_06_detail():
    """Return detailed data for ALM-06: users relying solely on SMS/voice."""
    total = UserData.objects.count()
    if total == 0:
        return {'total': 0, 'sms_only_count': 0, 'failing_users': [], 'logic': 'No users synced.'}

    stronger_methods = (
        Q(passKeyDeviceBound_authentication_method=True) |
        Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
        Q(windowsHelloforBusiness_authentication_method=True) |
        Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
        Q(microsoftAuthenticatorPush_authentication_method=True) |
        Q(softwareOneTimePasscode_authentication_method=True)
    )

    sms_only_users = UserData.objects.filter(
        mobilePhone_authentication_method=True,
    ).exclude(stronger_methods).distinct()

    sms_only_count = sms_only_users.count()

    failing = list(sms_only_users.values(
        'upn', 'given_name', 'surname', 'persona__persona_name',
        'highest_authentication_strength', 'lowest_authentication_strength',
        'mobilePhone_authentication_method',
        'email_authentication_method',
        'securityQuestion_authentication_method',
    )[:100])

    # Also show users who have phone + a stronger method (compliant)
    phone_with_stronger = UserData.objects.filter(
        mobilePhone_authentication_method=True,
    ).filter(stronger_methods).distinct()

    passing = list(phone_with_stronger.values(
        'upn', 'given_name', 'surname', 'persona__persona_name',
        'highest_authentication_strength',
        'mobilePhone_authentication_method',
        'passKeyDeviceBound_authentication_method',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'windowsHelloforBusiness_authentication_method',
        'microsoftAuthenticatorPasswordless_authentication_method',
        'microsoftAuthenticatorPush_authentication_method',
        'softwareOneTimePasscode_authentication_method',
    )[:100])

    return {
        'total': total,
        'sms_only_count': sms_only_count,
        'phone_with_stronger_count': phone_with_stronger.count(),
        'failing_count': sms_only_count,
        'passing_count': phone_with_stronger.count(),
        'failing_users': failing,
        'passing_users': passing,
        'logic': 'Users with mobilePhone (SMS/voice) as their ONLY authentication method, with no stronger alternative registered (FIDO2, WHfB, MS Authenticator, or software OTP). NIST SP 800-63B-4 restricts PSTN authenticators and requires at least one non-restricted alternative.',
        'qualifying_methods': 'Any of: FIDO2 key, Passkey (Authenticator), WHfB, MS Authenticator Passwordless, MS Authenticator Push, Software OTP',
        'disqualifying_methods': 'SMS/voice phone only — no alternative registered',
    }


def aal_09():
    """AAL-09: % of AAL3 accounts with intent-demonstrating authenticators.

    AAL3 users (isAdmin=True or persona AAL level >= 3) must have at least
    one authenticator that requires explicit user action:
    - FIDO2 key: physical tap (always demonstrates intent)
    - WHfB: biometric or PIN (always demonstrates intent)
    - MS Authenticator Push: requires number matching / user action
    - Software OTP: requires typing a code

    Users with ONLY phone/SMS/email do NOT demonstrate intent.

    Target: 100% for AAL3
    """
    aal3_users = UserData.objects.filter(
        Q(isAdmin=True) | Q(persona__aal_level__gte=3)
    ).distinct()

    total = aal3_users.count()
    if total == 0:
        return ('-', 'not_measured')

    # Intent-demonstrating methods
    intent_methods = (
        Q(passKeyDeviceBound_authentication_method=True) |
        Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
        Q(windowsHelloforBusiness_authentication_method=True) |
        Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
        Q(microsoftAuthenticatorPush_authentication_method=True) |
        Q(softwareOneTimePasscode_authentication_method=True)
    )

    with_intent = aal3_users.filter(intent_methods).distinct().count()
    pct = round(with_intent / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{with_intent}/{total} ({pct}%)', status)


def aal_09_detail():
    """Return detailed data for AAL-09: AAL3 users and their intent-demonstrating auth."""
    aal3_users = UserData.objects.filter(
        Q(isAdmin=True) | Q(persona__aal_level__gte=3)
    ).distinct()

    total = aal3_users.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_count': 0, 'failing_users': [], 'passing_users': [], 'logic': 'No AAL3 (privileged) users found.'}

    intent_methods = (
        Q(passKeyDeviceBound_authentication_method=True) |
        Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
        Q(windowsHelloforBusiness_authentication_method=True) |
        Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
        Q(microsoftAuthenticatorPush_authentication_method=True) |
        Q(softwareOneTimePasscode_authentication_method=True)
    )

    passing_qs = aal3_users.filter(intent_methods).distinct()
    failing_qs = aal3_users.exclude(intent_methods).distinct()

    passing = list(passing_qs.values(
        'upn', 'given_name', 'surname', 'isAdmin', 'persona__persona_name',
        'passKeyDeviceBound_authentication_method',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'windowsHelloforBusiness_authentication_method',
        'microsoftAuthenticatorPasswordless_authentication_method',
        'microsoftAuthenticatorPush_authentication_method',
        'softwareOneTimePasscode_authentication_method',
    )[:100])

    failing = list(failing_qs.values(
        'upn', 'given_name', 'surname', 'isAdmin', 'persona__persona_name',
        'highest_authentication_strength',
        'mobilePhone_authentication_method',
        'email_authentication_method',
        'temporaryAccessPass_authentication_method',
    )[:100])

    return {
        'total': total,
        'passing_count': passing_qs.count(),
        'failing_count': failing_qs.count(),
        'failing_users': failing,
        'passing_users': passing,
        'logic': 'AAL3 users (isAdmin=True or persona AAL level >= 3) must have at least one authenticator that requires explicit user action. FIDO2 keys (physical tap), WHfB (biometric/PIN), MS Authenticator Push (number matching), and software OTP (code entry) all demonstrate intent. Phone/SMS/email do not.',
        'qualifying_methods': 'FIDO2 key (tap), WHfB (biometric/PIN), MS Authenticator Passwordless, MS Authenticator Push (number matching), Software OTP (code entry)',
        'disqualifying_methods': 'Phone/SMS, email, and TAP alone do not demonstrate sufficient authentication intent for AAL3',
    }
