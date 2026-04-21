"""
Control evaluator functions.

Each function takes no arguments and returns a tuple of (current_value, status).
- current_value: string like '95%' or '142 / 150'
- status: one of 'passing', 'failing', 'not_measured'

The function name must match the Control.evaluator field value.
"""
from django.db.models import Q, Case, When, IntegerField, Value
from django.db.models.functions import Coalesce
from apps.main.models import UserData, Device, Integration, SignInSummary, Persona, ConditionalAccessPolicy, TenantSecurityConfig
from apps.authhandler.models import SSOIntegration


# ── Reusable query filters ──

def _get_users_by_aal(min_aal):
    """Get UserData queryset filtered by AAL level. isAdmin always counts as AAL3."""
    if min_aal <= 1:
        return UserData.objects.all()
    return UserData.objects.filter(
        Q(isAdmin=True) | Q(persona__aal_level__gte=min_aal)
    ).distinct()


# Any MFA method registered (AAL-02 baseline)
ANY_MFA_Q = (
    Q(passKeyDeviceBound_authentication_method=True) |
    Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
    Q(windowsHelloforBusiness_authentication_method=True) |
    Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
    Q(microsoftAuthenticatorPush_authentication_method=True) |
    Q(softwareOneTimePasscode_authentication_method=True) |
    Q(mobilePhone_authentication_method=True)
)

# Phishing-resistant methods (AAL-03: AAL2+)
PHISHING_RESISTANT_Q = (
    Q(passKeyDeviceBound_authentication_method=True) |
    Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
    Q(windowsHelloforBusiness_authentication_method=True)
)

# Hardware-bound phishing-resistant only (AAL-04: AAL3)
HARDWARE_BOUND_Q = (
    Q(passKeyDeviceBound_authentication_method=True) |
    Q(windowsHelloforBusiness_authentication_method=True)
)

# Replay-resistant methods (AAL-08) and intent-demonstrating (AAL-09) — same set
REPLAY_RESISTANT_Q = (
    Q(passKeyDeviceBound_authentication_method=True) |
    Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
    Q(windowsHelloforBusiness_authentication_method=True) |
    Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
    Q(microsoftAuthenticatorPush_authentication_method=True) |
    Q(softwareOneTimePasscode_authentication_method=True)
)

# Stronger methods (everything except phone/SMS — used by ALM-06)
STRONGER_THAN_SMS_Q = (
    Q(passKeyDeviceBound_authentication_method=True) |
    Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
    Q(windowsHelloforBusiness_authentication_method=True) |
    Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
    Q(microsoftAuthenticatorPush_authentication_method=True) |
    Q(softwareOneTimePasscode_authentication_method=True)
)


def alm_01():
    """ALM-01: % of accounts with at least one authenticator registered at enrollment.

    Measures: UserData where at least one authentication method boolean is True.
    Target: 100%
    """
    total = UserData.objects.count()
    if total == 0:
        return ('-', 'not_measured')

    with_auth = UserData.objects.filter(ANY_MFA_Q).distinct().count()

    pct = round(with_auth / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{pct}%', status)


def alm_03():
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
    aal2_users = _get_users_by_aal(2)

    total = aal2_users.count()
    if total == 0:
        return ('-', 'not_measured')

    with_mfa = aal2_users.filter(ANY_MFA_Q).distinct().count()
    pct = round(with_mfa / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{with_mfa}/{total} ({pct}%)', status)


def aal_02_detail():
    """Return detailed data for AAL-02: AAL2+ users and MFA registration status."""
    aal2_users = _get_users_by_aal(2)

    total = aal2_users.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_count': 0, 'failing_users': [], 'passing_users': [], 'logic': 'No AAL2+ users found.'}

    passing_qs = aal2_users.filter(ANY_MFA_Q).distinct()
    failing_qs = aal2_users.exclude(ANY_MFA_Q).distinct()

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


def aal_05():
    """AAL-05: % of AAL2+ accounts using phishing-resistant MFA.

    AAL2 users (persona aal_level >= 2, or isAdmin) must have at least one
    phishing-resistant authenticator: FIDO2 device-bound key, WHfB, or
    passkey (device-bound authenticator).

    Target: 100% for staff/contractors/partners
    """
    aal2_users = _get_users_by_aal(2)

    total = aal2_users.count()
    if total == 0:
        return ('-', 'not_measured')

    with_pr = aal2_users.filter(PHISHING_RESISTANT_Q).distinct().count()
    pct = round(with_pr / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{with_pr}/{total} ({pct}%)', status)


def aal_05_detail():
    """Return detailed data for AAL-05: AAL2+ users and phishing-resistant auth."""
    aal2_users = _get_users_by_aal(2)

    total = aal2_users.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_count': 0, 'failing_users': [], 'passing_users': [], 'logic': 'No AAL2+ users found.'}

    passing_qs = aal2_users.filter(PHISHING_RESISTANT_Q).distinct()
    failing_qs = aal2_users.exclude(PHISHING_RESISTANT_Q).distinct()

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
    privileged_users = _get_users_by_aal(3)

    total = privileged_users.count()
    if total == 0:
        return ('-', 'not_measured')

    # Hardware-bound phishing-resistant: FIDO2 device-bound OR WHfB
    # Explicitly exclude users who ONLY have syncable passkeys
    with_hardware_auth = privileged_users.filter(HARDWARE_BOUND_Q).distinct().count()

    pct = round(with_hardware_auth / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{with_hardware_auth}/{total} ({pct}%)', status)


def alm_01_detail():
    """Return detailed data for ALM-01: users and their auth method status."""
    total = UserData.objects.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_users': [], 'passing_users': []}

    passing = UserData.objects.filter(ANY_MFA_Q).distinct().values(
        'upn', 'given_name', 'surname', 'highest_authentication_strength',
        'passKeyDeviceBound_authentication_method',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'windowsHelloforBusiness_authentication_method',
        'microsoftAuthenticatorPasswordless_authentication_method',
        'microsoftAuthenticatorPush_authentication_method',
        'softwareOneTimePasscode_authentication_method',
        'mobilePhone_authentication_method',
    )
    failing = UserData.objects.exclude(ANY_MFA_Q).values(
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


_ALL_AUTH_FIELDS = [
    'passKeyDeviceBound_authentication_method',
    'passKeyDeviceBoundAuthenticator_authentication_method',
    'windowsHelloforBusiness_authentication_method',
    'microsoftAuthenticatorPasswordless_authentication_method',
    'microsoftAuthenticatorPush_authentication_method',
    'softwareOneTimePasscode_authentication_method',
    'temporaryAccessPass_authentication_method',
    'mobilePhone_authentication_method',
    'email_authentication_method',
    'securityQuestion_authentication_method',
]


def _annotate_method_count(qs):
    """Annotate queryset with a count of True auth method fields per user."""
    expr = Value(0, output_field=IntegerField())
    for field in _ALL_AUTH_FIELDS:
        expr = expr + Case(When(**{field: True}, then=1), default=0, output_field=IntegerField())
    return qs.annotate(method_count=expr)


def alm_02():
    """ALM-02: % of accounts with >= 2 registered authentication methods.

    NIST 800-63B-4 § 4.1.2.1: CSPs SHOULD encourage subscribers to maintain
    at least two separate means of authentication.

    Target: >90%
    """
    total = UserData.objects.count()
    if total == 0:
        return ('-', 'not_measured')

    with_two = _annotate_method_count(UserData.objects.all()).filter(method_count__gte=2).count()
    pct = round(with_two / total * 100)
    status = 'passing' if pct > 90 else 'failing'
    return (f'{with_two}/{total} ({pct}%)', status)


def alm_02_detail():
    """Return detailed data for ALM-02: accounts with >= 2 auth methods."""
    total = UserData.objects.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_count': 0, 'failing_users': [], 'passing_users': [], 'logic': 'No users synced.'}

    annotated = _annotate_method_count(UserData.objects.all())
    passing_qs = annotated.filter(method_count__gte=2)
    failing_qs = annotated.filter(method_count__lt=2)

    common_fields = (
        'upn', 'given_name', 'surname', 'persona__persona_name',
        'highest_authentication_strength', 'isMfaRegistered',
        'passKeyDeviceBound_authentication_method',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'windowsHelloforBusiness_authentication_method',
        'microsoftAuthenticatorPasswordless_authentication_method',
        'microsoftAuthenticatorPush_authentication_method',
        'softwareOneTimePasscode_authentication_method',
        'mobilePhone_authentication_method',
        'email_authentication_method',
    )

    return {
        'total': total,
        'passing_count': passing_qs.count(),
        'failing_count': failing_qs.count(),
        'failing_users': list(failing_qs.values(*common_fields)[:100]),
        'passing_users': list(passing_qs.values(*common_fields)[:100]),
        'logic': 'NIST 800-63B-4 § 4.1.2.1: CSPs SHALL permit and SHOULD encourage binding of multiple authenticators. This measures accounts with at least 2 distinct authentication methods registered. Target: >90%.',
        'qualifying_methods': 'All 10 Entra ID auth method types count: FIDO2, Passkey, WHfB, MS Authenticator (passwordless), MS Authenticator (push), Software OTP, Temporary Access Pass, Mobile Phone, Email, Security Questions',
        'threshold': '>90%',
    }


def alm_03_detail():
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
    privileged_users = _get_users_by_aal(3)

    total = privileged_users.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_users': [], 'passing_users': [], 'logic': 'No privileged users found.'}

    passing = privileged_users.filter(HARDWARE_BOUND_Q).distinct().values(
        'upn', 'given_name', 'surname', 'isAdmin',
        'passKeyDeviceBound_authentication_method',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'windowsHelloforBusiness_authentication_method',
        'persona__persona_name',
    )
    failing = privileged_users.exclude(HARDWARE_BOUND_Q).values(
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


def aal_12():
    """AAL-12: ALL enforced CA policies must have a session lifetime <= 30 days.

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


def aal_12_detail():
    """Return detailed data for AAL-12: all CA policies with session controls."""
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

    # SMS-only: has phone but no stronger method
    sms_only = UserData.objects.filter(
        mobilePhone_authentication_method=True,
    ).exclude(STRONGER_THAN_SMS_Q).distinct().count()

    if sms_only == 0:
        return ('0 users', 'passing')

    pct = round(sms_only / total * 100, 1)
    return (f'{sms_only} users ({pct}%)', 'failing')


def alm_06_detail():
    """Return detailed data for ALM-06: users relying solely on SMS/voice."""
    total = UserData.objects.count()
    if total == 0:
        return {'total': 0, 'sms_only_count': 0, 'failing_users': [], 'logic': 'No users synced.'}

    sms_only_users = UserData.objects.filter(
        mobilePhone_authentication_method=True,
    ).exclude(STRONGER_THAN_SMS_Q).distinct()

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
    ).filter(STRONGER_THAN_SMS_Q).distinct()

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
    aal3_users = _get_users_by_aal(3)

    total = aal3_users.count()
    if total == 0:
        return ('-', 'not_measured')

    with_intent = aal3_users.filter(REPLAY_RESISTANT_Q).distinct().count()
    pct = round(with_intent / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{with_intent}/{total} ({pct}%)', status)


def aal_09_detail():
    """Return detailed data for AAL-09: AAL3 users and their intent-demonstrating auth."""
    aal3_users = _get_users_by_aal(3)

    total = aal3_users.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_count': 0, 'failing_users': [], 'passing_users': [], 'logic': 'No AAL3 (privileged) users found.'}

    passing_qs = aal3_users.filter(REPLAY_RESISTANT_Q).distinct()
    failing_qs = aal3_users.exclude(REPLAY_RESISTANT_Q).distinct()

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


def aal_08():
    """AAL-08: % of AAL2+ users with replay-resistant authenticators.

    Replay-resistant methods use challenge-response or single-use codes
    that cannot be captured and reused:
    - FIDO2: challenge-response with nonce (replay-resistant)
    - WHfB: challenge-response with TPM (replay-resistant)
    - Passkey: challenge-response (replay-resistant)
    - MS Authenticator Passwordless: single-use challenge (replay-resistant)
    - MS Authenticator Push: single-use notification (replay-resistant)
    - Software OTP (TOTP): time-based single-use codes (replay-resistant)
    - Phone/SMS: codes can be intercepted and replayed (NOT replay-resistant)
    - Email: codes can be intercepted (NOT replay-resistant)

    Target: 100%
    """
    aal2_users = _get_users_by_aal(2)

    total = aal2_users.count()
    if total == 0:
        return ('-', 'not_measured')

    with_rr = aal2_users.filter(REPLAY_RESISTANT_Q).distinct().count()
    pct = round(with_rr / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{with_rr}/{total} ({pct}%)', status)


def aal_08_detail():
    """Return detailed data for AAL-08: AAL2+ users and replay resistance."""
    aal2_users = _get_users_by_aal(2)

    total = aal2_users.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_count': 0, 'failing_users': [], 'passing_users': [], 'logic': 'No AAL2+ users found.'}

    passing_qs = aal2_users.filter(REPLAY_RESISTANT_Q).distinct()
    failing_qs = aal2_users.exclude(REPLAY_RESISTANT_Q).distinct()

    passing = list(passing_qs.values(
        'upn', 'given_name', 'surname', 'isAdmin', 'persona__persona_name',
        'persona__aal_level',
        'passKeyDeviceBound_authentication_method',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'windowsHelloforBusiness_authentication_method',
        'microsoftAuthenticatorPasswordless_authentication_method',
        'microsoftAuthenticatorPush_authentication_method',
        'softwareOneTimePasscode_authentication_method',
    )[:100])

    failing = list(failing_qs.values(
        'upn', 'given_name', 'surname', 'isAdmin', 'persona__persona_name',
        'persona__aal_level',
        'highest_authentication_strength',
        'mobilePhone_authentication_method',
        'email_authentication_method',
    )[:100])

    return {
        'total': total,
        'passing_count': passing_qs.count(),
        'failing_count': failing_qs.count(),
        'failing_users': failing,
        'passing_users': passing,
        'logic': 'AAL2+ users (persona AAL level >= 2 or isAdmin=True) must have at least one replay-resistant authenticator. Challenge-response methods (FIDO2, WHfB, passkey) and single-use methods (push, TOTP) are replay-resistant. Phone/SMS and email codes can be intercepted and replayed within their validity window, so they are NOT replay-resistant.',
        'qualifying_methods': 'FIDO2 (challenge-response), WHfB (challenge-response), Passkey (challenge-response), MS Authenticator Passwordless (single-use challenge), MS Authenticator Push (single-use notification), Software OTP/TOTP (time-based single-use)',
        'disqualifying_methods': 'Phone/SMS codes (interceptable, replayable within validity window), Email codes (interceptable)',
    }


def pwd_10():
    """PWD-10: Password blocklist enforcement.

    Checks that Entra ID Password Protection is enabled with:
    1. Global banned password list enabled (EnableBannedPasswordCheck)
    2. Enforcement mode is 'Enforce' (not 'Audit')
    3. Optionally: custom banned password list configured

    Target: Enabled on all endpoints
    """
    config = TenantSecurityConfig.objects.first()
    if not config:
        return ('-', 'not_measured')

    issues = []
    if not config.password_protection_enabled:
        issues.append('Global banned list disabled')
    if config.password_protection_mode != 'Enforce':
        issues.append(f'Mode is "{config.password_protection_mode}" (should be Enforce)')

    if issues:
        return ('; '.join(issues), 'failing')

    extras = []
    if config.custom_banned_passwords_enabled:
        extras.append('custom list active')
    if config.password_protection_on_premises_enabled:
        extras.append('on-prem enabled')

    status_parts = ['Enforced']
    if extras:
        status_parts.append(', '.join(extras))

    return (' + '.join(status_parts), 'passing')


def pwd_10_detail():
    """Return detailed data for PWD-10: password protection configuration."""
    config = TenantSecurityConfig.objects.first()
    if not config:
        return {
            'total': 0,
            'logic': 'No tenant security configuration synced. Sync Entra ID users to populate.',
        }

    checks = [
        {
            'check': 'Global Banned Password List',
            'status': config.password_protection_enabled,
            'detail': 'Enabled' if config.password_protection_enabled else 'Disabled',
            'required': True,
        },
        {
            'check': 'Enforcement Mode',
            'status': config.password_protection_mode == 'Enforce',
            'detail': config.password_protection_mode or 'Not set',
            'required': True,
        },
        {
            'check': 'Custom Banned Password List',
            'status': config.custom_banned_passwords_enabled,
            'detail': f"Enabled ({len(config.custom_banned_password_list or [])} words)" if config.custom_banned_passwords_enabled else 'Disabled',
            'required': False,
        },
        {
            'check': 'On-Premises Password Protection',
            'status': config.password_protection_on_premises_enabled,
            'detail': 'Enabled' if config.password_protection_on_premises_enabled else 'Disabled',
            'required': False,
        },
    ]

    all_required_pass = all(c['status'] for c in checks if c['required'])

    return {
        'checks': checks,
        'all_required_pass': all_required_pass,
        'synced_at': config.synced_at,
        'logic': 'NIST SP 800-63B-4 requires passwords to be checked against a blocklist of known compromised passwords. Entra ID Password Protection provides a global banned password list (Microsoft-maintained) and optional custom banned passwords. Enforcement mode must be "Enforce" (not "Audit") to actively block weak passwords.',
    }


def pwd_08():
    """PWD-08: No KBA for Passwords — count of users with security questions registered.

    NIST 800-63B-4 § 3.1.1.2(8) prohibits knowledge-based authentication
    (security questions) in password flows. Measures the number of users in
    Entra ID who have the securityQuestion authentication method registered.

    Target: 0
    """
    total = UserData.objects.count()
    if total == 0:
        return ('-', 'not_measured')

    with_kba = UserData.objects.filter(securityQuestion_authentication_method=True).count()

    if with_kba == 0:
        return ('0', 'passing')
    return (str(with_kba), 'failing')


def pwd_08_detail():
    """Return detailed data for PWD-08: users with security questions registered."""
    total = UserData.objects.count()
    if total == 0:
        return {'total': 0, 'kba_count': 0, 'failing_users': [], 'logic': 'No users synced.'}

    kba_users = UserData.objects.filter(securityQuestion_authentication_method=True)
    kba_count = kba_users.count()

    failing = list(kba_users.values(
        'upn', 'given_name', 'surname', 'persona__persona_name',
        'highest_authentication_strength', 'securityQuestion_authentication_method',
    )[:100])

    return {
        'total': total,
        'kba_count': kba_count,
        'failing_count': kba_count,
        'passing_count': total - kba_count,
        'failing_users': failing,
        'logic': 'NIST 800-63B-4 § 3.1.1.2(8) prohibits verifiers from prompting subscribers to use knowledge-based authentication (security questions) when choosing passwords. Any user with the securityQuestion authentication method registered represents a non-compliant application or SSPR configuration.',
        'qualifying_methods': 'No security questions registered',
        'disqualifying_methods': 'securityQuestion authentication method registered',
    }
