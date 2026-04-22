"""
Control evaluator functions.

Each function takes no arguments and returns a tuple of (current_value, status).
- current_value: string like '95%' or '142 / 150'
- status: one of 'passing', 'failing', 'not_measured'

The function name must match the Control.evaluator field value.
"""
from django.db.models import Q, Case, When, IntegerField, Value
from django.db.models.functions import Coalesce
from apps.main.models import UserData, Device, Integration, SignInSummary, Persona, ConditionalAccessPolicy, TenantSecurityConfig, TenantAuthMethodsPolicy
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

# NIST-standard authenticators for AAL1 (excludes email OTP and security questions,
# which are not formally categorized as NIST authenticator types at AAL1).
# Any user who has registered for MFA but has ONLY email/KBA is flagged.
AAL1_STANDARD_Q = (
    Q(passKeyDeviceBound_authentication_method=True) |
    Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
    Q(windowsHelloforBusiness_authentication_method=True) |
    Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
    Q(microsoftAuthenticatorPush_authentication_method=True) |
    Q(softwareOneTimePasscode_authentication_method=True) |
    Q(mobilePhone_authentication_method=True)
)

# Users registered for MFA but whose only registered methods are email OTP
# and/or security questions — not formal NIST authenticator types.
AAL1_WEAK_ONLY_Q = (
    Q(isMfaRegistered=True) &
    ~Q(passKeyDeviceBound_authentication_method=True) &
    ~Q(passKeyDeviceBoundAuthenticator_authentication_method=True) &
    ~Q(windowsHelloforBusiness_authentication_method=True) &
    ~Q(microsoftAuthenticatorPasswordless_authentication_method=True) &
    ~Q(microsoftAuthenticatorPush_authentication_method=True) &
    ~Q(softwareOneTimePasscode_authentication_method=True) &
    ~Q(mobilePhone_authentication_method=True) &
    (Q(email_authentication_method=True) | Q(securityQuestion_authentication_method=True))
)


def aal_03():
    """AAL-03: % of users with at least one NIST-approved AAL1 authenticator type.

    NIST 800-63B-4 § 2.1.1 permits these authenticator types at AAL1:
    memorized secret (password), look-up secret, OOB device, SF/MF OTP,
    SF/MF crypto device. Email OTP and security questions are not formally
    categorized NIST authenticator types and do not satisfy the requirement
    on their own.

    Measurement: flags users who have registered for MFA but whose ONLY
    registered methods are email OTP and/or security questions — indicating
    the user's second factor falls outside the approved type list.

    Policy gate: if email OTP is disabled at the tenant auth methods policy level,
    user registrations using it are inert — the user cannot actually authenticate
    with email OTP regardless of what's registered. The control passes if email OTP
    is disabled at the policy level (assuming no other weak-only registrations remain).

    Target: 100%
    """
    total = UserData.objects.filter(isMfaRegistered=True).count()
    if total == 0:
        return ('-', 'not_measured')

    policy = TenantAuthMethodsPolicy.objects.filter(id=1).first()
    email_otp_policy_enabled = policy.email_otp_enabled if policy else True

    weak_only = UserData.objects.filter(AAL1_WEAK_ONLY_Q).count()

    # If email OTP is disabled at policy level, registered email methods are inert.
    # Re-count: only users whose sole weak method is email OTP (not securityQuestion) benefit.
    if not email_otp_policy_enabled:
        # Users who are weak-only because of email OTP alone are now effectively compliant.
        # Weak-only due to security questions still fail (securityQuestion has no policy disable).
        email_only_weak = UserData.objects.filter(
            AAL1_WEAK_ONLY_Q,
            email_authentication_method=True,
            securityQuestion_authentication_method=False,
        ).count()
        weak_only = weak_only - email_only_weak

    compliant = total - weak_only
    pct = round(compliant / total * 100)
    status = 'passing' if weak_only == 0 else 'failing'
    return (f'{compliant}/{total} ({pct}%)', status)


def aal_03_detail():
    """Return detailed data for AAL-03: AAL1 authenticator type compliance."""
    total = UserData.objects.filter(isMfaRegistered=True).count()
    if total == 0:
        return {
            'total': 0, 'passing_count': 0, 'failing_count': 0,
            'failing_users': [], 'passing_users': [],
            'logic': 'No users with MFA registered found.',
        }

    policy = TenantAuthMethodsPolicy.objects.filter(id=1).first()
    email_otp_policy_enabled = policy.email_otp_enabled if policy else True

    passing_qs = UserData.objects.filter(isMfaRegistered=True).filter(AAL1_STANDARD_Q).distinct()
    failing_qs = UserData.objects.filter(AAL1_WEAK_ONLY_Q).distinct()

    # If email OTP is policy-disabled, email-only weak registrations are inert
    if not email_otp_policy_enabled:
        failing_qs = failing_qs.exclude(
            email_authentication_method=True,
            securityQuestion_authentication_method=False,
        )

    passing = list(passing_qs.values(
        'upn', 'given_name', 'surname', 'isAdmin', 'persona__persona_name',
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
        'email_authentication_method',
        'securityQuestion_authentication_method',
        'highest_authentication_strength',
    )[:100])

    policy_note = ''
    if policy:
        if not email_otp_policy_enabled:
            policy_note = ' Email OTP is DISABLED at the tenant policy level — users with email OTP registered cannot use it to authenticate.'
        else:
            policy_note = ' Email OTP is enabled at the tenant policy level.'

    return {
        'total': total,
        'passing_count': passing_qs.count(),
        'failing_count': failing_qs.count(),
        'failing_users': failing,
        'passing_users': passing,
        'policy': {
            'email_otp_enabled': email_otp_policy_enabled,
            'synced_at': policy.synced_at.isoformat() if policy else None,
        },
        'logic': (
            'Users registered for MFA are checked for at least one NIST-recognized authenticator type '
            '(FIDO2, WHfB, passkey, MS Authenticator push/passwordless, software OTP, or phone/SMS). '
            'Email OTP and security questions are not formally categorized as NIST authenticator types '
            'under 800-63B-4 § 2.1.1 and do not satisfy the AAL1 requirement on their own.'
            + policy_note +
            ' Password-only users are implicitly compliant (memorized secret is an approved AAL1 type) '
            'and are excluded from this check.'
        ),
        'qualifying_methods': 'Password (implicit), FIDO2, WHfB, Passkey, MS Authenticator Passwordless/Push, Software OTP, Phone/SMS',
        'disqualifying_methods': 'Email OTP and security questions as sole registered second factors (not NIST authenticator types)',
    }


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

    800-63B-4 § 2.2.2: verifiers SHALL offer at least one phishing-resistant
    option at AAL2. Measures % of AAL2+ users who have at least one
    phishing-resistant authenticator registered (FIDO2 device-bound key,
    WHfB, or Authenticator passkey).

    Target: 100%
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
        'logic': 'AAL2+ users (persona AAL level >= 2 or isAdmin=True) must have at least one phishing-resistant authenticator registered. FIDO2 device-bound keys, Authenticator passkeys, and Windows Hello for Business qualify at AAL2 per NIST SP 800-63B-4 § 2.2.2.',
        'qualifying_methods': 'FIDO2 device-bound key (passKeyDeviceBound), Passkey via Authenticator (passKeyDeviceBoundAuthenticator), Windows Hello for Business (windowsHelloforBusiness)',
        'disqualifying_methods': 'Push notifications, software OTP, phone/SMS, and email are NOT phishing-resistant',
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


def aal_04_detail():
    """Return detailed data for AAL-04: AAL3 users and hardware-bound auth."""
    privileged_users = _get_users_by_aal(3)

    total = privileged_users.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_count': 0, 'failing_users': [], 'passing_users': [], 'logic': 'No AAL3 (privileged) users found.'}

    passing_qs = privileged_users.filter(HARDWARE_BOUND_Q).distinct()
    failing_qs = privileged_users.exclude(HARDWARE_BOUND_Q).distinct()

    common_fields = (
        'upn', 'given_name', 'surname', 'isAdmin', 'persona__persona_name',
        'passKeyDeviceBound_authentication_method',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'windowsHelloforBusiness_authentication_method',
        'highest_authentication_strength',
    )

    return {
        'total': total,
        'passing_count': passing_qs.count(),
        'failing_count': failing_qs.count(),
        'failing_users': list(failing_qs.values(*common_fields)[:100]),
        'passing_users': list(passing_qs.values(*common_fields)[:100]),
        'logic': 'AAL3 users (isAdmin=True or persona AAL level >= 3) must have at least one hardware-bound, non-exportable authenticator. Hardware FIDO2 security keys and WHfB (with TPM) are hardware-bound. Syncable passkeys (MS Authenticator) are software-backed and do not qualify.',
        'qualifying_methods': 'passKeyDeviceBound (hardware FIDO2 security key with SE/TPM), windowsHelloforBusiness (TPM 2.0 bound)',
        'disqualifying_methods': 'passKeyDeviceBoundAuthenticator (device-bound but software keychain — syncable), MS Authenticator push, OTP, phone/SMS',
    }


def phr_04():
    """PHR-04: % of AAL3 users with hardware-protected, non-exportable key authenticators.

    NIST 800-63B-4 § 3.2.13: the authenticator SHALL be a separate piece of hardware
    or an embedded processor (SE, TEE, or TPM) that provides a protected execution
    environment. The authenticator SHALL prohibit export of the authentication secret
    to the host processor.

    In Entra ID:
    - passKeyDeviceBound (hardware FIDO2): private key generated in SE/TPM,
      certified via attestation, never leaves hardware — compliant.
    - windowsHelloforBusiness: private key bound to TPM 2.0, non-exportable — compliant.
    - passKeyDeviceBoundAuthenticator (MS Authenticator passkey): stored in software
      keychain, backed up to cloud — keys are device-bound but NOT hardware-isolated;
      not compliant with § 3.2.13.
    - All software authenticators (OTP, push, phone): exportable — not compliant.

    Target: 100% for T0/T1
    """
    aal3_users = _get_users_by_aal(3)

    total = aal3_users.count()
    if total == 0:
        return ('-', 'not_measured')

    with_hw = aal3_users.filter(HARDWARE_BOUND_Q).distinct().count()
    pct = round(with_hw / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{with_hw}/{total} ({pct}%)', status)


def phr_04_detail():
    """Return detailed data for PHR-04: AAL3 users and non-exportable key compliance."""
    aal3_users = _get_users_by_aal(3)

    total = aal3_users.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_count': 0, 'failing_users': [], 'passing_users': [], 'logic': 'No AAL3 (T0/T1) users found.'}

    passing_qs = aal3_users.filter(HARDWARE_BOUND_Q).distinct()
    failing_qs = aal3_users.exclude(HARDWARE_BOUND_Q).distinct()

    passing = list(passing_qs.values(
        'upn', 'given_name', 'surname', 'isAdmin', 'persona__persona_name',
        'passKeyDeviceBound_authentication_method',
        'windowsHelloforBusiness_authentication_method',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'highest_authentication_strength',
    )[:100])

    failing = list(failing_qs.values(
        'upn', 'given_name', 'surname', 'isAdmin', 'persona__persona_name',
        'passKeyDeviceBoundAuthenticator_authentication_method',
        'microsoftAuthenticatorPasswordless_authentication_method',
        'microsoftAuthenticatorPush_authentication_method',
        'softwareOneTimePasscode_authentication_method',
        'mobilePhone_authentication_method',
        'highest_authentication_strength',
    )[:100])

    return {
        'total': total,
        'passing_count': passing_qs.count(),
        'failing_count': failing_qs.count(),
        'failing_users': failing,
        'passing_users': passing,
        'logic': (
            'NIST 800-63B-4 § 3.2.13 requires AAL3 authenticators to use a separate hardware module '
            '(SE, TEE, or TPM) that prevents export of the private key to the host processor. '
            'Hardware FIDO2 security keys generate and store private keys inside a certified SE/TPM — '
            'the key never leaves the device. WHfB private keys are bound to the platform TPM 2.0 '
            'and cannot be exported. MS Authenticator passkeys (passKeyDeviceBoundAuthenticator) are '
            'device-bound but backed up to iCloud/Google cloud — the private key material is exportable '
            'and does not meet the hardware isolation requirement. All software authenticators are disqualified.'
        ),
        'qualifying_methods': (
            'passKeyDeviceBound: hardware FIDO2 key (YubiKey, Feitian, etc.) with SE/TPM attestation; '
            'windowsHelloforBusiness: WHfB with TPM 2.0 chip (non-exportable by TPM design)'
        ),
        'disqualifying_methods': (
            'passKeyDeviceBoundAuthenticator: MS Authenticator passkey (software keychain, cloud-backed); '
            'all push/OTP/phone/SMS methods (software, exportable)'
        ),
        'attestation_note': 'Full compliance verification requires FIDO2 attestation certificate review and TPM 2.0 inventory — user registration data is a proxy indicator.',
    }


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
    """AAL-09: Number of AAL3 accounts with syncable passkeys registered.

    NIST 800-63B-4 § 2.3.2: syncable authenticators SHALL NOT be used at AAL3.

    Microsoft Graph distinguishes three passkey types in methodsRegistered:
      passKeyDeviceBound          → Passkey (other device-bound) — hardware FIDO2 key, never syncs
      passKeyDeviceBoundAuthenticator → Passkey (Microsoft Authenticator) — device-resident, not classified as synced
      passkey                     → Passkey (Synced) — explicitly cloud-synced (iCloud, Google, 1Password, etc.)

    Only passKeySynced is definitively syncable. passKeyDeviceBoundAuthenticator
    is device-resident in the Authenticator app and Microsoft does not classify it
    as a synced passkey in reporting.

    Target: 0
    """
    aal3_users = _get_users_by_aal(3)
    total = aal3_users.count()
    if total == 0:
        return ('-', 'not_measured')

    SYNCABLE_Q = Q(passKeySynced_authentication_method=True)
    with_syncable = aal3_users.filter(SYNCABLE_Q).count()
    status = 'passing' if with_syncable == 0 else 'failing'
    return (str(with_syncable), status)


def aal_09_detail():
    """Return detailed data for AAL-09: AAL3 users with syncable passkeys."""
    aal3_users = _get_users_by_aal(3)
    total = aal3_users.count()
    if total == 0:
        return {'total': 0, 'failing_count': 0, 'failing_users': [], 'passing_count': 0, 'logic': 'No AAL3 (privileged) users found.'}

    SYNCABLE_Q = Q(passKeySynced_authentication_method=True)
    failing_qs = aal3_users.filter(SYNCABLE_Q)
    passing_qs = aal3_users.exclude(SYNCABLE_Q)

    common = ('upn', 'given_name', 'surname', 'isAdmin', 'persona__persona_name',
              'passKeyDeviceBound_authentication_method',
              'passKeyDeviceBoundAuthenticator_authentication_method',
              'passKeySynced_authentication_method',
              'windowsHelloforBusiness_authentication_method')

    return {
        'total': total,
        'failing_count': failing_qs.count(),
        'passing_count': passing_qs.count(),
        'failing_users': list(failing_qs.values(*common)[:100]),
        'passing_users': list(passing_qs.values(*common)[:100]),
        'logic': (
            'NIST 800-63B-4 § 2.3.2: syncable authenticators SHALL NOT be used at AAL3. '
            'Microsoft Graph reports three passkey types: Passkey (other device-bound) = hardware FIDO2 key (permitted); '
            'Passkey (Microsoft Authenticator) = device-resident Authenticator passkey (permitted — not classified as synced by Microsoft); '
            'Passkey (Synced) = cloud-synced passkey via iCloud Keychain, Google Password Manager, 1Password, etc. (disqualified). '
            'Only the explicitly synced type fails this control.'
        ),
        'disqualifying_methods': 'passKeySynced / Passkey (Synced) — cloud-synced across devices',
        'qualifying_replacements': 'passKeyDeviceBound (hardware FIDO2), passKeyDeviceBoundAuthenticator (Authenticator passkey), windowsHelloforBusiness (TPM-bound)',
        'threshold': '0 — any AAL3 account with a synced passkey is non-compliant',
    }


def aal_11():
    """AAL-11: % of AAL3 accounts with intent-demonstrating authenticators.

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


def aal_11_detail():
    """Return detailed data for AAL-11: AAL3 users and their intent-demonstrating auth."""
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


def _get_aal2_only_users():
    """AAL2-only users: persona aal_level == 2, excluding AAL3 (isAdmin or aal_level >= 3)."""
    return UserData.objects.filter(
        Q(persona__aal_level=2)
    ).exclude(
        Q(isAdmin=True) | Q(persona__aal_level__gte=3)
    ).distinct()


def aal_07():
    """AAL-07: % of AAL2-only accounts with intent-demonstrating authenticators.

    NIST 800-63B-4 § 2.2.2: authentication at AAL2 SHOULD demonstrate intent
    from at least one authenticator. Intent-demonstrating methods require an
    explicit user action beyond passive possession:
    - FIDO2 key: physical tap (always demonstrates intent)
    - WHfB: biometric or PIN entry (always demonstrates intent)
    - MS Authenticator Passwordless: user must approve on device
    - MS Authenticator Push: number matching requires active code entry
    - Software OTP (TOTP): user must type the code

    Phone/SMS, email, and TAP do not require active user intent.
    AAL3 users are excluded — covered by AAL-11.

    Target: 100%
    """
    aal2_users = _get_aal2_only_users()

    total = aal2_users.count()
    if total == 0:
        return ('-', 'not_measured')

    with_intent = aal2_users.filter(REPLAY_RESISTANT_Q).distinct().count()
    pct = round(with_intent / total * 100)
    status = 'passing' if pct >= 100 else 'failing'
    return (f'{with_intent}/{total} ({pct}%)', status)


def aal_07_detail():
    """Return detailed data for AAL-07: AAL2-only users and intent-demonstrating auth."""
    aal2_users = _get_aal2_only_users()

    total = aal2_users.count()
    if total == 0:
        return {'total': 0, 'passing_count': 0, 'failing_count': 0, 'failing_users': [], 'passing_users': [], 'logic': 'No AAL2-only users found.'}

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
        'temporaryAccessPass_authentication_method',
    )[:100])

    return {
        'total': total,
        'passing_count': passing_qs.count(),
        'failing_count': failing_qs.count(),
        'failing_users': failing,
        'passing_users': passing,
        'logic': (
            'AAL2-only users (persona AAL level = 2, excluding admins and AAL3) should have at least one authenticator '
            'that requires explicit user action. FIDO2 keys (physical tap), WHfB (biometric/PIN), '
            'MS Authenticator Passwordless, MS Authenticator Push (number matching), and software OTP '
            '(code entry) all demonstrate intent. Phone/SMS codes and email OTP arrive passively and '
            'do not require an active user decision beyond receiving them. AAL3 users are measured separately by AAL-11.'
        ),
        'qualifying_methods': 'FIDO2 key (tap), WHfB (biometric/PIN), MS Authenticator Passwordless, MS Authenticator Push (number matching), Software OTP (code entry)',
        'disqualifying_methods': 'Phone/SMS, email OTP, and Temporary Access Pass alone do not demonstrate authentication intent',
        'nist_strength': 'SHOULD requirement (§ 2.2.2) — treated as a target; any gap is flagged as failing',
    }


def aal_06():
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


def aal_06_detail():
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
    (security questions) in password flows. Measures:
    1. Number of users with the securityQuestion auth method registered (user-level).
    2. Whether SSPR security questions are enabled at the tenant policy level — if yes,
       the control fails even if 0 users currently have them registered, because the
       configuration allows new registrations.

    Target: 0 users registered + SSPR security questions disabled
    """
    total = UserData.objects.count()
    if total == 0:
        return ('-', 'not_measured')

    with_kba = UserData.objects.filter(securityQuestion_authentication_method=True).count()

    policy = TenantAuthMethodsPolicy.objects.filter(id=1).first()
    sspr_sq_enabled = policy.sspr_security_questions_enabled if policy else None

    # Fail if users have it registered OR if SSPR policy allows security questions
    if with_kba > 0 or sspr_sq_enabled:
        label = str(with_kba)
        if sspr_sq_enabled:
            label += ' (SSPR policy: security questions enabled)'
        return (label, 'failing')
    return ('0', 'passing')


def pwd_08_detail():
    """Return detailed data for PWD-08: users with security questions registered."""
    total = UserData.objects.count()
    if total == 0:
        return {'total': 0, 'kba_count': 0, 'failing_users': [], 'logic': 'No users synced.'}

    kba_users = UserData.objects.filter(securityQuestion_authentication_method=True)
    kba_count = kba_users.count()

    policy = TenantAuthMethodsPolicy.objects.filter(id=1).first()
    sspr_sq_enabled = policy.sspr_security_questions_enabled if policy else None
    sspr_state = policy.sspr_state if policy else None
    sspr_allowed_methods = policy.sspr_allowed_methods if policy else []

    failing = list(kba_users.values(
        'upn', 'given_name', 'surname', 'persona__persona_name',
        'highest_authentication_strength', 'securityQuestion_authentication_method',
    )[:100])

    policy_note = ''
    if policy:
        if sspr_sq_enabled:
            policy_note = (
                f' SSPR policy has security questions ENABLED (state: {sspr_state}) — '
                'this allows new users to register security questions even if none currently have them.'
            )
        else:
            policy_note = f' SSPR policy has security questions DISABLED (state: {sspr_state}).'

    return {
        'total': total,
        'kba_count': kba_count,
        'failing_count': kba_count,
        'passing_count': total - kba_count,
        'failing_users': failing,
        'policy': {
            'sspr_security_questions_enabled': sspr_sq_enabled,
            'sspr_state': sspr_state,
            'sspr_allowed_methods': sspr_allowed_methods,
            'synced_at': policy.synced_at.isoformat() if policy else None,
        },
        'logic': (
            'NIST 800-63B-4 § 3.1.1.2(8) prohibits verifiers from prompting subscribers to use '
            'knowledge-based authentication (security questions) when choosing passwords. '
            'This control checks both user registrations (individual) and the SSPR tenant policy (systemic). '
            'A non-compliant SSPR policy fails the control even if 0 users currently have security questions registered.'
            + policy_note
        ),
        'qualifying_methods': 'No security questions registered + SSPR policy disables security questions',
        'disqualifying_methods': 'securityQuestion auth method registered (user-level) or SSPR policy allows security questions (policy-level)',
    }


def alm_11():
    """ALM-11: Recovery code lifetimes configured per NIST delivery-method thresholds.

    NIST 800-63B-4 § 4.2.1.2 sets maximum validity periods by delivery channel:
    - Postal (US): 21 days
    - Postal (international): 30 days
    - SMS/voice: 10 minutes
    - Email: 24 hours

    This control cannot be automatically evaluated from Entra ID or device data —
    it requires a manual review of SSPR configuration, application recovery flows,
    and any out-of-band delivery pipelines. Set use_manual=True on this control
    and record the result of a periodic configuration review in manual_notes.

    Returns not_measured until a manual review result is recorded.
    """
    return ('-', 'not_measured')
