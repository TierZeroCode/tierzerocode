"""
Control evaluator functions.

Each function takes no arguments and returns a tuple of (current_value, status).
- current_value: string like '95%' or '142 / 150'
- status: one of 'passing', 'failing', 'not_measured'

The function name must match the Control.evaluator field value.
"""
from django.db.models import Q
from apps.main.models import UserData, Device, Integration, SignInSummary
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
