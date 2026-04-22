import logging
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone

import ldap3
from django.utils import timezone

from apps.main.models import Integration, UserData, ADPasswordPolicy
from apps.logger.views import createLog

logger = logging.getLogger(__name__)

# AD 100ns interval epoch: 1601-01-01 UTC
_AD_EPOCH = datetime(1601, 1, 1, tzinfo=dt_timezone.utc)
_100NS_PER_SECOND = 10_000_000


def _ad_interval_to_days(raw):
    """Convert AD 100ns negative interval to positive days."""
    if not raw:
        return None
    try:
        val = int(raw)
        if val == 0 or val == -9223372036854775808:  # max/never
            return None
        return abs(val) // _100NS_PER_SECOND // 86400
    except (TypeError, ValueError):
        return None


def _ad_interval_to_minutes(raw):
    """Convert AD 100ns negative interval to positive minutes."""
    if not raw:
        return None
    try:
        val = int(raw)
        if val == 0 or val == -9223372036854775808:
            return None
        return abs(val) // _100NS_PER_SECOND // 60
    except (TypeError, ValueError):
        return None


def _pwd_last_set_to_datetime(raw):
    """Convert pwdLastSet (100ns since 1601-01-01) to timezone-aware datetime.

    The raw value from ldap3 comes as bytes (int64 LE Windows FILETIME).
    Decode with int.from_bytes before passing here, or pass an int directly.
    """
    if not raw:
        return None
    try:
        if isinstance(raw, bytes):
            val = int.from_bytes(raw, 'little')
        else:
            val = int(raw)
        if val == 0:
            return None
        seconds = val / _100NS_PER_SECOND
        return _AD_EPOCH + timedelta(seconds=seconds)
    except (TypeError, ValueError):
        return None


def _parse_guid(raw):
    """Convert raw objectGUID bytes to UUID string."""
    if not raw:
        return None
    try:
        if isinstance(raw, bytes):
            return str(uuid.UUID(bytes_le=raw))
        return str(raw)
    except Exception:
        return None


def _get_ldap_connection(config):
    """Create and return a bound ldap3 Connection from integration_config dict."""
    server_host = config.get('server', '')
    port = int(config.get('port', 636))
    use_ssl = config.get('use_ssl', True)
    service_account_dn = config.get('service_account_dn', '')
    service_account_password = config.get('service_account_password', '')

    server = ldap3.Server(server_host, port=port, use_ssl=use_ssl, get_info=ldap3.ALL)
    conn = ldap3.Connection(
        server,
        user=service_account_dn,
        password=service_account_password,
        authentication=ldap3.SIMPLE,
        auto_bind=ldap3.AUTO_BIND_NO_TLS,
    )
    if not conn.bind():
        raise ConnectionError(f"LDAP bind failed: {conn.result}")
    return conn


def _sync_pso(conn, pso_dn):
    """Pull FGPP attributes for a given PSO DN and upsert ADPasswordPolicy."""
    pso_attrs = [
        'name',
        'msDS-MinimumPasswordLength',
        'msDS-PasswordHistoryLength',
        'msDS-MaximumPasswordAge',
        'msDS-MinimumPasswordAge',
        'msDS-LockoutThreshold',
        'msDS-LockoutDuration',
        'msDS-LockoutObservationWindow',
        'msDS-PasswordComplexityEnabled',
        'msDS-PasswordReversibleEncryptionEnabled',
        'msDS-PasswordSettingsPrecedence',
    ]
    conn.search(
        search_base=pso_dn,
        search_filter='(objectClass=msDS-PasswordSettings)',
        search_scope=ldap3.BASE,
        attributes=pso_attrs,
    )
    if not conn.entries:
        return

    entry = conn.entries[0]

    def _get(attr):
        try:
            val = entry[attr].value
            return val if val != [] else None
        except Exception:
            return None

    ADPasswordPolicy.objects.update_or_create(
        policy_dn=pso_dn,
        defaults={
            'name': _get('name'),
            'min_password_length': _get('msDS-MinimumPasswordLength'),
            'password_history_length': _get('msDS-PasswordHistoryLength'),
            'max_password_age_days': _ad_interval_to_days(_get('msDS-MaximumPasswordAge')),
            'min_password_age_days': _ad_interval_to_days(_get('msDS-MinimumPasswordAge')),
            'lockout_threshold': _get('msDS-LockoutThreshold'),
            'lockout_duration_minutes': _ad_interval_to_minutes(_get('msDS-LockoutDuration')),
            'lockout_observation_window_minutes': _ad_interval_to_minutes(_get('msDS-LockoutObservationWindow')),
            'complexity_enabled': _get('msDS-PasswordComplexityEnabled'),
            'reversible_encryption_enabled': _get('msDS-PasswordReversibleEncryptionEnabled'),
            'precedence': _get('msDS-PasswordSettingsPrecedence'),
        }
    )


def syncActiveDirectoryUsers():
    """Main entry point: sync enabled AD users into UserData by UPN."""
    integration = Integration.objects.filter(
        integration_type='Active Directory', enabled=True
    ).first()

    if not integration:
        logger.warning("No enabled Active Directory integration found — skipping.")
        return

    config = integration.integration_config or {}
    base_dn = config.get('base_dn', '')
    if not base_dn:
        raise ValueError("Active Directory integration_config missing 'base_dn'")

    conn = _get_ldap_connection(config)

    search_filter = (
        '(&(objectClass=user)'
        '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
        '(userPrincipalName=*))'
    )
    attrs = [
        'userPrincipalName',
        'objectGUID',
        'sAMAccountName',
        'distinguishedName',
        'pwdLastSet',
        'msDS-ResultantPSO',
        'userAccountControl',
    ]

    entries = conn.extend.standard.paged_search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=ldap3.SUBTREE,
        attributes=attrs,
        paged_size=1000,
        generator=True,
    )

    synced_psos = set()
    matched_user_ids = []
    unmatched = 0

    now = timezone.now()
    update_fields = [
        'ad_object_guid',
        'ad_sam_account_name',
        'ad_distinguished_name',
        'ad_password_last_set',
        'ad_resultant_pso',
        'ad_synced_at',
        'updated_at',
    ]

    for entry in entries:
        if entry.get('type') != 'searchResEntry':
            continue

        attrs_dict = entry.get('attributes', {})
        raw_attrs = entry.get('raw_attributes', {})

        def _get(attr, _a=attrs_dict):
            val = _a.get(attr)
            if val is None or val == []:
                return None
            return val[0] if isinstance(val, list) else val

        upn = _get('userPrincipalName')
        if not upn:
            continue

        try:
            user = UserData.objects.get(upn__iexact=upn)
        except UserData.DoesNotExist:
            unmatched += 1
            continue
        except UserData.MultipleObjectsReturned:
            logger.warning("Multiple UserData rows for UPN %s — skipping", upn)
            continue

        pso_dn = _get('msDS-ResultantPSO')
        if pso_dn and pso_dn not in synced_psos:
            try:
                _sync_pso(conn, pso_dn)
                synced_psos.add(pso_dn)
            except Exception as e:
                logger.error("Failed to sync PSO %s: %s", pso_dn, e)

        raw_guid_list = raw_attrs.get('objectGUID', [])
        raw_pwd_list = raw_attrs.get('pwdLastSet', [])

        user.ad_object_guid = _parse_guid(raw_guid_list[0] if raw_guid_list else None)
        user.ad_sam_account_name = _get('sAMAccountName')
        user.ad_distinguished_name = _get('distinguishedName')
        user.ad_password_last_set = _pwd_last_set_to_datetime(raw_pwd_list[0] if raw_pwd_list else None)
        user.ad_resultant_pso = pso_dn
        user.ad_synced_at = now

        user.save(update_fields=update_fields)
        matched_user_ids.append(user.pk)

    conn.unbind()

    # Link matched users to this integration via M2M
    if matched_user_ids:
        UserIntegrationThrough = UserData.integration.through
        existing_links = set(
            UserIntegrationThrough.objects.filter(
                integration=integration,
                userdata_id__in=matched_user_ids,
            ).values_list('userdata_id', flat=True)
        )
        new_links = [
            UserIntegrationThrough(userdata_id=uid, integration=integration)
            for uid in matched_user_ids
            if uid not in existing_links
        ]
        if new_links:
            UserIntegrationThrough.objects.bulk_create(new_links, ignore_conflicts=True)

    integration.last_synced_at = now
    integration.save(update_fields=['last_synced_at'])

    createLog(
        None, "1514", "System Integration", "Active Directory User Sync",
        "Superuser", True, "System Integration Sync", "Success",
        additional_data=f"Matched: {len(matched_user_ids)}, Unmatched (no UPN in UserData): {unmatched}, PSOs synced: {len(synced_psos)}",
        user_id="system@tierzerocode.com", ip_address="127.0.0.1",
        user_agent="System", browser="System", operating_system="System",
    )

    logger.info("AD sync complete: %d matched, %d unmatched, %d PSOs", len(matched_user_ids), unmatched, len(synced_psos))
