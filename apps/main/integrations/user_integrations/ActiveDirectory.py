import logging
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone

import ldap3
from django.utils import timezone

from apps.main.models import Integration, UserData, PasswordPolicy
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
    except (TypeError, ValueError, OverflowError):
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
    except (TypeError, ValueError, OverflowError):
        return None


def _pwd_last_set_to_datetime(raw):
    """Convert pwdLastSet 100ns tick count (Python int from ldap3) to datetime."""
    if not raw:
        return None
    try:
        val = int(raw)
        if val == 0:
            return None
        seconds = val / _100NS_PER_SECOND
        return _AD_EPOCH + timedelta(seconds=seconds)
    except (TypeError, ValueError, OverflowError):
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


def _get_ldap_connection(integration):
    """Create and return a bound ldap3 Connection from Integration model fields."""
    server_host = integration.tenant_domain or ''
    extra = integration.integration_config or {}
    port = int(extra.get('port', 636))
    use_ssl = extra.get('use_ssl', True)
    service_account_dn = integration.client_id or ''
    service_account_password = integration.client_secret or ''

    # OFFLINE_AD_2012_R2 avoids a live schema fetch that can overflow on large AD integer attributes.
    server = ldap3.Server(server_host, port=port, use_ssl=use_ssl, get_info=ldap3.OFFLINE_AD_2012_R2)
    conn = ldap3.Connection(
        server,
        user=service_account_dn,
        password=service_account_password,
        authentication=ldap3.SIMPLE,
        auto_bind=ldap3.AUTO_BIND_NONE,
    )
    logger.debug("LDAP connecting to %s:%s ssl=%s as '%s'", server_host, port, use_ssl, service_account_dn)
    conn.open()
    if not conn.bind():
        raise ConnectionError(
            f"LDAP bind failed for DN '{service_account_dn}' on {server_host}:{port}: {conn.result}"
        )
    return conn


_PSO_ATTRS = [
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


def _raw_str(raw_attrs, attr):
    """Decode first raw bytes value for an attribute as a UTF-8 string."""
    vals = raw_attrs.get(attr) or []
    if not vals:
        return None
    v = vals[0]
    return v.decode('utf-8') if isinstance(v, bytes) else str(v)


def _raw_int(raw_attrs, attr):
    s = _raw_str(raw_attrs, attr)
    if s is None:
        return None
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


def _raw_bool(raw_attrs, attr):
    s = _raw_str(raw_attrs, attr)
    if s is None:
        return None
    return s.upper() == 'TRUE'


def _upsert_pso_from_raw(dn, raw_attrs):
    """Write one PSO dict (raw_attributes format) to PasswordPolicy."""
    PasswordPolicy.objects.update_or_create(
        policy_identifier=dn,
        defaults={
            'source': 'active_directory',
            'name': _raw_str(raw_attrs, 'name'),
            'min_password_length': _raw_int(raw_attrs, 'msDS-MinimumPasswordLength'),
            'password_history_length': _raw_int(raw_attrs, 'msDS-PasswordHistoryLength'),
            'max_password_age_days': _ad_interval_to_days(_raw_int(raw_attrs, 'msDS-MaximumPasswordAge')),
            'min_password_age_days': _ad_interval_to_days(_raw_int(raw_attrs, 'msDS-MinimumPasswordAge')),
            'lockout_threshold': _raw_int(raw_attrs, 'msDS-LockoutThreshold'),
            'lockout_duration_minutes': _ad_interval_to_minutes(_raw_int(raw_attrs, 'msDS-LockoutDuration')),
            'lockout_observation_window_minutes': _ad_interval_to_minutes(_raw_int(raw_attrs, 'msDS-LockoutObservationWindow')),
            'complexity_enabled': _raw_bool(raw_attrs, 'msDS-PasswordComplexityEnabled'),
            'reversible_encryption_enabled': _raw_bool(raw_attrs, 'msDS-PasswordReversibleEncryptionEnabled'),
            'precedence': _raw_int(raw_attrs, 'msDS-PasswordSettingsPrecedence'),
        }
    )


def _sync_pso(conn, pso_dn):
    """Fetch a single PSO by DN and upsert PasswordPolicy (per-user fallback)."""
    conn.search(
        search_base=pso_dn,
        search_filter='(objectClass=msDS-PasswordSettings)',
        search_scope=ldap3.BASE,
        attributes=_PSO_ATTRS,
    )
    entries = [e for e in (conn.response or []) if e.get('type') == 'searchResEntry']
    if not entries:
        logger.warning("_sync_pso: no entry found for DN %s (result=%s)", pso_dn, conn.result)
        return
    raw_attrs = entries[0].get('raw_attributes', {})
    _upsert_pso_from_raw(pso_dn, raw_attrs)


def _do_pso_search(conn, search_base, scope):
    """Execute a plain (non-paged) LDAP search for PSOs; return list of searchResEntry dicts."""
    conn.search(
        search_base=search_base,
        search_filter='(objectClass=msDS-PasswordSettings)',
        search_scope=scope,
        attributes=_PSO_ATTRS,
    )
    result_code = conn.result.get('result', -1)
    description = conn.result.get('description', '')
    entries = [e for e in (conn.response or []) if e.get('type') == 'searchResEntry']
    logger.info(
        "PSO search base=%s scope=%s → result=%s (%s) entries=%d",
        search_base, scope, result_code, description, len(entries),
    )
    return entries


def _sync_all_psos(conn, base_dn):
    """Discover and sync every PSO.

    Tries the PSO container first (plain non-paged search — the paged-search
    LDAP control can be denied on this container even after granting Read).
    Falls back to a full subtree scan if the container search returns nothing.
    """
    pso_container = f"CN=Password Settings Container,CN=System,{base_dn}"

    entries = _do_pso_search(conn, pso_container, ldap3.SUBTREE)

    if not entries:
        logger.warning(
            "0 PSOs from container %s — falling back to subtree search from base DN %s",
            pso_container, base_dn,
        )
        entries = _do_pso_search(conn, base_dn, ldap3.SUBTREE)

    if not entries:
        logger.error(
            "PSO search found 0 entries from both paths — FGPP will not be synced. "
            "Verify the service account has 'Read' on %s.",
            pso_container,
        )
        return set()

    pso_dns = set()
    for entry in entries:
        dn = entry.get('dn', '')
        if not dn:
            continue
        raw_attrs = entry.get('raw_attributes', {})
        try:
            _upsert_pso_from_raw(dn, raw_attrs)
            pso_dns.add(dn)
            logger.info("Synced PSO: %s", dn)
        except Exception as e:
            logger.error("Failed to upsert PSO %s: %s", dn, e)

    return pso_dns


def syncActiveDirectoryUsers():
    """Main entry point: sync enabled AD users into UserData by UPN."""
    integration = Integration.objects.filter(
        integration_type='Active Directory', enabled=True
    ).first()

    if not integration:
        logger.warning("No enabled Active Directory integration found — skipping.")
        return

    base_dn = integration.tenant_id or ''
    if not base_dn:
        raise ValueError("Active Directory integration missing Base DN (tenant_id field)")

    conn = _get_ldap_connection(integration)

    # Sync all PSOs directly from the container first, before touching users.
    synced_psos = _sync_all_psos(conn, base_dn)
    logger.info("Discovered %d PSO(s) from Password Settings Container", len(synced_psos))

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

        # objectGUID: binary attribute — raw_attributes gives the correct 16-byte GUID
        raw_guid_list = raw_attrs.get('objectGUID', [])
        user.ad_object_guid = _parse_guid(raw_guid_list[0] if raw_guid_list else None)

        user.ad_sam_account_name = _get('sAMAccountName')
        user.ad_distinguished_name = _get('distinguishedName')

        # pwdLastSet: integer attribute — use ldap3's decoded int, not raw bytes (raw bytes are BER big-endian, not LE FILETIME)
        user.ad_password_last_set = _pwd_last_set_to_datetime(_get('pwdLastSet'))

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
