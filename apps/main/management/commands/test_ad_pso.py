"""Diagnostic command: probe the AD PSO container and print exactly what the service account sees."""

import ldap3
from django.core.management.base import BaseCommand

from apps.main.integrations.user_integrations.ActiveDirectory import _get_ldap_connection
from apps.main.models import Integration


class Command(BaseCommand):
    help = 'Diagnose AD PSO (Fine-Grained Password Policy) discovery'

    def handle(self, *args, **options):
        integration = Integration.objects.filter(
            integration_type='Active Directory', enabled=True
        ).first()

        if not integration:
            self.stdout.write(self.style.ERROR('No enabled Active Directory integration found.'))
            return

        base_dn = (integration.tenant_id or '').strip()
        self.stdout.write(f'Base DN:   {repr(base_dn)}')
        self.stdout.write(f'Server:    {integration.tenant_domain}')
        self.stdout.write(f'Bind user: {integration.client_id}')
        self.stdout.write('')

        try:
            conn = _get_ldap_connection(integration)
            self.stdout.write(self.style.SUCCESS('LDAP bind: OK'))
        except Exception as exc:
            self.stdout.write(self.style.ERROR(f'LDAP bind FAILED: {exc}'))
            return

        pso_container = f"CN=Password Settings Container,CN=System,{base_dn}"

        # ── 1. Verify the container itself is reachable ──────────────────────
        self.stdout.write(f'\n[1] BASE search on PSO container:')
        self.stdout.write(f'    {pso_container}')
        conn.search(
            search_base=pso_container,
            search_filter='(objectClass=*)',
            search_scope=ldap3.BASE,
            attributes=['objectClass', 'cn'],
        )
        self._report(conn)

        # ── 2. ONE_LEVEL search inside the container ─────────────────────────
        self.stdout.write(f'\n[2] ONE_LEVEL search inside PSO container (lists direct children):')
        conn.search(
            search_base=pso_container,
            search_filter='(objectClass=*)',
            search_scope=ldap3.LEVEL,
            attributes=['objectClass', 'cn', 'name'],
        )
        self._report(conn)

        # ── 3. SUBTREE search for msDS-PasswordSettings in container ─────────
        self.stdout.write(f'\n[3] SUBTREE search for (objectClass=msDS-PasswordSettings) in container:')
        conn.search(
            search_base=pso_container,
            search_filter='(objectClass=msDS-PasswordSettings)',
            search_scope=ldap3.SUBTREE,
            attributes=['name', 'msDS-PasswordSettingsPrecedence'],
        )
        self._report(conn)

        # ── 4. SUBTREE search across the whole domain ─────────────────────────
        self.stdout.write(f'\n[4] SUBTREE search for (objectClass=msDS-PasswordSettings) from base DN:')
        conn.search(
            search_base=base_dn,
            search_filter='(objectClass=msDS-PasswordSettings)',
            search_scope=ldap3.SUBTREE,
            attributes=['name', 'msDS-PasswordSettingsPrecedence'],
        )
        self._report(conn)

        # ── 5. Alternative filter using msDS-PasswordSettingsPrecedence ───────
        self.stdout.write(f'\n[5] Alternate: search for (msDS-PasswordSettingsPrecedence=*) from base DN:')
        conn.search(
            search_base=base_dn,
            search_filter='(msDS-PasswordSettingsPrecedence=*)',
            search_scope=ldap3.SUBTREE,
            attributes=['name', 'objectClass'],
        )
        self._report(conn)

        conn.unbind()
        self.stdout.write('\nDone.')

    def _report(self, conn):
        result = conn.result
        code = result.get('result', '?')
        desc = result.get('description', '')
        msg  = result.get('message', '')
        entries = [e for e in (conn.response or []) if e.get('type') == 'searchResEntry']

        status = self.style.SUCCESS(f'result={code} ({desc})') if code == 0 else \
                 self.style.ERROR(f'result={code} ({desc}) {msg}')
        self.stdout.write(f'    Server returned: {status}')
        self.stdout.write(f'    Entries found:   {len(entries)}')
        for e in entries:
            self.stdout.write(f'      → {e["dn"]}')
            attrs = e.get('attributes', {})
            for k, v in attrs.items():
                if v not in (None, [], ''):
                    self.stdout.write(f'         {k}: {v}')
