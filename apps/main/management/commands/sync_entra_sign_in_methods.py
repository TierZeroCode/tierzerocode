import json
import requests
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.main.models import Integration, EntraSignInMethodStat, UserData
from apps.code_packages.microsoft import getMicrosoftGraphAccessToken


class Command(BaseCommand):
    help = 'Sync Entra ID sign-in method stats and print verbose diagnostics.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--diagnose',
            action='store_true',
            help='Skip the sync; only print the current state and probe the API once.',
        )

    def handle(self, *args, **options):
        from apps.main.integrations.user_integrations.MicrosoftEntraID import (
            syncSignInLogs, _REPLAY_RESISTANT_METHODS,
        )

        diagnose_only = options['diagnose']

        # ── Step 1: Pre-sync state ──────────────────────────────────────────
        self.stdout.write(self.style.MIGRATE_HEADING('── Pre-sync state ──'))
        pre_count = EntraSignInMethodStat.objects.count()
        aal2_qs = UserData.objects.filter(persona__aal_level=2)
        aal2_count = aal2_qs.count()
        self.stdout.write(f'  EntraSignInMethodStat rows: {pre_count}')
        self.stdout.write(f'  UserData rows with persona.aal_level=2: {aal2_count}')

        if pre_count > 0:
            sample_stats = list(EntraSignInMethodStat.objects.values(
                'upn', 'total_signins', 'replay_resistant_signins', 'mfa_satisfied_signins',
            )[:5])
            self.stdout.write(f'  Sample stat rows: {sample_stats}')

        if aal2_count > 0:
            sample_aal2 = list(aal2_qs.values_list('upn', flat=True)[:5])
            self.stdout.write(f'  Sample AAL2 UPNs: {sample_aal2}')

            matching = EntraSignInMethodStat.objects.filter(
                upn__in=aal2_qs.values_list('upn', flat=True)
            ).count()
            self.stdout.write(f'  EntraSignInMethodStat rows matching AAL2 UPNs: {matching}')

        # ── Step 2: Integration creds ───────────────────────────────────────
        self.stdout.write(self.style.MIGRATE_HEADING('\n── Integration credentials ──'))
        try:
            data = Integration.objects.get(
                integration_type='Microsoft Entra ID',
                integration_context='User',
            )
        except Integration.DoesNotExist:
            self.stdout.write(self.style.ERROR('  No Microsoft Entra ID User integration configured.'))
            return

        if not data.client_id or not data.client_secret or not data.tenant_id:
            self.stdout.write(self.style.ERROR('  Missing client_id, client_secret, or tenant_id.'))
            return
        self.stdout.write(self.style.SUCCESS('  OK — credentials present.'))

        access_token = getMicrosoftGraphAccessToken(
            data.client_id, data.client_secret, data.tenant_id,
            ['https://graph.microsoft.com/.default'],
        )
        if isinstance(access_token, dict) and 'error' in access_token:
            self.stdout.write(self.style.ERROR(f'  Token error: {access_token["error"]}'))
            return
        self.stdout.write(self.style.SUCCESS('  OK — access token acquired.'))

        # ── Step 3: API probe ───────────────────────────────────────────────
        self.stdout.write(self.style.MIGRATE_HEADING('\n── API probe (single page) ──'))
        url = (
            'https://graph.microsoft.com/beta/auditLogs/signIns'
            '?$filter=status/errorCode eq 0'
            '&$top=10'
        )
        headers = {'Authorization': access_token}
        try:
            resp = requests.get(url, headers=headers, timeout=30)
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  Request failed: {e}'))
            return

        self.stdout.write(f'  HTTP status: {resp.status_code}')
        if resp.status_code != 200:
            self.stdout.write(self.style.ERROR(f'  Body (first 500 chars): {resp.text[:500]}'))
            self.stdout.write(self.style.WARNING(
                '\n  Probable cause: missing AuditLog.Read.All app permission, or the\n'
                '  beta endpoint is rejecting the query. Add AuditLog.Read.All (Application)\n'
                '  in the Entra ID app registration and grant admin consent.'
            ))
            return

        body = resp.json()
        records = body.get('value', [])
        self.stdout.write(f'  Records returned: {len(records)}')

        window_start = timezone.now() - timedelta(days=30)
        self.stdout.write(f'  Window start (30d ago): {window_start.isoformat()}')

        if records:
            sample = records[0]
            self.stdout.write('  First record (sanitized sample):')
            self.stdout.write(f'    userPrincipalName: {sample.get("userPrincipalName")}')
            self.stdout.write(f'    createdDateTime:   {sample.get("createdDateTime")}')
            ad = sample.get('authenticationDetails') or []
            self.stdout.write(f'    authenticationDetails: {len(ad)} step(s)')
            for step in ad[:3]:
                method = step.get('authenticationMethod')
                requirement = step.get('authenticationStepRequirement')
                succeeded = step.get('succeeded')
                method_lc = (method or '').lower()
                if method_lc == 'previously satisfied':
                    marker = self.style.WARNING('SSO-CACHED (excluded from RR/HB rates)')
                elif method_lc in _REPLAY_RESISTANT_METHODS:
                    marker = self.style.SUCCESS('REPLAY-RESISTANT')
                else:
                    marker = self.style.WARNING('not classified RR')
                self.stdout.write(f'      - method={method!r} req={requirement!r} ok={succeeded} → {marker}')

            unique_methods = set()
            for rec in records:
                for step in (rec.get('authenticationDetails') or []):
                    m = step.get('authenticationMethod')
                    if m:
                        unique_methods.add(m)
            self.stdout.write(f'  Unique authenticationMethod values across {len(records)} records: {sorted(unique_methods)}')
            self.stdout.write(f'  Currently-classified replay-resistant set: {sorted(_REPLAY_RESISTANT_METHODS)}')
        else:
            self.stdout.write(self.style.WARNING('  No records returned. Either no successful sign-ins, or the API is filtering them all out.'))

        if diagnose_only:
            self.stdout.write(self.style.MIGRATE_HEADING('\n── --diagnose mode: skipping full sync ──'))
            return

        # ── Step 4: Run the full sync ──────────────────────────────────────
        self.stdout.write(self.style.MIGRATE_HEADING('\n── Full sync (combined SignInSummary + EntraSignInMethodStat) ──'))
        try:
            syncSignInLogs(access_token)
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  syncSignInLogs raised: {e}'))
            import traceback
            self.stdout.write(traceback.format_exc())
            return

        # ── Step 5: Post-sync state ────────────────────────────────────────
        self.stdout.write(self.style.MIGRATE_HEADING('\n── Post-sync state ──'))
        post_count = EntraSignInMethodStat.objects.count()
        self.stdout.write(f'  EntraSignInMethodStat rows: {pre_count} → {post_count}')

        if post_count > 0:
            from django.db.models import Sum
            total_agg = EntraSignInMethodStat.objects.aggregate(
                total=Sum('total_signins'),
                replay=Sum('replay_resistant_signins'),
                mfa=Sum('mfa_satisfied_signins'),
                hw=Sum('hardware_bound_signins'),
                prev=Sum('previously_satisfied_signins'),
            )
            self.stdout.write(
                f'  Aggregate sign-ins (all users): '
                f"total={total_agg['total']}, replay-resistant={total_agg['replay']}, "
                f"mfa-satisfied={total_agg['mfa']}, hardware-bound={total_agg['hw']}, "
                f"previously-satisfied={total_agg['prev']}"
            )

            if aal2_count > 0:
                aal2_agg = EntraSignInMethodStat.objects.filter(
                    upn__in=aal2_qs.values_list('upn', flat=True)
                ).aggregate(
                    total=Sum('total_signins'),
                    replay=Sum('replay_resistant_signins'),
                    mfa=Sum('mfa_satisfied_signins'),
                )
                aal2_t = aal2_agg['total'] or 0
                aal2_r = aal2_agg['replay'] or 0
                aal2_m = aal2_agg['mfa'] or 0
                rr_pct = round(aal2_r / aal2_t * 100) if aal2_t > 0 else 0
                mfa_pct = round(aal2_m / aal2_t * 100) if aal2_t > 0 else 0
                self.stdout.write(
                    f'  AAL2-scoped aggregate: total={aal2_t}\n'
                    f'    AAL-2.6 (replay-resistant): {aal2_r}/{aal2_t} ({rr_pct}%)\n'
                    f'    AAL-2.3 (mfa-satisfied):    {aal2_m}/{aal2_t} ({mfa_pct}%)'
                )
                if aal2_t == 0:
                    self.stdout.write(self.style.WARNING(
                        '  → No AAL2-scoped users had sign-ins in the 30-day window. '
                        'AAL-2.3 and AAL-2.6 will show "Not Measured".'
                    ))
                else:
                    self.stdout.write(self.style.SUCCESS('  → AAL-2.3 and AAL-2.6 should now evaluate.'))
            else:
                self.stdout.write(self.style.WARNING(
                    '  → No AAL2-scoped users in UserData. AAL-2.6 will show "Not Measured".'
                ))
        else:
            self.stdout.write(self.style.ERROR(
                '  → EntraSignInMethodStat is still empty after sync. '
                'Check the audit log for codes 1518/1519.'
            ))
