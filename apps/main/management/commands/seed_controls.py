from django.core.management.base import BaseCommand
from apps.main.models import ControlFramework, Control

# ─────────────────────────────────────────────────────────────────────────────
# New-generation controls (v2+).
#
# Each entry is the full canonical definition for one control.
# All fields map directly to the Control model. Each control is tagged with
# a `framework_short_name` that maps to one of the entries in FRAMEWORKS.
#
# Required:  control_id, framework_short_name, domain, statement,
#            source_reference, indicator, measurement_method, target,
#            evaluator
# Optional:  amber_threshold, red_threshold  (tiered alert thresholds)
#
# Re-seed behavior: a user-edited `target` is NEVER overwritten on re-seed.
# Other fields update normally. Drop the field from the seed entry if you
# want first-create defaulting only.
#
# Run via:   python manage.py seed_controls
# UI button: Settings → Seed Controls (superuser only)
# ─────────────────────────────────────────────────────────────────────────────

# Canonical framework definitions — keyed by short_name.
# `display_order` controls UI sort: lower = earlier. Custom is pinned to 100
# so it always lands at the bottom of any framework listing.
FRAMEWORKS = {
    'NIST SP 800-63-4': {
        'name': 'NIST Special Publication 800-63 Revision 4 — Digital Identity Guidelines',
        'version': 'Revision 4',
        'url': 'https://pages.nist.gov/800-63-4/',
        'display_order': 0,
    },
    'Custom': {
        'name': 'Custom Controls',
        'version': 'v1',
        'url': '',
        'display_order': 100,
    },
}

CONTROLS = [
    # ── AAL — Authentication Assurance Level ─────────────────────────────────
    {
        'framework_short_name': 'NIST SP 800-63-4',
        'control_id': 'AAL-2.1',
        'domain': 'AAL2 — MFA Registration',
        'statement': (
            'AAL2 authentication SHALL use either a multi-factor authenticator '
            'or a combination of two separate authenticators.'
        ),
        'source_reference': 'SP 800-63B-4 § 2.2.1',
        'indicator': '% of AAL2-scoped user accounts with ≥1 approved MFA method registered',
        'measurement_method': (
            'Entra ID authentication methods registration report — filter to AAL2-scoped '
            'users, count those with at least one non-password MFA method'
        ),
        'target': '100%',
        'amber_threshold': '< 100%',
        'red_threshold': '< 95%',
        'data_sources': ['Microsoft Entra ID'],
        'evaluator': 'aal_02_1',
    },
    {
        'framework_short_name': 'NIST SP 800-63-4',
        'control_id': 'AAL-2.3',
        'domain': 'AAL2 — MFA Usage Rate',
        'statement': (
            'AAL2 sign-ins should demonstrate MFA satisfaction; a drop in MFA '
            'usage rate may indicate bypass or legacy auth leakage.'
        ),
        'source_reference': 'SP 800-63B-4 § 2.2.1',
        'indicator': (
            "% of AAL2 sign-ins with authenticationRequirement = "
            "'multiFactorAuthentication' in last 30 days"
        ),
        'measurement_method': (
            'Entra ID sign-in logs — query authenticationRequirement field, '
            'filter to AAL2 app sign-ins, calculate % satisfying MFA vs total.'
        ),
        'target': '100%',
        'amber_threshold': '< 100%',
        'red_threshold': '< 95%',
        'data_sources': ['Microsoft Entra ID'],
        'evaluator': 'aal_02_3',
    },
    {
        'framework_short_name': 'NIST SP 800-63-4',
        'control_id': 'AAL-2.4',
        'domain': 'AAL2 — Phishing-Resistant MFA Adoption',
        'statement': (
            'Verifiers SHALL offer at least one phishing-resistant authentication '
            'option at AAL2.'
        ),
        'source_reference': 'SP 800-63B-4 § 2.2.2',
        'indicator': (
            '% of AAL2 using phishing-resistant MFA (FIDO2/WHfB/CBA) as primary '
            'AAL2 method'
        ),
        'measurement_method': (
            'Entra ID authentication methods report — filter to AAL2 accounts, '
            'count those with FIDO2, WHfB, or CBA as a registered method.'
        ),
        'target': '100%',
        'amber_threshold': '< 80%',
        'red_threshold': '< 60%',
        'data_sources': ['Microsoft Entra ID'],
        'evaluator': 'aal_02_4',
    },
    {
        'framework_short_name': 'NIST SP 800-63-4',
        'control_id': 'AAL-2.6',
        'domain': 'AAL2 — Replay Resistance',
        'statement': (
            'At least one authenticator used at AAL2 SHALL be replay-resistant '
            '(FIDO2, WHfB, CBA, TOTP are replay-resistant; push approval alone is not).'
        ),
        'source_reference': 'SP 800-63B-4 § 2.2.2',
        'indicator': '% of AAL2 sign-ins that used a replay-resistant authenticator (last 30 days)',
        'measurement_method': (
            'Entra ID sign-in logs — authenticationDetails per event; '
            'FIDO2/WHfB/CBA/Software OTP/Passwordless = replay-resistant; push = not. '
            'Aggregate: replay-resistant sign-in events ÷ total AAL2 sign-in events '
            'in the 30-day window. Requires AuditLog.Read.All and syncSignInMethods().'
        ),
        'target': '100%',
        'amber_threshold': '< 90%',
        'red_threshold': '< 75%',
        'data_sources': ['Microsoft Entra ID'],
        'evaluator': 'aal_02_6',
    },

    {
        'framework_short_name': 'NIST SP 800-63-4',
        'control_id': 'AAL-3.2',
        'domain': 'AAL3 — PHR-MFA Enforcement',
        'statement': (
            'AAL3 (or privileged human) sign-ins must be satisfied by hardware-bound '
            'phishing-resistant authentication (AAL3 enforcement via CA).'
        ),
        'source_reference': 'SP 800-63B-4 § 2.3.1–2.3.2',
        'indicator': (
            '% of AAL3 (or privileged human) sign-ins satisfied by hardware-bound '
            'phishing-resistant authenticator'
        ),
        'measurement_method': (
            'Entra ID sign-in logs filtered to AAL3 (or privileged human) accounts — '
            'verify authentication method = FIDO2 or WHfB with TPM attestation.'
        ),
        'target': '100%',
        'amber_threshold': '< 100%',
        'red_threshold': '< 90%',
        'data_sources': ['Microsoft Entra ID'],
        'evaluator': 'aal_03_2',
    },

    # ── PWD — Password Controls ──────────────────────────────────────────────
    {
        'framework_short_name': 'NIST SP 800-63-4',
        'control_id': 'PWD-05',
        'domain': 'Password Blocklist Enforcement',
        'statement': (
            'Verifiers SHALL compare prospective passwords against a blocklist '
            'of commonly used, expected, or compromised passwords.'
        ),
        'source_reference': 'SP 800-63B-4 § 3.1.1.2',
        'indicator': (
            'Password blocklist enforcement enabled across all authentication '
            'endpoints (Entra ID Password Protection — custom + global banned list)'
        ),
        'measurement_method': (
            'Entra ID Password Protection configuration audit — verify domain-level '
            'protection is in Enforce mode on all DCs; check custom banned password '
            'list includes organization-specific terms.'
        ),
        'target': 'Enabled on all endpoints',
        'red_threshold': 'Audit mode or not deployed to all DCs',
        'data_sources': ['Microsoft Entra ID', 'Active Directory'],
        'evaluator': 'pwd_10',
    },
    {
        'framework_short_name': 'NIST SP 800-63-4',
        'control_id': 'PWD-07',
        'domain': 'No Password Hints or KBA',
        'statement': (
            'Verifiers SHALL NOT permit password hints accessible to unauthenticated '
            'claimants. SHALL NOT use knowledge-based authentication (security '
            'questions) as a recovery factor.'
        ),
        'source_reference': 'SP 800-63B-4 § 3.1.1.2(7–8)',
        'indicator': (
            'Number of applications using password hints or security questions '
            'for password selection or recovery'
        ),
        'measurement_method': (
            'Application authentication configuration review — audit Entra ID SSPR '
            'configuration; review custom applications using KBA.'
        ),
        'target': '0',
        'red_threshold': '>= 1',
        'data_sources': ['Microsoft Entra ID'],
        'evaluator': 'pwd_07',
    },

    # ── Custom — non-framework controls ──────────────────────────────────────
    {
        'framework_short_name': 'Custom',
        'control_id': 'PRIV-01',
        'domain': 'Admin Account Privileged Persona Alignment',
        'statement': (
            'Entra ID administrative accounts must be assigned to a Persona '
            'tagged "Privileged" so they are properly scoped under '
            'privileged-account controls.'
        ),
        'source_reference': 'Internal — Tier Zero C.O.D.E. Custom',
        'indicator': (
            '% of Entra ID admins assigned to a Persona tagged "Privileged"'
        ),
        'measurement_method': (
            'UserData query: of all rows where isAdmin=True, the share whose '
            'persona has the "Privileged" PersonaTag applied.'
        ),
        'target': '100%',
        'amber_threshold': '< 100%',
        'red_threshold': '< 95%',
        'data_sources': ['Microsoft Entra ID'],
        'evaluator': 'custom_admin_no_privileged_persona',
    },
]


class Command(BaseCommand):
    help = 'Seed new-generation security controls. Called by the UI Seed Controls button.'

    def handle(self, *args, **options):
        # ── Phase 1: upsert every framework ─────────────────────────────────
        framework_objs = {}
        for short_name, defaults in FRAMEWORKS.items():
            fw, created = ControlFramework.objects.update_or_create(
                short_name=short_name,
                defaults=defaults,
            )
            framework_objs[short_name] = fw
            action = 'Created' if created else 'Updated'
            self.stdout.write(f'{action} framework: {fw}')

        # ── Phase 2: upsert every control, preserving user-edited targets ──
        target_preserved = 0
        for ctrl_data in CONTROLS:
            data = dict(ctrl_data)
            fw_short = data.pop('framework_short_name', None)
            if fw_short not in framework_objs:
                self.stdout.write(self.style.WARNING(
                    f'  Skipping {data.get("control_id")} — unknown framework {fw_short!r}'
                ))
                continue
            data['framework'] = framework_objs[fw_short]

            # If the control already exists with a non-empty target, leave it
            # alone — operators may have customized the threshold for their org.
            existing = Control.objects.filter(control_id=data['control_id']).first()
            if existing and existing.target:
                seed_target = data.pop('target', None)
                if seed_target and seed_target != existing.target:
                    target_preserved += 1
                    self.stdout.write(
                        f'  Preserving existing target on {data["control_id"]}: '
                        f'{existing.target!r} (seed value {seed_target!r} ignored)'
                    )

            ctrl, created = Control.objects.update_or_create(
                control_id=data['control_id'],
                defaults=data,
            )
            action = 'Created' if created else 'Updated'
            self.stdout.write(f'  {action} control: {ctrl.control_id} — {ctrl.domain}')

        summary = f'Done. {len(CONTROLS)} control(s) seeded across {len(framework_objs)} framework(s).'
        if target_preserved:
            summary += f' {target_preserved} user-edited target(s) preserved.'
        self.stdout.write(self.style.SUCCESS(summary))
