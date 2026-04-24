from django.core.management.base import BaseCommand
from apps.main.models import ControlFramework, Control

# ─────────────────────────────────────────────────────────────────────────────
# New-generation controls (v2+).
#
# Each entry is the full canonical definition for one control.
# All fields map directly to the Control model.
#
# Required:  control_id, domain, statement, source_reference,
#            indicator, measurement_method, target, evaluator
# Optional:  amber_threshold, red_threshold  (tiered alert thresholds)
#
# Run via:   python manage.py seed_controls
# UI button: Settings → Seed Controls (superuser only)
# ─────────────────────────────────────────────────────────────────────────────

CONTROLS = [
    # ── AAL — Authentication Assurance Level ─────────────────────────────────
    {
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
        'evaluator': 'aal_02_1',
    },
]


class Command(BaseCommand):
    help = 'Seed new-generation security controls. Called by the UI Seed Controls button.'

    def handle(self, *args, **options):
        framework, created = ControlFramework.objects.update_or_create(
            short_name='NIST SP 800-63-4',
            defaults={
                'name': 'NIST Special Publication 800-63 Revision 4 — Digital Identity Guidelines',
                'version': 'Revision 4',
                'url': 'https://pages.nist.gov/800-63-4/',
            },
        )
        action = 'Created' if created else 'Updated'
        self.stdout.write(f'{action} framework: {framework}')

        for ctrl_data in CONTROLS:
            ctrl, created = Control.objects.update_or_create(
                control_id=ctrl_data['control_id'],
                defaults={**ctrl_data, 'framework': framework},
            )
            action = 'Created' if created else 'Updated'
            self.stdout.write(f'  {action} control: {ctrl.control_id} — {ctrl.domain}')

        self.stdout.write(self.style.SUCCESS(f'Done. {len(CONTROLS)} control(s) seeded.'))
