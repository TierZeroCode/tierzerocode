from django.core.management.base import BaseCommand
from apps.main.models import ControlFramework, Control


class Command(BaseCommand):
    help = 'Seed initial security controls from NIST 800-63-4'

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

        controls = [
            {
                'control_id': 'ALM-01',
                'domain': 'Authenticator Binding at Enrollment',
                'statement': 'The CSP SHALL bind at least one authenticator to the subscriber account at the completion of the enrollment process.',
                'source_reference': 'SP 800-63B-4 § 4.1.1',
                'indicator': '% of accounts with at least one authenticator registered at enrollment',
                'measurement_method': 'Entra ID authentication methods registration report; SailPoint provisioning workflow audit',
                'target': '100%',
                'evaluator': 'alm_01',
            },
            {
                'control_id': 'ALM-02',
                'domain': 'Post-Enrollment Binding',
                'statement': 'Binding of additional authenticators after enrollment SHALL require authentication at the AAL (or IAL for identity proofing) at which the new authenticator will be used.',
                'source_reference': 'SP 800-63B-4 § 4.1.2',
                'indicator': '% of MFA registration events that required prior authentication at AAL2 or higher',
                'measurement_method': 'Entra ID MFA registration policy (require MFA to register MFA); CA policy for security info registration',
                'target': '100%',
                'evaluator': 'alm_02',
            },
        ]

        for ctrl_data in controls:
            ctrl, created = Control.objects.update_or_create(
                control_id=ctrl_data['control_id'],
                defaults={**ctrl_data, 'framework': framework},
            )
            action = 'Created' if created else 'Updated'
            self.stdout.write(f'  {action} control: {ctrl.control_id} — {ctrl.domain}')

        self.stdout.write(self.style.SUCCESS(f'Done. {len(controls)} controls seeded.'))
