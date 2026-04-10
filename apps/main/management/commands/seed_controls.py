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
            {
                'control_id': 'AAL-04',
                'domain': 'Phishing-Resistant Authentication (AAL3)',
                'statement': 'AAL3 SHALL require a cryptographic authenticator with a non-exportable private key that provides phishing resistance. Syncable authenticators SHALL NOT be used at AAL3.',
                'source_reference': 'SP 800-63B-4 § 2.3.1-2.3.2',
                'indicator': '% of AAL3 (Tier 0/Tier 1) accounts using hardware-bound phishing-resistant authenticators (non-syncable FIDO2/WHfB with TPM)',
                'measurement_method': 'Entra ID authentication methods report for T0/T1 admin accounts; verify no passkey sync enabled',
                'target': '100%',
                'evaluator': 'aal_04',
            },
            {
                'control_id': 'AAL-05',
                'domain': 'Reauthentication - AAL1',
                'statement': 'A definite reauthentication overall timeout SHALL be established, SHOULD be no more than 30 days at AAL1.',
                'source_reference': 'SP 800-63B-4 § 2.1.3',
                'indicator': 'Maximum session lifetime configured for AAL1 applications',
                'measurement_method': 'CA session control policy review',
                'target': '<= 30 days',
                'evaluator': 'aal_05',
            },
            {
                'control_id': 'ALM-06',
                'domain': 'Restricted Authenticator Management',
                'statement': 'PSTN (SMS/voice) authenticators are restricted. CSPs SHALL offer at least one alternative authenticator that is not restricted and SHALL provide clear guidance on risks.',
                'source_reference': 'SP 800-63B-4 § 3.2.9',
                'indicator': '% of users with ONLY SMS/voice as their MFA method (no alternative registered)',
                'measurement_method': 'Entra ID authentication methods report filtered to SMS-only users',
                'target': 'Monitored; declining trend toward 0%',
                'evaluator': 'alm_06',
            },
            {
                'control_id': 'AAL-09',
                'domain': 'Authentication Intent',
                'statement': 'AAL2 SHOULD demonstrate authentication intent. AAL3 SHALL demonstrate authentication intent from at least one authenticator.',
                'source_reference': 'SP 800-63B-4 § 2.2.2, 2.3.2',
                'indicator': '% of AAL3 accounts configured with authenticators that require explicit user action (tap, biometric, PIN)',
                'measurement_method': 'Entra ID authentication methods review for T0/T1; verify number matching enabled for push notifications',
                'target': '100% for AAL3',
                'evaluator': 'aal_09',
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
