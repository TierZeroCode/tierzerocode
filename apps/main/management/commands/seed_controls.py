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

        # Rename PWD-05 → PWD-10 if the old ID still exists
        Control.objects.filter(control_id='PWD-05').update(control_id='PWD-10')
        # Rename AAL-05 (reauthentication) → AAL-12, but only if AAL-12 doesn't exist yet
        if not Control.objects.filter(control_id='AAL-12').exists():
            Control.objects.filter(control_id='AAL-05').update(control_id='AAL-12')
        # Rename AAL-03 → AAL-05 if the old ID still exists
        Control.objects.filter(control_id='AAL-03').update(control_id='AAL-05')
        # Rename AAL-08 → AAL-06
        Control.objects.filter(control_id='AAL-08').update(control_id='AAL-06')
        # Rename AAL-09 → AAL-11 (frees AAL-09 for new control)
        if not Control.objects.filter(control_id='AAL-11').exists():
            Control.objects.filter(control_id='AAL-09').update(control_id='AAL-11')

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
                'domain': 'Multiple Authenticator Support',
                'statement': 'CSPs SHALL permit binding of multiple authenticators to a subscriber account. SHOULD encourage subscribers to maintain at least two separate means of authentication.',
                'source_reference': '800-63B-4 § 4.1.2.1',
                'indicator': '% of accounts with ≥2 registered auth methods',
                'measurement_method': 'Entra ID auth methods registration report',
                'target': '>90%',
                'evaluator': 'alm_02',
            },
            {
                'control_id': 'ALM-03',
                'domain': 'Post-Enrollment Binding',
                'statement': 'Binding of additional authenticators after enrollment SHALL require authentication at the AAL (or IAL for identity proofing) at which the new authenticator will be used.',
                'source_reference': 'SP 800-63B-4 § 4.1.2',
                'indicator': '% of MFA registration events that required prior authentication at AAL2 or higher',
                'measurement_method': 'Entra ID MFA registration policy (require MFA to register MFA); CA policy for security info registration',
                'target': '100%',
                'evaluator': 'alm_03',
            },
            {
                'control_id': 'AAL-02',
                'domain': 'Multi-Factor Authentication',
                'statement': 'AAL2 authentication SHALL use either a multi-factor authenticator or a combination of two separate authentication factors, including one physical authenticator ("something you have").',
                'source_reference': 'SP 800-63B-4 § 2.2.1',
                'indicator': '% of AAL2 user accounts with MFA enforced using an approved authenticator combination',
                'measurement_method': 'Entra ID authentication methods registration report / CA authentication strength policy audit',
                'target': '100%',
                'evaluator': 'aal_02',
            },
            {
                'control_id': 'AAL-05',
                'domain': 'AAL2 Phishing-Resistant Availability',
                'statement': 'Verifiers SHALL offer at least one phishing-resistant authentication option at AAL2. Federal agencies SHALL require staff, contractors, and partners to use phishing-resistant authentication.',
                'source_reference': '800-63B-4 § 2.2.2',
                'indicator': '% of staff/contractor/partner accounts using phishing-resistant MFA',
                'measurement_method': 'Entra ID auth methods report filtered to FIDO2/WHfB/CBA; CA authentication strength policies',
                'target': '100% for staff/contractors/partners',
                'evaluator': 'aal_05',
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
                'control_id': 'AAL-12',
                'domain': 'Reauthentication - AAL1',
                'statement': 'A definite reauthentication overall timeout SHALL be established, SHOULD be no more than 30 days at AAL1.',
                'source_reference': 'SP 800-63B-4 § 2.1.3',
                'indicator': 'Maximum session lifetime configured for AAL1 applications',
                'measurement_method': 'CA session control policy review',
                'target': '<= 30 days',
                'evaluator': 'aal_12',
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
                'control_id': 'AAL-06',
                'domain': 'AAL2/AAL3 Replay Resistance',
                'statement': 'At least one authenticator used at AAL2 SHALL be replay-resistant. AAL3 SHALL use replay-resistant authentication protocols.',
                'source_reference': 'SP 800-63B-4 § 2.2.2, 2.3.2',
                'indicator': '% of AAL2/AAL3 authentication flows using replay-resistant authenticators',
                'measurement_method': 'Authentication method audit (FIDO2, WHfB, certificate-based are replay-resistant; OTP and push are replay-resistant if single-use)',
                'target': '100%',
                'evaluator': 'aal_06',
            },
            {
                'control_id': 'AAL-09',
                'domain': 'AAL3 No Syncable Authenticators',
                'statement': 'Syncable authenticators (passkeys synced across devices) SHALL NOT be used at AAL3.',
                'source_reference': '800-63B-4 § 2.3.2',
                'indicator': 'Number of AAL3 accounts with syncable passkeys registered',
                'measurement_method': 'Entra ID passkey sync policy; FIDO2 key registration audit for T0/T1',
                'target': '0',
                'evaluator': 'aal_09',
            },
            {
                'control_id': 'AAL-11',
                'domain': 'AAL3 Authentication Intent Required',
                'statement': 'All authentication and reauthentication processes at AAL3 SHALL demonstrate authentication intent from at least one authenticator.',
                'source_reference': '800-63B-4 § 2.3.2',
                'indicator': '% of AAL3 auth events requiring explicit user action',
                'measurement_method': 'Entra ID authentication methods review for T0/T1; verify number matching enabled for push notifications and no passwordless without user gesture',
                'target': '100%',
                'evaluator': 'aal_11',
            },
            {
                'control_id': 'PWD-10',
                'domain': 'Password Blocklist',
                'statement': 'Verifiers SHALL compare prospective passwords against a blocklist of commonly used, expected, or compromised passwords. The entire password SHALL be checked.',
                'source_reference': '800-63B-4 § 3.1.1.2',
                'indicator': 'Password blocklist enforcement active on all endpoints',
                'measurement_method': 'Entra ID Password Protection (custom banned password list + global banned list) configuration audit; on-prem AD Password Protection agent deployment',
                'target': 'Enabled on all endpoints',
                'evaluator': 'pwd_10',
            },
            {
                'control_id': 'PWD-08',
                'domain': 'No KBA for Passwords',
                'statement': 'Verifiers SHALL NOT prompt subscribers to use knowledge-based authentication (security questions) when choosing passwords.',
                'source_reference': '800-63B-4 § 3.1.1.2(8)',
                'indicator': 'Number of applications using security questions in password flows',
                'measurement_method': 'Application auth configuration review; Entra ID SSPR method audit',
                'target': '0',
                'evaluator': 'pwd_08',
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
