from django.core.management.base import BaseCommand
from apps.main.models import ControlFramework, Control


class Command(BaseCommand):
    help = 'Seed legacy NIST 800-63-4 controls (v1 generation). Not called from the UI — run manually only.'

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

        # Historical ID renames — idempotent
        Control.objects.filter(control_id='PWD-05').update(control_id='PWD-10')
        if not Control.objects.filter(control_id='AAL-12').exists():
            Control.objects.filter(control_id='AAL-05').update(control_id='AAL-12')
        if not Control.objects.filter(control_id='AAL-05').exists():
            Control.objects.filter(control_id='AAL-03').update(control_id='AAL-05')
        Control.objects.filter(control_id='AAL-08').update(control_id='AAL-06')
        if not Control.objects.filter(control_id='AAL-11').exists():
            Control.objects.filter(control_id='AAL-09').update(control_id='AAL-11')
        Control.objects.filter(control_id='PWD-08').update(control_id='PWD-07')

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
                'indicator': '% of human subscriber accounts with ≥2 registered auth methods',
                'measurement_method': 'Entra ID auth methods registration report; scoped to personas tagged "Human"',
                'target': '100%',
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
                'control_id': 'AAL-03',
                'domain': 'AAL1 Authenticator Types',
                'statement': 'AAL1 authentication SHALL use any approved authenticator type (password, look-up secret, OOB device, SF OTP, MF OTP, SF crypto, MF crypto).',
                'source_reference': '800-63B-4 § 2.1.1',
                'indicator': '% of AAL1 applications using only approved authenticator types',
                'measurement_method': 'Application authentication method inventory; Entra ID auth methods report filtered to users with only email OTP or security questions as their registered second factor',
                'target': '100%',
                'evaluator': 'aal_03',
            },
            {
                'control_id': 'AAL-04',
                'domain': 'AAL2 Multi-Factor Requirement',
                'statement': 'AAL2 authentication SHALL use either a multi-factor authenticator or a combination of two separate authentication factors including one physical authenticator.',
                'source_reference': '800-63B-4 § 2.2.1',
                'indicator': '% of AAL2 accounts with MFA enforced using approved combination',
                'measurement_method': 'Entra ID auth methods registration report; CA authentication strength audit',
                'target': '100%',
                'evaluator': 'aal_02',
            },
            {
                'control_id': 'AAL-05',
                'domain': 'AAL2 Phishing-Resistant Availability',
                'statement': 'Verifiers SHALL offer at least one phishing-resistant authentication option at AAL2.',
                'source_reference': '800-63B-4 § 2.2.2',
                'indicator': '% of AAL2 accounts using phishing-resistant MFA',
                'measurement_method': 'Entra ID auth methods report filtered to FIDO2/WHfB/CBA',
                'target': '100%',
                'evaluator': 'aal_05',
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
                'control_id': 'ALM-11',
                'domain': 'Issued Recovery Code Lifetime',
                'statement': 'Issued recovery codes SHALL be valid for at most: 21 days (postal US), 30 days (postal intl), 10 minutes (SMS/voice), 24 hours (email).',
                'source_reference': '800-63B-4 § 4.2.1.2',
                'indicator': 'Recovery code lifetimes configured per delivery method',
                'measurement_method': 'SSPR and application recovery flow configuration review; manual audit of Entra ID SSPR expiry settings and any application-level recovery code TTLs',
                'target': 'Per NIST thresholds: ≤21d postal US, ≤30d postal intl, ≤10min SMS/voice, ≤24h email',
                'evaluator': 'alm_11',
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
                'control_id': 'AAL-07',
                'domain': 'AAL2 Authentication Intent',
                'statement': 'Authentication at AAL2 SHOULD demonstrate authentication intent from at least one authenticator.',
                'source_reference': '800-63B-4 § 2.2.2',
                'indicator': '% of AAL2 accounts with intent-demonstrating auth (number matching, tap, biometric)',
                'measurement_method': 'Entra ID MFA settings; verify number matching enabled for push notifications; auth methods report for AAL2 users',
                'target': '100%',
                'evaluator': 'aal_07',
            },
            {
                'control_id': 'AAL-08',
                'domain': 'AAL3 Cryptographic Requirement',
                'statement': 'AAL3 SHALL require multi-factor cryptographic authentication or single-factor cryptographic plus password/biometric. The cryptographic authenticator SHALL have a non-exportable private key and provide phishing resistance.',
                'source_reference': '800-63B-4 § 2.3.1-2.3.2',
                'indicator': '% of AAL3 (T0/T1) accounts using hardware-bound phishing-resistant authenticators',
                'measurement_method': 'Entra ID auth methods for T0/T1 admins; FIDO2 key attestation; WHfB TPM binding',
                'target': '100%',
                'evaluator': 'aal_04',
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
                'control_id': 'PHR-04',
                'domain': 'Non-Exportable Keys (AAL3)',
                'statement': 'Non-exportable authenticator SHALL be separate hardware or embedded processor (SE, TEE, TPM). SHALL prohibit export of auth secret to host processor.',
                'source_reference': '800-63B-4 § 3.2.13',
                'indicator': '% of AAL3 authenticators with hardware-protected non-exportable keys',
                'measurement_method': 'FIDO2 key attestation audit; TPM 2.0 inventory for WHfB devices; Entra ID authentication methods report for T0/T1',
                'target': '100% for T0/T1',
                'evaluator': 'phr_04',
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
                'control_id': 'PWD-07',
                'domain': 'No KBA for Passwords',
                'statement': 'Verifiers SHALL NOT prompt subscribers to use knowledge-based authentication (security questions) when choosing passwords.',
                'source_reference': '800-63B-4 § 3.1.1.2(8)',
                'indicator': 'Number of applications using security questions in password flows',
                'measurement_method': 'Application auth configuration review; Entra ID SSPR method audit',
                'target': '0',
                'evaluator': 'pwd_07',
            },
        ]

        for ctrl_data in controls:
            ctrl, created = Control.objects.update_or_create(
                control_id=ctrl_data['control_id'],
                defaults={**ctrl_data, 'framework': framework},
            )
            action = 'Created' if created else 'Updated'
            self.stdout.write(f'  {action} control: {ctrl.control_id} — {ctrl.domain}')

        self.stdout.write(self.style.SUCCESS(f'Done. {len(controls)} legacy controls seeded.'))
