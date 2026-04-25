from django.core.management.base import BaseCommand
from apps.main.models import Integration, EntraSignInMethodStat
from apps.code_packages.microsoft import getMicrosoftGraphAccessToken


class Command(BaseCommand):
    help = 'Sync Entra ID sign-in method stats (per-user replay-resistance counts, last 30 days)'

    def handle(self, *args, **options):
        from apps.main.integrations.user_integrations.MicrosoftEntraID import syncSignInMethods

        try:
            data = Integration.objects.get(
                integration_type='Microsoft Entra ID',
                integration_context='User',
            )
        except Integration.DoesNotExist:
            self.stdout.write(self.style.ERROR(
                'No Microsoft Entra ID User integration configured.'
            ))
            return

        if not data.client_id or not data.client_secret or not data.tenant_id:
            self.stdout.write(self.style.ERROR(
                'Integration is missing client_id, client_secret, or tenant_id.'
            ))
            return

        access_token = getMicrosoftGraphAccessToken(
            data.client_id, data.client_secret, data.tenant_id,
            ['https://graph.microsoft.com/.default'],
        )
        if isinstance(access_token, dict) and 'error' in access_token:
            self.stdout.write(self.style.ERROR(
                f'Failed to get access token: {access_token["error"]}'
            ))
            return

        self.stdout.write('Syncing sign-in method stats...')
        syncSignInMethods(access_token)

        count = EntraSignInMethodStat.objects.count()
        self.stdout.write(self.style.SUCCESS(
            f'Done. {count} user sign-in stat record(s) in database.'
        ))
