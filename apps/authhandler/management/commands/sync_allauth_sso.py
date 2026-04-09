from django.core.management.base import BaseCommand
from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site
from apps.authhandler.models import SSOIntegration


class Command(BaseCommand):
    help = 'Sync SSOIntegration credentials to django-allauth SocialApp'

    def handle(self, *args, **options):
        sso = SSOIntegration.objects.filter(
            enabled=True,
            integration_type='Microsoft Entra ID'
        ).first()

        if not sso:
            self.stdout.write(self.style.WARNING('No enabled Microsoft Entra ID SSO integration found.'))
            return

        if not sso.client_id or not sso.client_secret:
            self.stdout.write(self.style.ERROR('SSO integration missing client_id or client_secret.'))
            return

        app, created = SocialApp.objects.update_or_create(
            provider='microsoft',
            defaults={
                'name': 'Microsoft Entra ID',
                'client_id': sso.client_id,
                'secret': sso.client_secret,
                'settings': {
                    'tenant': sso.tenant_id or 'common',
                },
            },
        )

        # Ensure app is linked to the current site
        site = Site.objects.get_current()
        if not app.sites.filter(pk=site.pk).exists():
            app.sites.add(site)

        action = 'Created' if created else 'Updated'
        self.stdout.write(self.style.SUCCESS(
            f'{action} SocialApp for Microsoft Entra ID '
            f'(client_id: {sso.client_id[:8]}..., tenant: {sso.tenant_id})'
        ))
