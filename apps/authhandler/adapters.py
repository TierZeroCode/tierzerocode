from django.contrib.auth import get_user_model
from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


User = get_user_model()


class AccountAdapter(DefaultAccountAdapter):
    """Custom adapter to control local account behavior."""

    def is_open_for_signup(self, request):
        # Disable local signup — users are created by admins or via SSO
        return False

    def get_login_redirect_url(self, request):
        return '/'


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    """Custom adapter for Microsoft Entra ID auto-provisioning.

    - Existing users: auto-connect by email match (no confirmation page)
    - New users: auto-create with is_staff=True
    """

    def is_open_for_signup(self, request, sociallogin):
        # Allow auto-provisioning for SSO users
        return True

    def pre_social_login(self, request, sociallogin):
        """Auto-connect SSO login to existing user by email match."""
        if sociallogin.is_existing:
            return

        email = sociallogin.account.extra_data.get('mail') or sociallogin.account.extra_data.get('userPrincipalName', '')
        if not email:
            return

        try:
            user = User.objects.get(email__iexact=email)
            sociallogin.connect(request, user)
        except User.DoesNotExist:
            pass
        except User.MultipleObjectsReturned:
            user = User.objects.filter(email__iexact=email).first()
            if user:
                sociallogin.connect(request, user)

    def populate_user(self, request, sociallogin, data):
        """Populate user fields from Microsoft Entra ID claims."""
        user = super().populate_user(request, sociallogin, data)
        user.is_staff = True
        return user

    def save_user(self, request, sociallogin, form=None):
        """Save the auto-provisioned user."""
        user = super().save_user(request, sociallogin, form)
        user.is_staff = True
        user.save(update_fields=['is_staff'])
        return user
