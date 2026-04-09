from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


class AccountAdapter(DefaultAccountAdapter):
    """Custom adapter to control local account behavior."""

    def is_open_for_signup(self, request):
        # Disable local signup — users are created by admins or via SSO
        return False

    def get_login_redirect_url(self, request):
        return '/'


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    """Custom adapter for Microsoft Entra ID auto-provisioning."""

    def is_open_for_signup(self, request, sociallogin):
        # Allow auto-provisioning for SSO users
        # Microsoft Entra ID with required user assignment handles authorization
        return True

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
