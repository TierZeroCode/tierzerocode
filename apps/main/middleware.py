from django.shortcuts import redirect
from django.core.cache import cache
from .checks import checkSystemDeviceIntegrations, checkSystemUserIntegrations, checkDeviceComplianceSettings, systemDeviceInitialSetup, systemUserInitialSetup, deviceComplianceSettingsInitialSetup

CACHE_KEY = 'model_verification_status'
CACHE_TTL = 60  # seconds

class ModelVerificationMiddleware:
    """
    Middleware to verify required models exist and redirect to setup if needed.
    Uses caching to avoid repeated database queries on every request.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip verification for non-authenticated or non-staff users
        if not (request.user.is_authenticated and request.user.is_staff):
            return self.get_response(request)

        # Skip verification for static files and login paths
        skip_paths = ['/static/', '/identity/']
        if any(request.path.startswith(path) for path in skip_paths):
            return self.get_response(request)

        # Check cache first — avoid 3 DB queries on every request
        verification_status = cache.get(CACHE_KEY)
        if verification_status is None:
            verification_status = self._perform_model_verification_checks()
            cache.set(CACHE_KEY, verification_status, CACHE_TTL)

        if verification_status['system_device_integrations']:
            systemDeviceInitialSetup()
            cache.delete(CACHE_KEY)
        if verification_status['system_user_integrations']:
            systemUserInitialSetup()
            cache.delete(CACHE_KEY)
        if verification_status['device_compliance_settings']:
            deviceComplianceSettingsInitialSetup()
            cache.delete(CACHE_KEY)

        return self.get_response(request)

    def _perform_model_verification_checks(self):
        """Perform all verification checks and return status."""
        return {
            'system_device_integrations': not checkSystemDeviceIntegrations(),
            'system_user_integrations': not checkSystemUserIntegrations(),
            'device_compliance_settings': not checkDeviceComplianceSettings(),
        }
