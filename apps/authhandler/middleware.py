from django.shortcuts import redirect
from apps.authhandler.checks import checkUserCount, checkSSOIntegrations, ssoInitialSetup
from apps.logger.views import createLog

class AuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # --- 1. FORCE SESSION CREATION (With Logging) ---
        if not request.session.session_key:
            try:
                request.session.save()
                
                # Success Log (Code 1105)
                createLog(request, '1105', 'User Authentication Handler', 'User Session Event', "System", True, 'User Session Creation', 'Success', additional_data='Session Creation Success')

            except Exception as e:
                # Failure Log (Code 1106)
                # We catch the error so we can log it, then re-raise it or handle it gracefully
                createLog(request, '1106', 'User Authentication Handler', 'User Session Event', "System", True, 'User Session Creation', 'Failure', additional_data='Session Creation Failed (' + str(e) + ')')
                # Optional: You might want to return a 500 error page here if session creation is critical

        # --- 2. DEFINE EXEMPT PATHS ---
        setup_paths = [
            '/identity/unclaimed',
            '/static/',
        ]
        # Only exempt accountcreation during initial setup (no users exist)
        if not checkUserCount():
            setup_paths.append('/identity/accountcreation')

        if any(request.path.startswith(path) for path in setup_paths):
            return self.get_response(request)

        # --- 3. GLOBAL SETUP CHECKS ---
        if not checkUserCount():
            return redirect('unclaimed')

        if request.user.is_authenticated and request.user.is_staff:
            verification_status = self._perform_verification_checks()
            if verification_status['sso_integrations']:
                ssoInitialSetup()
                return redirect('admin-dashboard')
        
        response = self.get_response(request)
        return response

    def _perform_verification_checks(self):
        return {
            'sso_integrations': not checkSSOIntegrations(),
        }