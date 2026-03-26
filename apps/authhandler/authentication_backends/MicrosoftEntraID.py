import logging
import secrets
from django.contrib.auth.models import User
from django.contrib.auth.backends import BaseBackend
from apps.authhandler.models import SSOIntegration
from apps.logger.views import createLog
from urllib.parse import urlencode, quote_plus, urlparse, urlunparse
from django.contrib.auth import logout
from django.conf import settings

logger = logging.getLogger(__name__)

class MicrosoftEntraIDBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:           
            # Get Entra ID configuration
            sso_config = self._get_sso_config()
            if not sso_config or not sso_config.enabled:
                createLog(request, '1503', 'Claim ID', 'Authentication', "Unauthenticated", False, 'Microsoft Entra ID Login', 'Failure', additional_data="Microsoft Entra ID SSO is not enabled or configured")
                return None
            
            try:
                user = User.objects.get(username=username)
                if user:
                    return self._handle_sso_login(request, user, sso_config)
            except User.DoesNotExist:
                # return "User Does Not Exist"
                pass
            return None
            
        except Exception as e:
            logger.error(f"Microsoft Entra ID authentication error: {str(e)}")
            
            # Log authentication failure
            if hasattr(request, 'session') and 'session_id' in request.session:
                createLog(request, '1502', 'Claim ID', 'Authentication', "Unauthenticated", False, 'Microsoft Entra ID Login', 'Failure', additional_data=f"Authentication failed: {str(e)}")
            return None
    
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
    
    def _get_sso_config(self):
        try:
            return SSOIntegration.objects.filter(integration_type="Microsoft Entra ID",enabled=True).first()
        except Exception as e:
            logger.error(f"Error getting SSO configuration: {str(e)}")
            return None
    
    def _handle_sso_login(self, request, user, sso_config):
        """
        Description: Handle SSO login flow for existing users.   
        Returns: User object if user exists and SSO is initiated, None otherwise
        """
        try:
            if user and not user.has_usable_password() and user.is_active:
                # User exists, has no password (SSO user), and is active
                # Generate SSO login URL
                auth_url = self._generate_sso_auth_url(request, user, sso_config)
                
                # Store the redirect URL in session for after SSO callback
                if hasattr(request, 'session'):
                    request.session['sso_redirect_url'] = request.GET.get('next', '/')
                
                # Return a special response that indicates SSO redirect needed
                # We'll use a custom attribute to signal this
                user._sso_redirect_url = auth_url
                return user
            else:
                logger.warning(f"User {user.username} not found, has password, or is inactive")
                return None
            
        except Exception as e:
            logger.error(f"Error handling SSO login for {user.username}: {str(e)}")
            return None
            
    def _generate_sso_auth_url(self, request, user, sso_config):
        """
        Description: Generate Microsoft Entra ID SSO authentication URL.    
        Returns: SSO authentication URL
        """
        try:
            # Build redirect URI
            DEBUG = settings.DEBUG
            if DEBUG:
                # redirect_uri = urlunparse(urlparse(request.build_absolute_uri("/admin/azure/callback/"))._replace(scheme="http"))
                redirect_uri = urlunparse(urlparse(request.build_absolute_uri("/identity/azure/callback/"))._replace(scheme="http"))
            else:
                # redirect_uri = urlunparse(urlparse(request.build_absolute_uri("/admin/azure/callback/"))._replace(scheme="https"))
                redirect_uri = urlunparse(urlparse(request.build_absolute_uri("/identity/azure/callback/"))._replace(scheme="https"))
            
            # Generate cryptographic state nonce for CSRF protection
            oauth_state = secrets.token_urlsafe(32)
            if hasattr(request, 'session'):
                request.session['oauth_state'] = oauth_state

            # OAuth2 parameters
            params = {
                'client_id': sso_config.client_id,
                'response_type': 'code',
                'redirect_uri': redirect_uri,
                'response_mode': 'query',
                'scope': 'openid profile email',
                'state': oauth_state
            }
            
            # Build authorization URL with user's email as login hint
            login_hint = user.email if user.email else user.username
            auth_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/authorize?login_hint={}&{}'.format(
                sso_config.tenant_id,
                login_hint,
                urlencode(params, quote_via=quote_plus)
            )
            
            return auth_url
            
        except Exception as e:
            logger.error(f"Error generating SSO auth URL: {str(e)}")
            return None
    
    def exchange_code_for_token(self, sso_config, authorization_code, redirect_uri):
        """
        Description: Exchange authorization code for access token.            
        Returns: Dict containing token information or None if failed
        """
        try:
            import requests
            
            token_url = f"https://login.microsoftonline.com/{sso_config.tenant_id}/oauth2/v2.0/token"
            
            data = {
                'client_id': sso_config.client_id,
                'client_secret': sso_config.client_secret,
                'code': authorization_code,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code',
                'scope': 'openid profile email',  # Required scope parameter
            }
            
            response = requests.post(token_url, data=data)
            
            # Log error information for debugging (never log client_secret or tokens)
            if response.status_code != 200:
                logger.error(f"Token exchange failed with status {response.status_code}")
                logger.error(f"Token exchange failed for client_id={sso_config.client_id}, tenant_id={sso_config.tenant_id}")
                return None
                
            response.raise_for_status()
            return response.json()
                
        except Exception as e:
            logger.error(f"Error exchanging code for token: {str(e)}")
            return None
    
    def get_user_info_from_token(self, access_token):
        """
        Description: Get user information from Microsoft Graph API using access token.
        Returns: Dict containing user information or None if failed
        """
        try:
            import requests
            
            graph_url = "https://graph.microsoft.com/v1.0/me"
            headers = {'Authorization': f'Bearer {access_token}','Content-Type': 'application/json'}
            response = requests.get(graph_url, headers=headers)
            
            # Log detailed error information for debugging
            if response.status_code == 403:
                logger.error(f"Graph API 403 Forbidden - Token may lack required permissions")
                logger.error(f"Response: {response.text}")
                # Try to get token info for debugging
                try:
                    token_info_url = "https://graph.microsoft.com/v1.0/me"
                    token_response = requests.get(token_info_url, headers=headers)
                    logger.error(f"Token validation response: {token_response.status_code} - {token_response.text}")
                except:
                    pass
                return None
            
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP Error getting user info from Graph API: {str(e)}")
            logger.error(f"Response status: {response.status_code}")
            logger.error(f"Response text: {response.text}")
            return None
        except Exception as e:
            logger.error(f"Error getting user info from Graph API: {str(e)}")
            return None
    
    def _extract_user_info_from_id_token(self, id_token):
        """
        Description: Extract user information from ID token with signature verification.
        Returns: Dict containing user information or None if failed
        """
        try:
            import jwt
            from jwt import PyJWKClient

            # Get SSO config for tenant_id and client_id
            sso_config = self._get_sso_config()
            if not sso_config:
                logger.error("Cannot validate ID token: SSO configuration not found")
                return None

            # Verify signature against Microsoft's published JWKS
            jwks_url = f"https://login.microsoftonline.com/{sso_config.tenant_id}/discovery/v2.0/keys"
            jwks_client = PyJWKClient(jwks_url)
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)

            payload = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=sso_config.client_id,
                issuer=f"https://login.microsoftonline.com/{sso_config.tenant_id}/v2.0",
            )

            # Extract user information from ID token claims
            user_info = {
                'id': payload.get('oid'),  # Object ID
                'userPrincipalName': payload.get('preferred_username'),
                'mail': payload.get('email'),
                'givenName': payload.get('given_name'),
                'surname': payload.get('family_name'),
                'displayName': payload.get('name'),
            }

            logger.info(f"Successfully extracted user info from ID token for: {user_info.get('userPrincipalName')}")
            return user_info

        except Exception as e:
            logger.error(f"Error extracting/validating ID token: {str(e)}")
            return None
    
    def handle_entra_id_callback(self, request):
        """
        Handle Microsoft Entra ID authentication callback.
        
        This function processes the authentication callback from Microsoft Entra ID,
        validates the token, and logs the user in.
            
        Returns: Redirect response or error response
        """
        try:
            from django.contrib.auth import login
            from django.shortcuts import redirect
            from django.contrib import messages
            from urllib.parse import urlparse, urlunparse
            
            # Get authorization code from callback
            code = request.GET.get('code')
            state = request.GET.get('state')

            # Validate OAuth state parameter to prevent CSRF
            expected_state = request.session.pop('oauth_state', None)
            if not state or state != expected_state:
                logger.warning(f"OAuth state mismatch: expected={expected_state}, received={state}")
                createLog(request, '1102', 'User Authentication Handler', 'User Login Event', "Unauthenticated", False, 'Microsoft Entra ID Login', 'Failure', additional_data='OAuth state parameter mismatch - possible CSRF attack')
                messages.error(request, 'Authentication failed: invalid state parameter. Please try again.')
                return redirect('login')

            if not code:
                messages.error(request, 'No authorization code received from Microsoft Entra ID')
                return redirect('login')
            
            # Get SSO configuration
            sso_config = self._get_sso_config()
            if not sso_config:
                messages.error(request, 'Microsoft Entra ID configuration not found')
                return redirect('login')
            
            # Build redirect URI (must match the one used in authorization URL)
            DEBUG = settings.DEBUG
            if DEBUG:
                # redirect_uri = urlunparse(urlparse(request.build_absolute_uri("/admin/azure/callback/"))._replace(scheme="http"))
                redirect_uri = urlunparse(urlparse(request.build_absolute_uri("/identity/azure/callback/"))._replace(scheme="http"))
            else:
                # redirect_uri = urlunparse(urlparse(request.build_absolute_uri("/admin/azure/callback/"))._replace(scheme="https"))
                redirect_uri = urlunparse(urlparse(request.build_absolute_uri("/identity/azure/callback/"))._replace(scheme="https"))
            
            # Exchange code for token
            token_data = self.exchange_code_for_token(sso_config, code, redirect_uri)
            if not token_data or 'access_token' not in token_data:
                messages.error(request, 'Failed to exchange authorization code for token (' + str(token_data) + ')')
                # Safe session variable access
                session_id = request.session.get('session_id', 'unknown')
                user_id = request.session.get('user_id', 'unknown')
                ip_address = request.session.get('ip_address', 'unknown')
                user_agent = request.session.get('user_agent', 'unknown')
                browser = request.session.get('browser', 'unknown')
                operating_system = request.session.get('operating_system', 'unknown')
                
                createLog(session_id, '1102', 'User Authentication Handler', 'User Login Event', "Admin", True, 'User Login', 'Failure', 'Failed to exchange authorization code for token (' + str(token_data) + ')', user_id, ip_address, user_agent, browser, operating_system)
                return redirect('login')
            
            # Try to get user info from access token first
            user_info = self.get_user_info_from_token(token_data['access_token'])
            
            # If access token fails, try to use ID token if available
            if not user_info and 'id_token' in token_data:
                logger.info("Access token failed, trying ID token for user info")
                user_info = self._extract_user_info_from_id_token(token_data['id_token'])
            
            if not user_info:
                messages.error(request, 'Failed to get user information from Microsoft. Please check permissions.')
                return redirect('login')
            
            # Get user by username from the user info
            username = user_info.get('userPrincipalName').lower() or user_info.get('mail').lower()
            if not username:
                messages.error(request, 'No username found in user information')
                return redirect('login')
            
            # Keep full username (including domain) for UPN matching
            # Username will be used as-is for user lookup
            
            logger.info(f"Looking for user with username: {username}")
            
            # Get the user
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                user = None
            
            if user:
                # Log the user in
                login(request, user, backend='apps.authhandler.authentication_backends.MicrosoftEntraID.MicrosoftEntraIDBackend')
                if request.user.is_authenticated:
                    print (f"User {user.username} logged in successfully")
                
                # Get redirect URL from session
                redirect_url = request.session.get('sso_redirect_url', '/')
                if 'sso_redirect_url' in request.session:
                    del request.session['sso_redirect_url']
                
                messages.success(request, f"Welcome back, {user.first_name or user.username}!")
                
                # ADDITIONAL SESSION VARIABLES
                request.session['admin_upn'] = user.email
                request.session['active'] = user.is_active
                request.session['user_id'] = user.id
                request.session['username'] = user.username
                request.session['first_name'] = user.first_name
                request.session['last_name'] = user.last_name
                request.session['is_staff'] = user.is_staff
                request.session['is_superuser'] = user.is_superuser
                # END ADDITIONAL SESSION VARIABLES

                request.session.save()
                return redirect(redirect_url)
            else:
                messages.error(request, f'User {username} not found. Please contact administrator.')
                return redirect('login')
                
        except Exception as e:
            logger.error(f"Error handling Azure callback: {str(e)}")
            messages.error(request, 'An error occurred during authentication. Please try again.')
            return redirect('login')

    def logout(self, request):
        """
        Description: This method generates the Microsoft logout URL and performs local logout.
        Returns: Redirect response to Microsoft logout URL
        """
        try:
            sso_integration = self._get_sso_config()
            if not sso_integration:
                logout(request)
                return {'status': True, 'message': 'Microsoft Entra ID - Logout Successful'}
            logout(request)
            logout_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/logout?post_logout_redirect_uri={}'.format(
                sso_integration.tenant_id,
                urlunparse(urlparse(request.build_absolute_uri("login-sso"))._replace(scheme="https"))
            )
            # return redirect(logout_url)
            return {'status': True, 'message': 'Microsoft Entra ID - Logout Successful', 'logout_url': logout_url}
        except Exception as e:
            logout(request)
            return {'status': False, 'message': 'Microsoft Entra ID - Logout Failed (' + str(e) + ')'}

    def suspend_user(self, user_id):
        """
        Description: Suspend a user.
        Returns: True / False
        """
        try:
            user = User.objects.get(id=user_id)
            user.is_active = False
            user.save()
            return {'status': True, 'message': 'User Suspension Successful (' + user.email + ')'}
        except Exception as e:
            return {'status': False, 'message': '(' + user.email + ')' + ' (' + str(e) + ')'}
    
    def activate_user(self, user_id):
        """
        Description: Activate a user.
        Returns: True / False
        """
        try:
            user = User.objects.get(id=user_id)
            user.is_active = True
            user.save()
            return {'status': True, 'message': 'User Activation Successful (' + user.email + ')'}
        except Exception as e:
            return {'status': False, 'message': '(' + user.email + ')' + ' (' + str(e) + ')'}
    
    def delete_user(self, user_id):
        """
        Description: Delete a user.
        Returns: True / False
        """
        try:
            user = User.objects.get(id=user_id)
            user.delete()
            return {'status': True, 'message': 'User Deletion Successful (' + user.email + ')'}
        except Exception as e:
            return {'status': False, 'message': '(' + user.email + ')' + ' (' + str(e) + ')'}