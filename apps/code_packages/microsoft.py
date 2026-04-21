import logging
import msal, jwt, requests
from django.utils import timezone

logger = logging.getLogger(__name__)
from datetime import timedelta
# from apps.main.models import GeneralSetting
from apps.logger.views import createLog

def getMicrosoftGraphAccessToken(client_id, client_secret, tenant_id, scope):
    try:
        authority = 'https://login.microsoftonline.com/' + tenant_id
        client = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)
        token_result = client.acquire_token_silent(scope, account=None)
        if token_result:
            access_token = 'Bearer ' + token_result['access_token']
        if not token_result:
            token_result = client.acquire_token_for_client(scopes=scope)
            access_token = 'Bearer ' + token_result['access_token']
        return access_token
    except Exception as e:        
        return {'error': e}

def testMicrosoftGraphConnection(access_token, required_permissions, tenant_id=None):
    try:
        token = access_token.replace('Bearer ', '') if access_token.startswith('Bearer ') else access_token
        # Validate token signature against Microsoft JWKS when tenant_id is available
        if tenant_id:
            from jwt import PyJWKClient
            jwks_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
            jwks_client = PyJWKClient(jwks_url)
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(token, signing_key.key, algorithms=["RS256"], audience="https://graph.microsoft.com")
        else:
            payload = jwt.decode(token, options={"verify_signature": False})
        # Extract scopes - can be in 'scp' (delegated tokens) or 'roles' (application tokens)
        # 'scp' can be a string (space-separated) or list, 'roles' is typically a list
        scp = payload.get('scp', '')
        roles_claim = payload.get('roles', [])
        
        if scp:
            if isinstance(scp, str):
                roles = scp.split()
            elif isinstance(scp, list):
                roles = scp
            else:
                roles = []
        # Fallback to roles claim if scp is not available
        elif roles_claim:
            if isinstance(roles_claim, list):
                roles = roles_claim
            elif isinstance(roles_claim, str):
                roles = roles_claim.split()
            else:
                roles = []
        else:
            roles = []
        has_required = any(permission in roles for permission in required_permissions)
        return {'roles': roles, 'has_required_permissions': has_required}
    except Exception as e:
        logger.error("Error decoding access token: %s", str(e))
        return {'roles': [], 'has_required_permissions': False}

class MicrosoftEntraIDUser:
    def __init__(self, userPrincipalName):
        self.id = None
        self.accountEnabled = None
        self.userPrincipalName = userPrincipalName
        self.givenName = None
        self.surname = None
        self.displayName = None
        self.personalEmail = None
        self.networkId = None
    
    def _to_dict(self):
        return {
            'id': self.id,
            'accountEnabled': self.accountEnabled,
            'userPrincipalName': self.userPrincipalName,
            'givenName': self.givenName,
            'surname': self.surname,
            'displayName': self.displayName,
            'personalEmail': self.personalEmail,
            'networkId': self.networkId
        }
    
    def __json__(self):
        """Make the object JSON serializable for Django sessions"""
        return self._to_dict()
    
    @classmethod
    def from_dict(cls, data):
        """Create a MicrosoftEntraIDUser object from a dictionary"""
        user = cls(data.get('userPrincipalName', ''))
        user.id = data.get('id')
        user.accountEnabled = data.get('accountEnabled')
        user.givenName = data.get('givenName')
        user.surname = data.get('surname')
        user.displayName = data.get('displayName')
        user.personalEmail = data.get('personalEmail')
        user.networkId = data.get('networkId')
        return user
    
    def getUser(self, access_token):
        try:
            url = 'https://graph.microsoft.com/v1.0/users/' + self.userPrincipalName + '/?$select=givenName,surname,userPrincipalName,id,accountEnabled,employeeId,extension_09474e7580ed457a8d48b4d8698a8f68_eskPulseMail'
            headers = {'Authorization': access_token}
            response = requests.get(url, headers=headers)
            return response.json()
        except Exception as e:
            return {'error': e}
    
    def getEmailAuthenticationMethod(self, access_token):
        try:
            url = 'https://graph.microsoft.com/v1.0/users/' + self.userPrincipalName + '/authentication/emailMethods?$select=emailAddress'
            headers = {'Authorization': access_token}
            response = requests.get(url, headers=headers)
            return response.json()
        except Exception as e:
            return {'error': e}
    
    def enableUserAccount(self, access_token):
        try:
            url = 'https://graph.microsoft.com/v1.0/users/' + self.userPrincipalName
            headers = {'Authorization': access_token, 'Content-Type': 'application/json'}
            body = {"accountEnabled": True}
            graph_result = requests.patch(url=url, headers=headers, json=body)
            return graph_result
        except Exception as e:
            return {'error': e}
    
    def getTemporaryAccessPass(self, request, access_token):
        try:
            url = f'https://graph.microsoft.com/v1.0/users/{self.userPrincipalName}/authentication/temporaryAccessPassMethods'
            headers = {'Authorization': access_token, 'Content-Type': 'application/json'}
            tap_code_lifetime = GeneralSetting.objects.get(setting_name='TAP Code - Minutes to Expiration').setting_value
            tap_code_use_once = GeneralSetting.objects.get(setting_name='TAP Code - One Time Use').setting_value
            body = {
                "startDateTime": str((timezone.now() + timedelta(seconds=20)).strftime('%Y-%m-%dT%H:%M:%S')),
                "lifetimeInMinutes": int(tap_code_lifetime),
                "isUsableOnce": tap_code_use_once,
            }
            graph_result = requests.post(url=url, headers=headers, json=body)
            graph_data = graph_result.json()
            try:
                createLog(request, '1703', 'Application', 'Manage ID', "Unauthenticated", False, 'TAP Code Generation', 'Success', additional_data=self.userPrincipalName + " - TAP Issued")
            except Exception as e:
                # Log error
                pass
            return graph_data
        except Exception as e:
            return {'error': e}
    
    def groupManagement(self, group_id, action, access_token):  
        try:
            headers = {'Authorization': access_token, 'Content-Type': 'application/json'}
            if action == 'opt-in':
                url = f'https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref'
                body = {'@odata.id': f'https://graph.microsoft.com/v1.0/directoryObjects/{self.id}'}
                response = requests.post(url, headers=headers, json=body)
            elif action == 'opt-out':
                url = f'https://graph.microsoft.com/v1.0/groups/{group_id}/members/{self.id}/$ref'
                response = requests.delete(url, headers=headers)
            logger.info("Group management response: %s", response.status_code)
            return response.status_code == 204
        except Exception as e:
            return {'error': e}
    
    def getAuthenticationMethods(self, access_token):
        try:
            url = f"https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?$filter=userPrincipalName eq '{self.userPrincipalName}'&$select=userPrincipalName,isAdmin,isSsprRegistered,isSsprEnabled,isSsprCapable,isMfaRegistered,isMfaCapable,isPasswordlessCapable,methodsRegistered"
            headers = {'Authorization': access_token}
            response = requests.get(url, headers=headers)  
            return response.json()
        except requests.RequestException as e:
            # Log error
            return {'error': 'Network error'}
        except Exception as e:
            # Log error
            return {'error': 'Unknown error'}