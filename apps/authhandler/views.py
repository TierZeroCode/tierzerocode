from .authentication_backends.MicrosoftEntraID import MicrosoftEntraIDBackend
from .decorators import permission_required_with_message
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.views.decorators.http import require_POST
from django_ratelimit.decorators import ratelimit
from .models import SSOIntegration
from apps.logger.views import createLog
from django.contrib.auth.models import User

@require_POST
@ratelimit(key='ip', rate='10/m', block=True)
def loginUser(request):
    try:
        username = request.POST.get('email').lower()
        password = request.POST.get('password')
        if not password:
            backend = MicrosoftEntraIDBackend()
            user = backend.authenticate(request=request, username=username)
            if user and hasattr(user, '_sso_redirect_url'):
                return redirect(user._sso_redirect_url)
            else:
                messages.error(request, 'Invalid Credentials')
                createLog(request, '1102', 'User Authentication Handler', 'User Login Event', "Admin", True, 'User Login', 'Failure', additional_data='Invalid Credentials (' + str(user) + ')')
                return redirect('login')
        else:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                request.session['admin_upn'] = username
                request.session['active'] = user.is_active
                request.session['user_id'] = user.id
                createLog(request, '1101', 'User Authentication Handler', 'User Login Event', "Admin", True, 'User Login', 'Success', additional_data="Local - " + request.session['admin_upn'])
                return redirect('admin-dashboard')
            else:
                messages.error(request, 'Invalid Credentials')
                createLog(request, '1102', 'User Authentication Handler', 'User Login Event', "Admin", True, 'User Login', 'Failure', additional_data='Invalid Credentials (' + str(e) + ')')
                return redirect('login')
    except Exception as e:
        messages.error(request, 'Invalid Credentials')
        createLog(request, '1102', 'User Authentication Handler', 'User Login Event', "Admin", True, 'User Login', 'Failure', additional_data='Invalid Credentials (' + str(e) + ')')
        return redirect('login')

def azure_callback(request):
    backend = MicrosoftEntraIDBackend()
    return backend.handle_entra_id_callback(request)

@require_POST
def logoutUser(request):
    try:
        data = {
            'session_id': request.session.get('session_id', 'unknown'),
            'user_id': request.session.get('user_id', 'unknown'),
            'ip_address': request.session.get('ip_address', 'unknown'),
            'user_agent': request.session.get('user_agent', 'unknown'),
            'browser': request.session.get('browser', 'unknown'),
            'operating_system': request.session.get('operating_system', 'unknown')
        }
        if request.user.has_usable_password() == False:
            response = MicrosoftEntraIDBackend().logout(request)
            if response['status']:
                messages.success(request, response['message'])
                createLog(request, '1103', 'User Authentication Handler', 'User Logout Event', "Admin", True, 'User Logout', 'Success', additional_data=response['message'])
                return redirect(response['logout_url'])
            else:
                messages.error(request, response['message'])
                createLog(request, '1104', 'User Authentication Handler', 'User Logout Event', "Admin", True, 'User Logout', 'Failure', additional_data=response['message'])
                return redirect('login')
        else:
            try:
                logout(request)
                messages.success(request, 'Logout Successful')
                createLog(request, '1103', 'User Authentication Handler', 'User Logout Event', "Admin", True, 'User Logout', 'Success', additional_data='Logout Successful')
                return redirect('login')
            except Exception as e:
                messages.error(request, str(e))
                createLog(request, '1104', 'User Authentication Handler', 'User Logout Event', "Admin", True, 'User Logout', 'Failure', additional_data=str(e))
                return redirect('login')
    except Exception as e:
        messages.error(request, str(e))
        createLog(request, '1104', 'User Authentication Handler', 'User Logout Event', "Admin", True, 'User Logout', 'Failure', additional_data=str(e))
        return redirect('login')

############################################################################################

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.change_user',"You do not have Permission to Access this Resource", redirect_url='/admin')
def suspendUser(request, id):
    try:
        response = MicrosoftEntraIDBackend().suspend_user(id)
        if response['status']:
            messages.success(request, response['message'])
            createLog(request, '1005', 'User Management', 'User Suspension Event', "Admin", True, 'User Suspension', 'Success', additional_data=response['message'])
        else:
            messages.error(request, response['message'])
            createLog(request, '1006', 'User Management', 'User Suspension Event', "Admin", True, 'User Suspension', 'Failure', additional_data=response['message'])
        return redirect(reverse('general-settings') + '#user-management')
    except Exception as e:
        try:
            messages.error(request, '(' + User.objects.get(id=id).email + ')' + ' (' + str(e) + ')')
            createLog(request, '1006', 'User Management', 'User Suspension Event', "Admin", True, 'User Suspension', 'Failure', additional_data='(' + User.objects.get(id=id).email + ')' + ' (' + str(e) + ')')
        except User.DoesNotExist:
            messages.error(request, 'User ID: ' + id + ' (' + str(e) + ')')
            createLog(request, '1006', 'User Management', 'User Suspension Event', "Admin", True, 'User Suspension', 'Failure', additional_data='User ID: ' + id + ' (' + str(e) + ')')
        return redirect(reverse('general-settings') + '#user-management')

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.change_user',"You do not have Permission to Access this Resource", redirect_url='/admin')
def activateUser(request, id):
    try:
        response = MicrosoftEntraIDBackend().activate_user(id)
        if response['status']:
            messages.success(request, response['message'])
            createLog(request, '1007', 'User Management', 'User Activation Event', "Admin", True, 'User Activation', 'Success', additional_data=response['message'])
        else:
            messages.error(request, response['message'])
            createLog(request, '1008', 'User Management', 'User Activation Event', "Admin", True, 'User Activation', 'Failure', additional_data=response['message'])
        return redirect(reverse('general-settings') + '#user-management')
    except Exception as e:
        try:
            messages.error(request, '(' + User.objects.get(id=id).email + ')' + ' (' + str(e) + ')')
            createLog(request, '1008', 'User Management', 'User Activation Event', "Admin", True, 'User Activation', 'Failure', additional_data='(' + User.objects.get(id=id).email + ')' + ' (' + str(e) + ')')
        except User.DoesNotExist:
            messages.error(request, 'User ID: ' + id + ' (' + str(e) + ')')
            createLog(request, '1008', 'User Management', 'User Activation Event', "Admin", True, 'User Activation', 'Failure', additional_data='User ID: ' + id + ' (' + str(e) + ')')
        return redirect(reverse('general-settings') + '#user-management')

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.delete_user',"You do not have Permission to Access this Resource", redirect_url='/admin')
def deleteUser(request, id):
    try:
        response = MicrosoftEntraIDBackend().delete_user(id)
        if response['status']:
            messages.success(request, response['message'])
            createLog(request, '1009', 'User Management', 'User Deletion Event', "Admin", True, 'User Deletion', 'Success', additional_data=response['message'])
        else:
            messages.error(request, response['message'])
            createLog(request, '1010', 'User Management', 'User Deletion Event', "Admin", True, 'User Deletion', 'Failure', additional_data=response['message'])
        return redirect(reverse('general-settings') + '#user-management')
    except Exception as e:
        try:
            messages.error(request, '(' + User.objects.get(id=id).email + ')' + ' (' + str(e) + ')')
            createLog(request, '1010', 'User Management', 'User Deletion Event', "Admin", True, 'User Deletion', 'Failure', additional_data='(' + User.objects.get(id=id).email + ')' + ' (' + str(e) + ')')
        except User.DoesNotExist:
            messages.error(request, 'User ID: ' + id + ' (' + str(e) + ')')
            createLog(request, '1010', 'User Management', 'User Deletion Event', "Admin", True, 'User Deletion', 'Failure', additional_data='User ID: ' + id + ' (' + str(e) + ')')
        return redirect(reverse('general-settings') + '#user-management')

############################################################################################

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.change_ssointegration',"You do not have Permission to Access this Resource", redirect_url='/admin')
def enableSSOIntegration(request, id):
    try:	
        integration_update = SSOIntegration.objects.get(id=id)
        integration_update.enabled = True
        integration_update.save()
        message = 'SSO Integration Enabled Successfully (' + integration_update.integration_type + ')'
        messages.success(request, message)
        createLog(request, '1201', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Enabled', 'Success', additional_data=message)
        return redirect(reverse('general-settings') + '#sso-integrations')
    except Exception as e:
        try:
            messages.error(request, '(' + integration_update.integration_type + ')' + ' (' + str(e) + ')' )
            createLog(request, '1202', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Disabled', 'Failure', additional_data='(' + integration_update.integration_type + ')' + ' (' + str(e) + ')')
        except SSOIntegration.DoesNotExist:
            messages.error(request, 'SSO Integration ID: ' + id + ' (' + str(e) + ')')
            createLog(request, '1202', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Disabled', 'Failure', additional_data='SSO Integration ID: ' + id + ' (' + str(e) + ')')
        return redirect(reverse('general-settings') + '#sso-integrations')

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.change_ssointegration',"You do not have Permission to Access this Resource", redirect_url='/admin')
def disableSSOIntegration(request, id):
    try:
        integration_update = SSOIntegration.objects.get(id=id)
        integration_update.enabled = False
        integration_update.save()
        message = 'SSO Integration Disabled Successfully (' + integration_update.integration_type + ')'
        messages.success(request, message)
        createLog(request, '1203', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Disabled', 'Success', additional_data=message)
        return redirect(reverse('general-settings') + '#sso-integrations')
    except Exception as e:
        try:
            messages.error(request, '(' + integration_update.integration_type + ')' + ' (' + str(e) + ')' )
            createLog(request, '1204', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Disabled', 'Failure', additional_data='(' + integration_update.integration_type + ')' + ' (' + str(e) + ')')
        except SSOIntegration.DoesNotExist:
            messages.error(request, 'SSO Integration ID: ' + id + ' (' + str(e) + ')')
            createLog(request, '1204', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Disabled', 'Failure', additional_data='SSO Integration ID: ' + id + ' (' + str(e) + ')')
        return redirect(reverse('general-settings') + '#sso-integrations')

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.change_ssointegration',"You do not have Permission to Access this Resource", redirect_url='/admin')
def updateSSOIntegration(request, id):
    try:
        integration_update = SSOIntegration.objects.get(id=id)
        integration_update.client_id = request.POST['client_id']
        integration_update.client_secret = request.POST['client_secret']
        integration_update.tenant_id = request.POST['tenant_id']
        integration_update.tenant_domain = request.POST['tenant_domain']
        integration_update.save()
        message = 'SSO Integration Configured Successfully (' + integration_update.integration_type + ')'
        messages.success(request, message)
        createLog(request, '1205', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Configured', 'Success', additional_data=message)
        return redirect(reverse('general-settings') + '#sso-integrations')
    except Exception as e:
        try:
            messages.error(request, '(' + integration_update.integration_type + ')' + ' (' + str(e) + ')' )
            createLog(request, '1206', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Configured', 'Failure', additional_data='(' + integration_update.integration_type + ')' + ' (' + str(e) + ')')
        except SSOIntegration.DoesNotExist:
            messages.error(request, 'SSO Integration ID: ' + id + ' (' + str(e) + ')')
            createLog(request, '1206', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Configured', 'Failure', additional_data='SSO Integration ID: ' + id + ' (' + str(e) + ')')
        return redirect(reverse('general-settings') + '#sso-integrations')

############################################################################################

# Function to generate a random password
def generate_random_password(length=15):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password