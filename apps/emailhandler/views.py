import requests
from apps.main.models import GeneralSetting
from django.contrib import messages
from django.shortcuts import redirect
from apps.logger.views import createLog
from apps.emailhandler.models import EmailIntegration
from apps.authhandler.decorators import permission_required_with_message

# Sends Email via Microsoft Graph API
def sendEmail(email, subject, body, access_token, importance='high', bcc='idam@email.com'):
    try:
        sender = GeneralSetting.objects.get(setting_name='User Verification - Email Address').setting_value
    except Exception as e:
        # Log error
        return False
    url = f'https://graph.microsoft.com/v1.0/users/{sender}/sendMail'
    headers = {'Authorization': access_token}
    body_data = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "HTML",
                "content": body
            },
            "toRecipients": [
                {"emailAddress": {"address": email}},
            ],
            "bccRecipients": [
                {"emailAddress": {"address": bcc}}
            ],
            "importance": importance
        },
        "saveToSentItems": "true"
    }
    try:
        response = requests.post(url=url, headers=headers, json=body_data)
        if response.status_code == 202:
            print('Email sent successfully')
            return True
        else:
            print(f'Error sending email: {response.status_code}')
            print(response.json())
            return False
    except Exception as e:
        # Log error
        return False

####################################################################################################################################################################

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.change_emailintegration',"You do not have Permission to Access this Resource", redirect_url='/admin')
def enableEmailIntegration(request, id):
    try:	
        integration_update = EmailIntegration.objects.get(id=id)
        integration_update.enabled = True
        integration_update.save()
        message = 'Email Integration Enabled Successfully (' + integration_update.integration_type + ')'
        messages.success(request, message)
        createLog(request, '1201', 'Email Integration', 'Email Integration Event', "Admin", True, 'Email Integration Enabled', 'Success', additional_data=message)
        return redirect ('system-integrations')
    except Exception as e:
        try:
            messages.error(request, '(' + integration_update.integration_type + ')' + ' (' + str(e) + ')' )
            createLog(request, '1202', 'Email Integration', 'Email Integration Event', "Admin", True, 'Email Integration Disabled', 'Failure', additional_data='(' + integration_update.integration_type + ')' + ' (' + str(e) + ')')
        except EmailIntegration.DoesNotExist:
            messages.error(request, 'Email Integration ID: ' + id + ' (' + str(e) + ')')
            createLog(request, '1202', 'Email Integration', 'Email Integration Event', "Admin", True, 'Email Integration Disabled', 'Failure', additional_data='Email Integration ID: ' + id + ' (' + str(e) + ')')
        return redirect ('system-integrations')

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.change_emailintegration',"You do not have Permission to Access this Resource", redirect_url='/admin')
def disableEmailIntegration(request, id):
    try:
        integration_update = EmailIntegration.objects.get(id=id)
        integration_update.enabled = False
        integration_update.save()
        message = 'Email Integration Disabled Successfully (' + integration_update.integration_type + ')'
        messages.success(request, message)
        createLog(request, '1203', 'Email Integration', 'Email Integration Event', "Admin", True, 'Email Integration Disabled', 'Success', additional_data=message)
        return redirect ('system-integrations')
    except Exception as e:
        try:
            messages.error(request, '(' + integration_update.integration_type + ')' + ' (' + str(e) + ')' )
            createLog(request, '1204', 'Email Integration', 'Email Integration Event', "Admin", True, 'Email Integration Disabled', 'Failure', additional_data='(' + integration_update.integration_type + ')' + ' (' + str(e) + ')')
        except EmailIntegration.DoesNotExist:
            messages.error(request, 'Email Integration ID: ' + id + ' (' + str(e) + ')')
            createLog(request, '1204', 'Email Integration', 'Email Integration Event', "Admin", True, 'Email Integration Disabled', 'Failure', additional_data='Email Integration ID: ' + id + ' (' + str(e) + ')')
        return redirect ('system-integrations')

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.change_emailintegration',"You do not have Permission to Access this Resource", redirect_url='/admin')
def updateEmailIntegration(request, id):
    try:
        integration_update = EmailIntegration.objects.get(id=id)
        integration_update.client_id = request.POST['client_id']
        integration_update.client_secret = request.POST['client_secret']
        integration_update.tenant_id = request.POST['tenant_id']
        integration_update.tenant_domain = request.POST['tenant_domain']
        integration_update.save()
        message = 'Email Integration Configured Successfully (' + integration_update.integration_type + ')'
        messages.success(request, message)
        createLog(request, '1205', 'Email Integration', 'Email Integration Event', "Admin", True, 'Email Integration Configured', 'Success', additional_data=message)
        return redirect ('system-integrations')
    except Exception as e:
        try:
            messages.error(request, '(' + integration_update.integration_type + ')' + ' (' + str(e) + ')' )
            createLog(request, '1206', 'Email Integration', 'Email Integration Event', "Admin", True, 'Email Integration Configured', 'Failure', additional_data='(' + integration_update.integration_type + ')' + ' (' + str(e) + ')')
        except EmailIntegration.DoesNotExist:
            messages.error(request, 'Email Integration ID: ' + id + ' (' + str(e) + ')')
            createLog(request, '1206', 'Email Integration', 'Email Integration Event', "Admin", True, 'Email Integration Configured', 'Failure', additional_data='Email Integration ID: ' + id + ' (' + str(e) + ')')
        return redirect ('system-integrations')