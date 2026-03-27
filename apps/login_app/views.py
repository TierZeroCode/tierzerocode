# Import Django Modules
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.http import HttpResponseForbidden
# Import Django User Model
from django.contrib.auth.models import User
# Import Models
from ..authhandler.models import SSOIntegration
from ..authhandler.views import *

############################################################################################
	
def getEnabledSSOIntegrations():
    return SSOIntegration.objects.filter(enabled=True)

############################################################################################

def unclaimed(request):
	if User.objects.all().count() > 0:
		return redirect('login')
	else:
		return render(request, 'login_app/unclaimed.html')

############################################################################################

def login_page(request):
    if request.user.is_authenticated:
        return redirect('index')
    enabled_sso = getEnabledSSOIntegrations()
    context = {
        'sso': bool(enabled_sso),
        'enabledSSOIntegrations': enabled_sso
    }
    return render(request, 'login_app/login.html', context)
		
############################################################################################

def accountcreation(request):
	# Security: If users already exist, require authentication and superuser status
	is_initial_setup = not User.objects.exists()
	if not is_initial_setup:
		if not request.user.is_authenticated:
			return redirect('login')
		if not request.user.is_superuser:
			return HttpResponseForbidden("You do not have permission to create users.")

	user_email = request.POST.get('email').lower()
	user_first_name = request.POST.get('firstName')
	user_last_name = request.POST.get('lastName')

	if not user_email or not user_first_name or not user_last_name:
		messages.warning(request, 'Info Missing from User Creation Form')
		return redirect(reverse('general-settings') + '#user-management')

	if User.objects.filter(email = user_email):
		messages.warning(request, 'User with Email Already Exists (Ensure SSO Users are not Local Users)')
		return redirect(reverse('general-settings') + '#user-management')

	# First user gets superuser; subsequent users get staff only
	if is_initial_setup:
		user = User.objects.create_superuser(user_email, user_email)
	else:
		user = User.objects.create_user(user_email, user_email, is_staff=True)
	user.first_name = user_first_name
	user.last_name = user_last_name

	if request.POST.get('sso-user'):
		user.set_unusable_password()
	elif request.POST.get('initial-setup'):
		if request.POST.get('password') == request.POST.get('c_password'):
			user.set_password(request.POST.get('password'))
		else:
			messages.warning(request, 'Passwords do not match')
			user.delete()
			return redirect(reverse('general-settings') + '#user-management')
	else:
		user_password = generate_random_password()
		user.set_password(user_password)
	messages.info(request, 'User Created Successfully')
	user.save()
	return redirect(reverse('general-settings') + '#user-management')

############################################################################################