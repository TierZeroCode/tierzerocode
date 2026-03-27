from django import forms
from django.core.exceptions import ValidationError
from .models import DeviceComplianceSettings, Integration

class ComplianceSettingsForm(forms.ModelForm):
    """Form for managing device compliance settings"""
    
    class Meta:
        model = DeviceComplianceSettings
        fields = [
            'cloudflare_zero_trust',
            'crowdstrike_falcon',
            'microsoft_defender_for_endpoint',
            'microsoft_entra_id',
            'microsoft_intune',
            'sophos_central',
            'qualys',
            'tailscale',
        ]
        widgets = {
            'cloudflare_zero_trust': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'crowdstrike_falcon': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'microsoft_defender_for_endpoint': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'microsoft_entra_id': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'microsoft_intune': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'sophos_central': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'qualys': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'tailscale': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add labels and help text for better UX
        self.fields['cloudflare_zero_trust'].label = 'Cloudflare Zero Trust'
        self.fields['cloudflare_zero_trust'].help_text = 'Require Cloudflare Zero Trust for compliance'
        
        self.fields['crowdstrike_falcon'].label = 'CrowdStrike Falcon'
        self.fields['crowdstrike_falcon'].help_text = 'Require CrowdStrike Falcon for compliance'
        
        self.fields['microsoft_defender_for_endpoint'].label = 'Microsoft Defender for Endpoint'
        self.fields['microsoft_defender_for_endpoint'].help_text = 'Require Microsoft Defender for Endpoint for compliance'
        
        self.fields['microsoft_entra_id'].label = 'Microsoft Entra ID'
        self.fields['microsoft_entra_id'].help_text = 'Require Microsoft Entra ID for compliance'
        
        self.fields['microsoft_intune'].label = 'Microsoft Intune'
        self.fields['microsoft_intune'].help_text = 'Require Microsoft Intune for compliance'
        
        self.fields['sophos_central'].label = 'Sophos Central'
        self.fields['sophos_central'].help_text = 'Require Sophos Central for compliance'
        
        self.fields['qualys'].label = 'Qualys'
        self.fields['qualys'].help_text = 'Require Qualys for compliance'

        self.fields['tailscale'].label = 'Tailscale'
        self.fields['tailscale'].help_text = 'Require Tailscale for compliance'

class BulkComplianceSettingsForm(forms.Form):
    """Form for bulk updating compliance settings across all platforms"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Get all available integrations
        integrations = Integration.objects.filter(enabled=True)
        
        for integration in integrations:
            field_name = f'bulk_{integration.integration_type.lower().replace(" ", "_")}'
            self.fields[field_name] = forms.BooleanField(
                required=False,
                label=integration.integration_type,
                help_text=f'Apply this setting to all platforms',
                widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
            )

class NotificationSettingsForm(forms.Form):
    """Form for notification preferences (placeholder for future implementation)"""
    
    # Email notifications
    email_compliance_violations = forms.BooleanField(
        required=False,
        label='Compliance Violations',
        help_text='Receive email notifications for compliance violations',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    email_security_alerts = forms.BooleanField(
        required=False,
        label='Security Alerts',
        help_text='Receive email notifications for security alerts',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    email_system_updates = forms.BooleanField(
        required=False,
        label='System Updates',
        help_text='Receive email notifications for system updates',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    # In-app notifications
    app_compliance_violations = forms.BooleanField(
        required=False,
        label='Compliance Violations',
        help_text='Show in-app notifications for compliance violations',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    app_security_alerts = forms.BooleanField(
        required=False,
        label='Security Alerts',
        help_text='Show in-app notifications for security alerts',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    app_system_updates = forms.BooleanField(
        required=False,
        label='System Updates',
        help_text='Show in-app notifications for system updates',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    ) 