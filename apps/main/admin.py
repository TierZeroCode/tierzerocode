from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from import_export import resources
from import_export.admin import ImportExportModelAdmin

from apps.main.models import (
    EntraSignInMethodStat,
    PasswordPolicy,
    CloudflareZeroTrustDeviceData,
    ConditionalAccessPolicy,
    Control,
    ControlFramework,
    CrowdStrikeFalconDeviceData,
    Device,
    DeviceComplianceSettings,
    Integration,
    MicrosoftDefenderforEndpointDeviceData,
    MicrosoftEntraIDDeviceData,
    MicrosoftIntuneDeviceData,
    Notification,
    Persona,
    PersonaGroup,
    PersonaTag,
    QualysDevice,
    SignInSummary,
    SophosCentralDeviceData,
    TailscaleDeviceData,
    TenantAuthMethodsPolicy,
    TenantSecurityConfig,
    UserData,
)


# ---------------------------------------------------------------------------
# Resource classes — sensitive credential fields (client_id, client_secret)
# are never included in any export.
# ---------------------------------------------------------------------------

class DeviceResource(resources.ModelResource):
    class Meta:
        model = Device
        fields = (
            "id",
            "hostname",
            "compliant",
            "osPlatform",
            "endpointType",
            "manufacturer",
            "created_at",
            "updated_at",
        )


class IntegrationResource(resources.ModelResource):
    class Meta:
        model = Integration
        # Explicitly list every field — client_id and client_secret are omitted.
        fields = (
            "id",
            "enabled",
            "integration_type",
            "integration_type_short",
            "integration_context",
            "image_navbar_path",
            "image_integration_path",
            "tenant_id",
            "tenant_domain",
            "device_ownership_filter",
            "last_synced_at",
            "last_connection_test_at",
            "created_at",
            "updated_at",
        )


class DeviceComplianceSettingsResource(resources.ModelResource):
    class Meta:
        model = DeviceComplianceSettings
        fields = (
            "id",
            "os_platform",
            "cloudflare_zero_trust",
            "crowdstrike_falcon",
            "microsoft_defender_for_endpoint",
            "microsoft_entra_id",
            "microsoft_intune",
            "sophos_central",
            "qualys",
            "tailscale",
            "created_at",
            "updated_at",
        )


class CloudflareZeroTrustDeviceDataResource(resources.ModelResource):
    class Meta:
        model = CloudflareZeroTrustDeviceData
        fields = (
            "id",
            "key",
            "hostname",
            "osPlatform",
            "endpointType",
            "version",
            "updated",
            "created",
            "last_seen",
            "model",
            "os_version",
            "manufacturer",
            "ip",
            "gateway_device_id",
            "serial_number",
            "parentDevice",
            "created_at",
            "updated_at",
        )


class CrowdStrikeFalconDeviceDataResource(resources.ModelResource):
    class Meta:
        model = CrowdStrikeFalconDeviceData
        exclude = ("parentDevice",)


class MicrosoftEntraIDDeviceDataResource(resources.ModelResource):
    class Meta:
        model = MicrosoftEntraIDDeviceData
        exclude = ("parentDevice",)


class MicrosoftIntuneDeviceDataResource(resources.ModelResource):
    class Meta:
        model = MicrosoftIntuneDeviceData
        exclude = ("parentDevice",)


class SophosCentralDeviceDataResource(resources.ModelResource):
    class Meta:
        model = SophosCentralDeviceData
        fields = (
            "id",
            "type",
            "hostname",
            "os_isServer",
            "os_platform",
            "os_name",
            "os_majorVersion",
            "os_minorVersion",
            "os_build",
            "associatedPerson_name",
            "associatedPerson_viaLogin",
            "associatedPerson_id",
            "tamperProtectionEnabled",
            "lastSeenAt",
            "parentDevice",
            "created_at",
            "updated_at",
        )


class MicrosoftDefenderforEndpointDeviceDataResource(resources.ModelResource):
    class Meta:
        model = MicrosoftDefenderforEndpointDeviceData
        exclude = ("parentDevice",)


class QualysDeviceResource(resources.ModelResource):
    class Meta:
        model = QualysDevice
        fields = (
            "id",
            "hostname",
            "osPlatform",
            "endpointType",
            "firstFoundDate",
            "ipAddress",
            "parentDevice",
            "created_at",
            "updated_at",
        )


class TailscaleDeviceDataResource(resources.ModelResource):
    class Meta:
        model = TailscaleDeviceData
        fields = (
            "id",
            "nodeId",
            "hostname",
            "user",
            "name",
            "clientVersion",
            "updateAvailable",
            "os",
            "created",
            "connectedToControl",
            "lastSeen",
            "expires",
            "keyExpiryDisabled",
            "authorized",
            "isExternal",
            "blocksIncomingConnections",
            "tailnetLockError",
            "parentDevice",
            "created_at",
            "updated_at",
        )


class PersonaResource(resources.ModelResource):
    class Meta:
        model = Persona
        fields = (
            "id",
            "persona_name",
            "priority",
            "created_at",
            "updated_at",
        )


class PersonaGroupResource(resources.ModelResource):
    class Meta:
        model = PersonaGroup
        fields = (
            "id",
            "persona",
            "group_name",
            "object_id",
            "created_at",
            "updated_at",
        )


class UserDataResource(resources.ModelResource):
    class Meta:
        model = UserData
        exclude = ("integration", "persona_group", "persona")


class SignInSummaryResource(resources.ModelResource):
    class Meta:
        model = SignInSummary
        fields = (
            "id",
            "ca_mfa",
            "ca_no_mfa",
            "no_ca_mfa",
            "no_ca_no_mfa",
            "total_signins",
            "synced_at",
        )


class NotificationResource(resources.ModelResource):
    class Meta:
        model = Notification
        fields = (
            "id",
            "title",
            "status",
            "created_at",
            "updated_at",
        )


# ---------------------------------------------------------------------------
# Custom list filters
# ---------------------------------------------------------------------------

class IntegrationFilter(admin.SimpleListFilter):
    title = _('integration')
    parameter_name = 'integration'

    def lookups(self, request, model_admin):
        return [
            (str(i.pk), i.integration_type)
            for i in Integration.objects.order_by('integration_type')
        ]

    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(integration__pk=self.value())
        return queryset


# ---------------------------------------------------------------------------
# Admin classes
# ---------------------------------------------------------------------------

@admin.register(Device)
class DeviceAdmin(ImportExportModelAdmin):
    resource_class = DeviceResource


@admin.register(Integration)
class IntegrationAdmin(ImportExportModelAdmin):
    resource_class = IntegrationResource
    list_display = ('integration_type', 'integration_context', 'enabled', 'last_synced_at')
    list_filter = ('enabled', 'integration_context', 'integration_type')
    search_fields = ('integration_type',)
    ordering = ('integration_context', 'integration_type')


@admin.register(DeviceComplianceSettings)
class DeviceComplianceSettingsAdmin(ImportExportModelAdmin):
    resource_class = DeviceComplianceSettingsResource


@admin.register(CloudflareZeroTrustDeviceData)
class CloudflareZeroTrustDeviceDataAdmin(ImportExportModelAdmin):
    resource_class = CloudflareZeroTrustDeviceDataResource


@admin.register(CrowdStrikeFalconDeviceData)
class CrowdStrikeFalconDeviceDataAdmin(ImportExportModelAdmin):
    resource_class = CrowdStrikeFalconDeviceDataResource


@admin.register(MicrosoftEntraIDDeviceData)
class MicrosoftEntraIDDeviceDataAdmin(ImportExportModelAdmin):
    resource_class = MicrosoftEntraIDDeviceDataResource


@admin.register(MicrosoftIntuneDeviceData)
class MicrosoftIntuneDeviceDataAdmin(ImportExportModelAdmin):
    resource_class = MicrosoftIntuneDeviceDataResource


@admin.register(SophosCentralDeviceData)
class SophosCentralDeviceDataAdmin(ImportExportModelAdmin):
    resource_class = SophosCentralDeviceDataResource


@admin.register(MicrosoftDefenderforEndpointDeviceData)
class MicrosoftDefenderforEndpointDeviceDataAdmin(ImportExportModelAdmin):
    resource_class = MicrosoftDefenderforEndpointDeviceDataResource


@admin.register(QualysDevice)
class QualysDeviceAdmin(ImportExportModelAdmin):
    resource_class = QualysDeviceResource


@admin.register(TailscaleDeviceData)
class TailscaleDeviceDataAdmin(ImportExportModelAdmin):
    resource_class = TailscaleDeviceDataResource


@admin.register(Persona)
class PersonaAdmin(ImportExportModelAdmin):
    resource_class = PersonaResource


@admin.register(PersonaGroup)
class PersonaGroupAdmin(ImportExportModelAdmin):
    resource_class = PersonaGroupResource


@admin.register(PersonaTag)
class PersonaTagAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)


@admin.register(UserData)
class UserDataAdmin(ImportExportModelAdmin):
    resource_class = UserDataResource
    list_display = ('upn', 'uid', 'network_id', 'persona', 'job_title', 'department', 'isAdmin', 'isMfaCapable', 'created_at', 'updated_at')
    list_filter = ('isAdmin', 'isMfaCapable', 'isMfaRegistered', 'isPasswordlessCapable', 'isSsprEnabled', 'department', 'job_title', IntegrationFilter)
    search_fields = ('upn', 'uid', 'network_id', 'given_name', 'surname', 'job_title', 'department')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')


@admin.register(SignInSummary)
class SignInSummaryAdmin(ImportExportModelAdmin):
    resource_class = SignInSummaryResource


@admin.register(EntraSignInMethodStat)
class EntraSignInMethodStatAdmin(admin.ModelAdmin):
    list_display = ('upn', 'total_signins', 'replay_resistant_signins', 'non_replay_resistant_signins', 'mfa_satisfied_signins', 'hardware_bound_signins', 'last_signin_at', 'synced_at')
    search_fields = ('upn',)
    ordering = ('-total_signins',)
    readonly_fields = ('synced_at',)


@admin.register(Notification)
class NotificationAdmin(ImportExportModelAdmin):
    resource_class = NotificationResource
    list_display = ('title', 'status', 'created_at', 'updated_at')
    list_filter = ('status', 'created_at', 'updated_at')
    search_fields = ('title', 'status')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        ('Notification Details', {
            'fields': ('title', 'status')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(ControlFramework)
class ControlFrameworkAdmin(admin.ModelAdmin):
    list_display = ('name', 'short_name', 'version', 'display_order', 'url')
    list_editable = ('display_order',)
    search_fields = ('name', 'short_name')
    ordering = ('display_order', 'name')


@admin.register(Control)
class ControlAdmin(admin.ModelAdmin):
    list_display = ('control_id', 'domain', 'framework', 'status', 'target', 'current_value', 'enabled', 'use_manual')
    list_filter = ('status', 'enabled', 'use_manual', 'framework', 'domain')
    search_fields = ('control_id', 'domain', 'statement')
    ordering = ('control_id',)
    readonly_fields = ('updated_at',)


@admin.register(ConditionalAccessPolicy)
class ConditionalAccessPolicyAdmin(admin.ModelAdmin):
    list_display = ('policy_id', 'display_name', 'state', 'created_at', 'updated_at')
    list_filter = ('state',)
    search_fields = ('display_name', 'policy_id')
    ordering = ('display_name',)
    readonly_fields = ('created_at', 'updated_at')


@admin.register(TenantSecurityConfig)
class TenantSecurityConfigAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'synced_at')
    readonly_fields = ('synced_at',)


@admin.register(TenantAuthMethodsPolicy)
class TenantAuthMethodsPolicyAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'synced_at', 'sspr_state')
    list_filter = ('sspr_state',)
    readonly_fields = ('synced_at',)


@admin.register(PasswordPolicy)
class PasswordPolicyAdmin(admin.ModelAdmin):
    list_display = ('name', 'source', 'policy_identifier', 'min_password_length', 'max_password_age_days', 'lockout_threshold', 'complexity_enabled', 'synced_at')
    list_filter = ('source', 'complexity_enabled')
    search_fields = ('name', 'policy_identifier')
    ordering = ('source', 'name')
