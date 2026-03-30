from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin

from apps.main.models import (
    Device,
    Integration,
    DeviceComplianceSettings,
    MicrosoftEntraIDDeviceData,
    MicrosoftIntuneDeviceData,
    UserData,
    MicrosoftDefenderforEndpointDeviceData,
    CrowdStrikeFalconDeviceData,
    SophosCentralDeviceData,
    TailscaleDeviceData,
    CloudflareZeroTrustDeviceData,
    QualysDevice,
    SignInSummary,
    Notification,
    PersonaGroup,
    Persona,
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
# Admin classes
# ---------------------------------------------------------------------------

@admin.register(Device)
class DeviceAdmin(ImportExportModelAdmin):
    resource_class = DeviceResource


@admin.register(Integration)
class IntegrationAdmin(ImportExportModelAdmin):
    resource_class = IntegrationResource


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


@admin.register(UserData)
class UserDataAdmin(ImportExportModelAdmin):
    resource_class = UserDataResource
    list_display = ('upn', 'uid', 'network_id', 'persona', 'job_title', 'department', 'isAdmin', 'isMfaCapable', 'created_at', 'updated_at')
    list_filter = ('isAdmin', 'isMfaCapable', 'isMfaRegistered', 'isPasswordlessCapable', 'isSsprEnabled', 'department', 'job_title')
    search_fields = ('upn', 'uid', 'network_id', 'given_name', 'surname', 'job_title', 'department')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')


@admin.register(SignInSummary)
class SignInSummaryAdmin(ImportExportModelAdmin):
    resource_class = SignInSummaryResource


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
