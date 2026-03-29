from django.db import models

class Device(models.Model):
    hostname = models.CharField(max_length=75, null=True, db_index=True)
    compliant = models.BooleanField(null=False, default=False)
    OS_PLATFORM_CHOICES = (
        ("Android", "Android"),
        ("iOS/iPadOS", "iOS/iPadOS"),
        ("MacOS", "MacOS"),
        ("Red Hat Enterprise Linux", "Red Hat Enterprise Linux"),
        ("CentOS", "CentOS"),
        ("Ubuntu", "Ubuntu"),
        ("Windows", "Windows"),
        ("Windows Server", "Windows Server"),
        ("Other", "Other"),
    )
    osPlatform = models.CharField(max_length=100, choices=OS_PLATFORM_CHOICES, null=True)
    ENDPOINT_TYPE_CHOICES = (
        ("Client", "Client"),
        ("Server", "Server"),
        ("Mobile", "Mobile"),
        ("Other", "Other"),
    )
    endpointType = models.CharField(max_length=9, choices=ENDPOINT_TYPE_CHOICES, null=True)
    manufacturer = models.CharField(max_length=200, null=True)
    integration = models.ManyToManyField("Integration", related_name='devices')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.hostname or f'{self.__class__.__name__} {self.pk}'

class DeviceComplianceSettings(models.Model):
    os_platform = models.CharField(max_length=200, null=True)
    cloudflare_zero_trust = models.BooleanField(null=True)
    crowdstrike_falcon = models.BooleanField(null=True)
    microsoft_defender_for_endpoint = models.BooleanField(null=True)
    microsoft_entra_id = models.BooleanField(null=True)
    microsoft_intune = models.BooleanField(null=True)
    sophos_central = models.BooleanField(null=True)
    qualys = models.BooleanField(null=True)
    tailscale = models.BooleanField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        verbose_name = "Device Compliance Setting"
        verbose_name_plural = "Device Compliance Settings"

    def __str__(self):
        return self.os_platform
    
class Integration(models.Model):
    enabled = models.BooleanField(null=True, default=False)
    #X6969
    INTEGRATION_CHOICES = (
        ("Cloudflare Zero Trust", "Cloudflare Zero Trust"),
        ("CrowdStrike Falcon", "CrowdStrike Falcon"),
        ("Microsoft Defender for Endpoint", "Microsoft Defender for Endpoint"),
        ("Microsoft Entra ID", "Microsoft Entra ID"),
        ("Microsoft Intune", "Microsoft Intune"),
        ("Sophos Central", "Sophos Central"),
        ("Qualys", "Qualys"),
        ("Tailscale", "Tailscale"),
    )
    integration_type = models.CharField(max_length=35, choices=INTEGRATION_CHOICES, null=True)
    integration_type_short = models.CharField(max_length=35, null=True)
    INTEGRATION_CONTEXTS = (
        ("Cloud Configuration", "Cloud Configuration"),
        ("Device", "Device"),
        ("User", "User"),
    )
    integration_context = models.CharField(max_length=35, choices=INTEGRATION_CONTEXTS, null=True)
    image_navbar_path = models.CharField(max_length=200, null=True)
    image_integration_path = models.CharField(max_length=200, null=True)
    client_id = models.CharField(max_length=200, null=True)
    client_secret = models.CharField(max_length=200, null=True)
    tenant_id = models.CharField(max_length=200, null=True)
    tenant_domain = models.CharField(max_length=200, null=True)
    DEVICE_OWNERSHIP_CHOICES = (
        ("All", "All Devices"),
        ("Company", "Corporate Devices Only"),
        ("Personal", "Personal Devices Only"),
    )
    device_ownership_filter = models.CharField(max_length=20, choices=DEVICE_OWNERSHIP_CHOICES, default="All", null=True)
    last_synced_at = models.DateTimeField(null=True)
    last_connection_test_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.integration_type 

class CloudflareZeroTrustDeviceData(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    key = models.CharField(max_length=200, null=True)
    hostname = models.CharField(max_length=200, null=True)
    osPlatform = models.CharField(max_length=200, null=True)
    endpointType = models.CharField(max_length=25, null=True)
    version = models.CharField(max_length=200, null=True)
    updated = models.DateTimeField(null=True)
    created = models.DateTimeField(null=True)
    last_seen = models.DateTimeField(null=True)
    model = models.CharField(max_length=200, null=True)
    os_version = models.CharField(max_length=200, null=True)
    manufacturer = models.CharField(max_length=200, null=True)
    ip = models.CharField(max_length=200, null=True)
    gateway_device_id = models.CharField(max_length=200, null=True)
    serial_number = models.CharField(max_length=200, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationCloudflareZeroTrust')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        verbose_name = "Cloudflare Zero Trust Device"
        verbose_name_plural = "Cloudflare Zero Trust Devices"

    def __str__(self):
        return self.hostname or f'{self.__class__.__name__} {self.pk}'

class CrowdStrikeFalconDeviceData(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    agent_load_flags = models.CharField(max_length=200, null=True)
    agent_local_time = models.DateTimeField(null=True)
    agent_version = models.CharField(max_length=200, null=True)
    base_image_version = models.CharField(max_length=200, null=True)
    bios_manufacturer = models.CharField(max_length=200, null=True)
    bios_version = models.CharField(max_length=200, null=True)
    build_number = models.CharField(max_length=200, null=True)
    chassis_type = models.CharField(max_length=200, null=True)
    chassis_type_desc = models.CharField(max_length=200, null=True)
    cid = models.CharField(max_length=200, null=True)
    config_id_base = models.CharField(max_length=200, null=True)
    config_id_build = models.CharField(max_length=200, null=True)
    config_id_platform = models.CharField(max_length=200, null=True)
    connection_ip = models.CharField(max_length=200, null=True)
    connection_mac_address = models.CharField(max_length=200, null=True)
    cpu_signature = models.CharField(max_length=200, null=True)
    cpu_vendor = models.CharField(max_length=200, null=True)
    default_gateway_ip = models.CharField(max_length=200, null=True)
    deployment_type = models.CharField(max_length=200, null=True)
    detection_suppression_status = models.CharField(max_length=200, null=True)
    email = models.EmailField(max_length=200, null=True)
    external_ip = models.CharField(max_length=200, null=True)
    first_login_timestamp = models.DateTimeField(null=True)
    first_seen = models.DateTimeField(null=True)
    group_hash = models.CharField(max_length=200, null=True)
    host_hidden_status = models.CharField(max_length=200, null=True)
    host_utc_offset = models.CharField(max_length=200, null=True)
    hostname = models.CharField(max_length=200, null=True)
    instance_id = models.CharField(max_length=200, null=True)
    internet_exposure = models.CharField(max_length=200, null=True)
    k8s_cluster_git_version = models.CharField(max_length=200, null=True)
    k8s_cluster_id = models.CharField(max_length=200, null=True)
    k8s_cluster_version = models.CharField(max_length=200, null=True)
    kernel_version = models.CharField(max_length=200, null=True)
    last_login_timestamp = models.DateTimeField(null=True)
    last_login_uid = models.CharField(max_length=200, null=True)
    last_login_user = models.CharField(max_length=200, null=True)
    last_login_user_sid = models.CharField(max_length=200, null=True)
    last_reboot = models.DateTimeField(null=True)
    last_seen = models.DateTimeField(null=True)
    linux_sensor_mode = models.CharField(max_length=200, null=True)
    local_ip = models.CharField(max_length=200, null=True)
    mac_address = models.CharField(max_length=200, null=True)
    machine_domain = models.CharField(max_length=200, null=True)
    major_version = models.CharField(max_length=200, null=True)
    migration_completed_time = models.DateTimeField(null=True)
    minor_version = models.CharField(max_length=200, null=True)
    modified_timestamp = models.DateTimeField(null=True)
    os_build = models.CharField(max_length=200, null=True)
    os_product_name = models.CharField(max_length=200, null=True)
    os_version = models.CharField(max_length=200, null=True)
    platform_id = models.CharField(max_length=200, null=True)
    platform_name = models.CharField(max_length=200, null=True)
    pod_host_ip4 = models.CharField(max_length=200, null=True)
    pod_host_ip6 = models.CharField(max_length=200, null=True)
    pod_hostname = models.CharField(max_length=200, null=True)
    pod_id = models.CharField(max_length=200, null=True)
    pod_ip4 = models.CharField(max_length=200, null=True)
    pod_ip6 = models.CharField(max_length=200, null=True)
    pod_name = models.CharField(max_length=200, null=True)
    pod_namespace = models.CharField(max_length=200, null=True)
    pod_service_account_name = models.CharField(max_length=200, null=True)
    pointer_size = models.CharField(max_length=200, null=True)
    product_type = models.CharField(max_length=200, null=True)
    product_type_desc = models.CharField(max_length=200, null=True)
    provision_status = models.CharField(max_length=200, null=True)
    reduced_functionality_mode = models.CharField(max_length=200, null=True)
    release_group = models.CharField(max_length=200, null=True)
    rtr_state = models.CharField(max_length=200, null=True)
    serial_number = models.CharField(max_length=200, null=True)
    service_pack_major = models.CharField(max_length=200, null=True)
    service_pack_minor = models.CharField(max_length=200, null=True)
    service_provider = models.CharField(max_length=200, null=True)
    service_provider_account_id = models.CharField(max_length=200, null=True)
    site_name = models.CharField(max_length=200, null=True)
    status = models.CharField(max_length=200, null=True)
    system_manufacturer = models.CharField(max_length=200, null=True)
    system_product_name = models.CharField(max_length=200, null=True)
    zone_group = models.CharField(max_length=200, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationCrowdStrikeFalcon')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        verbose_name = "CrowdStrike Falcon Device"
        verbose_name_plural = "CrowdStrike Falcon Devices"

    def __str__(self):
        return self.hostname or f'{self.__class__.__name__} {self.pk}'

class MicrosoftEntraIDDeviceData(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    deletedDateTime = models.DateTimeField(null=True)
    accountEnabled = models.BooleanField(null=True)
    approximateLastSignInDateTime = models.DateTimeField(null=True)
    complianceExpirationDateTime = models.DateTimeField(null=True)
    createdDateTime = models.DateTimeField(null=True)
    deviceCategory = models.CharField(max_length=200, null=True)
    deviceId = models.CharField(max_length=200, null=True)
    deviceMetadata = models.CharField(max_length=200, null=True)
    deviceOwnership = models.CharField(max_length=200, null=True)
    deviceVersion = models.CharField(max_length=200, null=True)
    displayName = models.CharField(max_length=200, null=True)
    domainName = models.CharField(max_length=75, null=True)
    enrollmentProfileName = models.CharField(max_length=200, null=True)
    enrollmentType = models.CharField(max_length=200, null=True)
    externalSourceName = models.CharField(max_length=200, null=True)
    isCompliant = models.BooleanField(null=True)
    isManaged = models.BooleanField(null=True)
    isRooted = models.BooleanField(null=True)
    managementType = models.CharField(max_length=200, null=True)
    manufacturer = models.CharField(max_length=200, null=True)
    mdmAppId = models.CharField(max_length=200, null=True)
    model = models.CharField(max_length=200, null=True)
    onPremisesLastSyncDateTime = models.DateTimeField(null=True)
    onPremisesSyncEnabled = models.BooleanField(null=True)
    operatingSystem = models.CharField(max_length=200, null=True)
    operatingSystemVersion = models.CharField(max_length=200, null=True)
    profileType = models.CharField(max_length=200, null=True)
    registrationDateTime = models.DateTimeField(null=True)
    sourceType = models.CharField(max_length=200, null=True)
    trustType = models.CharField(max_length=200, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationMicrosoftEntraID')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        verbose_name = "Microsoft Entra ID Device"
        verbose_name_plural = "Microsoft Entra ID Devices"

    def __str__(self):
        return self.displayName 

class MicrosoftIntuneDeviceData(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    userId = models.CharField(max_length=200, null=True)
    deviceName = models.CharField(max_length=200, null=True)
    managedDeviceOwnerType = models.CharField(max_length=200, null=True)
    enrolledDateTime = models.DateTimeField(null=True)
    lastSyncDateTime = models.DateTimeField(null=True)
    operatingSystem = models.CharField(max_length=200, null=True)
    complianceState = models.CharField(max_length=200, null=True)
    jailBroken = models.CharField(max_length=200, null=True)
    managementAgent = models.CharField(max_length=200, null=True)
    osVersion = models.CharField(max_length=200, null=True)
    easActivated = models.BooleanField(null=True)
    easDeviceId = models.CharField(max_length=200, null=True)
    easActivationDateTime = models.DateTimeField(null=True)
    azureADRegistered = models.BooleanField(null=True)
    deviceEnrollmentType = models.CharField(max_length=200, null=True)
    activationLockBypassCode = models.CharField(max_length=200, null=True)
    emailAddress = models.EmailField(max_length=200, null=True)
    azureADDeviceId = models.CharField(max_length=200, null=True)
    deviceRegistrationState = models.CharField(max_length=200, null=True)
    deviceCategoryDisplayName = models.CharField(max_length=200, null=True)
    isSupervised = models.BooleanField(null=True)
    exchangeLastSuccessfulSyncDateTime = models.DateTimeField(null=True)
    exchangeAccessState = models.CharField(max_length=200, null=True)
    exchangeAccessStateReason = models.CharField(max_length=200, null=True)
    remoteAssistanceSessionUrl = models.CharField(max_length=200, null=True)
    remoteAssistanceSessionErrorDetails = models.CharField(max_length=200, null=True)
    isEncrypted = models.BooleanField(null=True)
    userPrincipalName = models.CharField(max_length=200, null=True)
    model = models.CharField(max_length=200, null=True)
    manufacturer = models.CharField(max_length=200, null=True)
    imei = models.CharField(max_length=200, null=True)
    complianceGracePeriodExpirationDateTime = models.DateTimeField(null=True)
    serialNumber = models.CharField(max_length=200, null=True)
    phoneNumber = models.CharField(max_length=200, null=True)
    androidSecurityPatchLevel = models.CharField(max_length=200, null=True)
    userDisplayName = models.CharField(max_length=200, null=True)
    configurationManagerClientEnabledFeatures = models.CharField(max_length=200, null=True)
    wiFiMacAddress = models.CharField(max_length=200, null=True)
    deviceHealthAttestationState = models.CharField(max_length=200, null=True)
    subscriberCarrier = models.CharField(max_length=200, null=True)
    meid = models.CharField(max_length=200, null=True)
    totalStorageSpaceInBytes = models.CharField(max_length=200, null=True)
    freeStorageSpaceInBytes = models.BigIntegerField(null=True)
    managedDeviceName = models.CharField(max_length=200, null=True)
    partnerReportedThreatState = models.CharField(max_length=200, null=True)
    requireUserEnrollmentApproval = models.CharField(max_length=200, null=True)
    managementCertificateExpirationDate = models.DateTimeField(null=True)
    iccid = models.CharField(max_length=200, null=True)
    udid = models.CharField(max_length=200, null=True)
    notes = models.CharField(max_length=200, null=True)
    ethernetMacAddress = models.CharField(max_length=200, null=True)
    physicalMemoryInBytes = models.BigIntegerField(null=True)
    enrollmentProfileName = models.CharField(max_length=200, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationIntune')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        verbose_name = "Microsoft Intune Device"
        verbose_name_plural = "Microsoft Intune Devices"

    def __str__(self):
        return self.deviceName
    

class SophosCentralDeviceData(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    type = models.CharField(max_length=200, null=True)
    hostname = models.CharField(max_length=75, null=True)
    os_isServer = models.BooleanField(null=True)
    os_platform = models.CharField(max_length=200, null=True)
    os_name = models.CharField(max_length=200, null=True)
    os_majorVersion = models.CharField(max_length=200, null=True)
    os_minorVersion = models.CharField(max_length=200, null=True)
    os_build = models.CharField(max_length=200, null=True)
    associatedPerson_name = models.CharField(max_length=200, null=True)
    associatedPerson_viaLogin = models.CharField(max_length=200, null=True)
    associatedPerson_id = models.CharField(max_length=200, null=True)
    tamperProtectionEnabled = models.BooleanField(null=True)
    lastSeenAt = models.DateTimeField(null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationSophos')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        verbose_name = "Sophos Central Device"
        verbose_name_plural = "Sophos Central Devices"

    def __str__(self):
        return self.hostname or f'{self.__class__.__name__} {self.pk}'

class MicrosoftDefenderforEndpointDeviceData(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    mergedIntoMachineId = models.CharField(max_length=200, null=True)
    isPotentialDuplication = models.BooleanField(null=True)
    isExcluded = models.BooleanField(null=True)
    exclusionReason = models.CharField(max_length=200, null=True)
    computerDnsName = models.CharField(max_length=200, null=True)
    firstSeen = models.CharField(max_length=200, null=True)
    lastSeen = models.CharField(max_length=200, null=True)
    osPlatform = models.CharField(max_length=200, null=True)
    osVersion = models.CharField(max_length=200, null=True)
    osProcessor = models.CharField(max_length=200, null=True)
    version = models.CharField(max_length=200, null=True)
    lastIpAddress = models.CharField(max_length=200, null=True)
    lastExternalIpAddress = models.CharField(max_length=200, null=True)
    agentVersion = models.CharField(max_length=200, null=True)
    osBuild = models.BigIntegerField(null=True)
    healthStatus = models.CharField(max_length=200, null=True)
    deviceValue = models.CharField(max_length=200, null=True)
    rbacGroupId = models.BigIntegerField(null=True)
    rbacGroupName = models.CharField(max_length=200, null=True)
    riskScore = models.CharField(max_length=200, null=True)
    exposureLevel = models.CharField(max_length=200, null=True)
    isAadJoined = models.BooleanField(null=True)
    aadDeviceId = models.CharField(max_length=200, null=True)
    defenderAvStatus = models.CharField(max_length=200, null=True)
    onboardingStatus = models.CharField(max_length=200, null=True)
    osArchitecture = models.CharField(max_length=200, null=True)
    managedBy = models.CharField(max_length=200, null=True)
    managedByStatus = models.CharField(max_length=200, null=True)
    vmMetadata = models.TextField(null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationMicrosoftDefenderForEndpoint')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        verbose_name = "Microsoft Defender for Endpoint Device"
        verbose_name_plural = "Microsoft Defender for Endpoint Devices"

    def __str__(self):
        return self.computerDnsName or f'{self.__class__.__name__} {self.pk}'

class QualysDevice(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    hostname = models.CharField(max_length=200, null=True)
    osPlatform = models.CharField(max_length=200, null=True)
    endpointType = models.CharField(max_length=25, null=True)
    firstFoundDate = models.CharField(max_length=200, null=True)
    ipAddress = models.CharField(max_length=200, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationQualys')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        verbose_name = "Qualys Device"
        verbose_name_plural = "Qualys Devices"

    def __str__(self):
        return self.hostname or f'{self.__class__.__name__} {self.pk}'

class TailscaleDeviceData(models.Model):
    id = models.CharField(max_length=50, primary_key=True)
    nodeId = models.CharField(max_length=50, null=True)
    hostname = models.CharField(max_length=200, null=True)
    user = models.EmailField(max_length=254, null=True)
    name = models.CharField(max_length=200, null=True)
    clientVersion = models.CharField(max_length=200, null=True)
    updateAvailable = models.BooleanField(null=True)
    os = models.CharField(max_length=50, null=True)
    created = models.DateTimeField(null=True)
    connectedToControl = models.BooleanField(null=True)
    lastSeen = models.DateTimeField(null=True)
    expires = models.DateTimeField(null=True)
    keyExpiryDisabled = models.BooleanField(null=True)
    authorized = models.BooleanField(null=True)
    isExternal = models.BooleanField(null=True)
    machineKey = models.CharField(max_length=200, null=True)
    nodeKey = models.CharField(max_length=200, null=True)
    tailnetLockKey = models.CharField(max_length=200, null=True)
    blocksIncomingConnections = models.BooleanField(null=True)
    tailnetLockError = models.CharField(max_length=200, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationTailscale')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    class Meta:
        verbose_name = "Tailscale Device"
        verbose_name_plural = "Tailscale Devices"

    def __str__(self):
        return self.hostname or f'{self.__class__.__name__} {self.pk}'

class Persona(models.Model):
    persona_name = models.CharField(max_length=200, null=True)
    priority = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.persona_name

class PersonaGroup(models.Model):
    persona = models.ForeignKey(Persona, on_delete=models.CASCADE, null=True)
    group_name = models.CharField(max_length=200, null=True)
    object_id = models.CharField(max_length=200, null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.group_name or 'Unnamed Group'
    
class UserData(models.Model):
    upn = models.EmailField(max_length=200, null=True, db_index=True)
    uid = models.CharField(max_length=200, null=True)
    network_id = models.CharField(max_length=200, null=True)
    persona = models.ForeignKey(Persona, on_delete=models.CASCADE, null=True)
    given_name = models.CharField(max_length=200, null=True)
    surname = models.CharField(max_length=200, null=True)
    job_title = models.CharField(max_length=200, null=True)
    department = models.CharField(max_length=200, null=True)
    # Start Auth Capabilities
    isAdmin = models.BooleanField(null=True)
    isMfaCapable = models.BooleanField(null=True)
    isMfaRegistered = models.BooleanField(null=True)
    isPasswordlessCapable = models.BooleanField(null=True)
    isSsprEnabled = models.BooleanField(null=True)
    isSsprRegistered = models.BooleanField(null=True)
    isSystemPreferredAuthenticationMethodEnabled = models.BooleanField(null=True)
    highest_authentication_strength = models.CharField(max_length=200, null=True)
    lowest_authentication_strength = models.CharField(max_length=200, null=True)
    # End Auth Capabilities
    # Start Authentication methods
    passKeyDeviceBound_authentication_method = models.BooleanField(null=True)
    passKeyDeviceBoundAuthenticator_authentication_method = models.BooleanField(null=True)
    windowsHelloforBusiness_authentication_method = models.BooleanField(null=True)
    microsoftAuthenticatorPasswordless_authentication_method = models.BooleanField(null=True)
    microsoftAuthenticatorPush_authentication_method = models.BooleanField(null=True)
    softwareOneTimePasscode_authentication_method = models.BooleanField(null=True)
    temporaryAccessPass_authentication_method = models.BooleanField(null=True)
    mobilePhone_authentication_method = models.BooleanField(null=True)
    email_authentication_method = models.BooleanField(null=True)
    securityQuestion_authentication_method = models.BooleanField(null=True)
    # End Authentication methods
    integration = models.ManyToManyField("Integration", related_name='users')
    persona_group = models.ForeignKey("PersonaGroup", on_delete=models.CASCADE, null=True, related_name='users')
    created_at_timestamp = models.DateTimeField(null=True)
    last_logon_timestamp = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.upn

class SignInSummary(models.Model):
    """Stores CA+MFA sign-in analysis from Microsoft Entra ID sign-in logs. Updated per sync."""
    ca_mfa = models.IntegerField(default=0)          # CA applied + MFA enforced
    ca_no_mfa = models.IntegerField(default=0)        # CA applied + single factor
    no_ca_mfa = models.IntegerField(default=0)        # No CA + MFA present
    no_ca_no_mfa = models.IntegerField(default=0)     # No CA + no MFA
    total_signins = models.IntegerField(default=0)
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Sign-In Summary"
        verbose_name_plural = "Sign-In Summaries"

    def __str__(self):
        return f"Sign-In Summary ({self.synced_at})"

class Notification(models.Model):
    title = models.CharField(max_length=200, null=True)
    status = models.TextField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.title