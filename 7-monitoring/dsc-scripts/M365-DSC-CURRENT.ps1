[CmdletBinding()]
param( 
    [Parameter(Mandatory=$false)]
    [String]$ApplicationID,
    
    [Parameter(Mandatory=$false)]
    [String]$CertificateThumbprint,
    
    [Parameter(Mandatory=$false)]
    [String]$TenantName,
    
    [Parameter(Mandatory=$false)]
    [String]$PathBaseline
)

Export-M365DSCConfiguration -Components @("AADAdministrativeUnit", "AADApplication", "AADAttributeSet", "AADAuthenticationContextClassReference", "AADAuthenticationMethodPolicy", "AADAuthenticationMethodPolicyAuthenticator", "AADAuthenticationMethodPolicyEmail", "AADAuthenticationMethodPolicyFido2", "AADAuthenticationMethodPolicySms", "AADAuthenticationMethodPolicySoftware", "AADAuthenticationMethodPolicyTemporary", "AADAuthenticationMethodPolicyVoice", "AADAuthenticationMethodPolicyX509", "AADAuthenticationStrengthPolicy", "AADAuthorizationPolicy", "AADConditionalAccessPolicy", "AADCrossTenantAccessPolicy", "AADCrossTenantAccessPolicyConfigurationDefault", "AADCrossTenantAccessPolicyConfigurationPartner", "AADExternalIdentityPolicy", "AADGroup", "AADGroupLifecyclePolicy", "AADNamedLocationPolicy", "AADSecurityDefaults", "AADSocialIdentityProvider", "AADTenantDetails", "AADTokenLifetimePolicy", "EXOAcceptedDomain", "EXOActiveSyncDeviceAccessRule", "EXOAntiPhishPolicy", "EXOAntiPhishRule", "EXOApplicationAccessPolicy", "EXOAtpPolicyForO365", "EXOAuthenticationPolicy", "EXOAuthenticationPolicyAssignment", "EXOAvailabilityAddressSpace", "EXOAvailabilityConfig",  "EXOClientAccessRule", "EXODataEncryptionPolicy", "EXODkimSigningConfig", "EXOEmailAddressPolicy", "EXOHostedConnectionFilterPolicy", "EXOHostedContentFilterPolicy", "EXOHostedContentFilterRule", "EXOHostedOutboundSpamFilterPolicy", "EXOHostedOutboundSpamFilterRule", "EXOInboundConnector", "EXOIntraOrganizationConnector", "EXOIRMConfiguration", "EXOMailTips", "EXOMalwareFilterPolicy", "EXOMalwareFilterRule", "EXOMobileDeviceMailboxPolicy",  "EXOOMEConfiguration", "EXOOnPremisesOrganization", "EXOOrganizationConfig", "EXOOrganizationRelationship", "EXOPartnerApplication", "EXOPerimeterConfiguration", "EXOPlace", "EXOPolicyTipConfig", "EXOQuarantinePolicy", "EXORemoteDomain", "EXOReportSubmissionPolicy", "EXOReportSubmissionRule", "EXORoleAssignmentPolicy", "EXOSafeAttachmentPolicy", "EXOSafeAttachmentRule", "EXOSafeLinksPolicy", "EXOSafeLinksRule", "EXOSharingPolicy", "IntuneAccountProtectionLocalAdministratorPasswordSolutionPolicy", "IntuneAccountProtectionLocalUserGroupMembershipPolicy", "IntuneAccountProtectionPolicy", "IntuneAntivirusPolicyWindows10SettingCatalog", "IntuneAppConfigurationPolicy", "IntuneApplicationControlPolicyWindows10", "IntuneAppProtectionPolicyAndroid", "IntuneAppProtectionPolicyiOS", "IntuneASRRulesPolicyWindows10", "IntuneAttackSurfaceReductionRulesPolicyWindows10ConfigManager", "IntuneDeviceCategory", "IntuneDeviceCleanupRule", "IntuneDeviceCompliancePolicyAndroid", "IntuneDeviceCompliancePolicyAndroidDeviceOwner", "IntuneDeviceCompliancePolicyAndroidWorkProfile", "IntuneDeviceCompliancePolicyiOs", "IntuneDeviceCompliancePolicyMacOS", "IntuneDeviceCompliancePolicyWindows10", "IntuneDeviceConfigurationAdministrativeTemplatePolicyWindows10", "IntuneDeviceConfigurationDefenderForEndpointOnboardingPolicyWindows10", "IntuneDeviceConfigurationEndpointProtectionPolicyWindows10", "IntuneDeviceConfigurationHealthMonitoringConfigurationPolicyWindows10", "IntuneDeviceConfigurationIdentityProtectionPolicyWindows10", "IntuneDeviceConfigurationPolicyAndroidDeviceAdministrator", "IntuneDeviceConfigurationPolicyAndroidDeviceOwner", "IntuneDeviceConfigurationPolicyAndroidOpenSourceProject", "IntuneDeviceConfigurationPolicyAndroidWorkProfile", "IntuneDeviceConfigurationPolicyiOS", "IntuneDeviceConfigurationPolicyMacOS", "IntuneDeviceConfigurationPolicyWindows10", "IntuneDeviceConfigurationSecureAssessmentPolicyWindows10", "IntuneDeviceEnrollmentLimitRestriction", "IntuneDeviceEnrollmentPlatformRestriction","IntuneEndpointDetectionAndResponsePolicyWindows10", "IntuneExploitProtectionPolicyWindows10SettingCatalog", "IntuneSettingCatalogASRRulesPolicyWindows10", "IntuneSettingCatalogCustomPolicyWindows10", "O365AdminAuditLogConfig", "O365OrgCustomizationSetting", "ODSettings", "SCAuditConfigurationPolicy", "SCComplianceTag", "SCDeviceConditionalAccessPolicy", "SCDeviceConfigurationPolicy", "SPOAccessControlSettings", "SPOBrowserIdleSignout", "SPOSharingSettings", "SPOSiteScript", "SPOStorageEntity", "SPOTenantCdnEnabled", "SPOTenantCdnPolicy", "SPOTenantSettings", "TeamsAppPermissionPolicy", "TeamsAppSetupPolicy", "TeamsAudioConferencingPolicy", "TeamsCallHoldPolicy", "TeamsCallingPolicy", "TeamsCallParkPolicy", "TeamsCallQueue", "TeamsChannelsPolicy", "TeamsClientConfiguration", "TeamsComplianceRecordingPolicy", "TeamsCortanaPolicy", "TeamsDialInConferencingTenantSettings", "TeamsEmergencyCallingPolicy", "TeamsEmergencyCallRoutingPolicy", "TeamsEnhancedEncryptionPolicy", "TeamsEventsPolicy", "TeamsFederationConfiguration", "TeamsFeedbackPolicy", "TeamsFilesPolicy", "TeamsGuestMeetingConfiguration", "TeamsGuestMessagingConfiguration",  "TeamsMeetingConfiguration", "TeamsMeetingPolicy", "TeamsTenantNetworkRegion", "TeamsTenantNetworkSite", "TeamsTenantNetworkSubnet", "TeamsTenantTrustedIPAddress") -ApplicationId $ApplicationID -CertificateThumbprint $CertificateThumbprint -TenantId $TenantName -Path $PathBaseline














