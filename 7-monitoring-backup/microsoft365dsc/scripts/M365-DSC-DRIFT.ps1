[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$Customer,
    
    [Parameter(Mandatory=$false)]
    [String]$PathCurrent,
    
    [Parameter(Mandatory=$false)]
    [String]$PathDrift,
    
    [Parameter(Mandatory=$false)]
    [String]$PathReport,
    
    [Parameter(Mandatory=$false)]
    [String]$TenantName,
    
    [Parameter(Mandatory=$false)]
    [String]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [String]$WorkloadClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$WorkloadThumbprint,
    
    [Parameter(Mandatory=$true)]
    [String]$EXOMailFrom,
    
    [Parameter(Mandatory=$true)]
    [String]$EXOMailTo,
    
    [Parameter(Mandatory=$true)]
    [String]$EXOClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOThumbprint,
    
    [Parameter(Mandatory=$false)]
    [String]$Workload
)

# Define workload components
$WorkloadComponents = @{
     "EntraID" = @("AADAccessReviewPolicy", "AADActivityBasedTimeoutPolicy", "AADAdminConsentRequestPolicy", "AADAdministrativeUnit", "AADAgreement", "AADAppManagementPolicy", "AADApplication", "AADAttributeSet", "AADAuthenticationContextClassReference", "AADAuthenticationFlowPolicy", "AADAuthenticationMethodPolicy", "AADAuthenticationMethodPolicyAuthenticator", "AADAuthenticationMethodPolicyEmail", "AADAuthenticationMethodPolicyExternal", "AADAuthenticationMethodPolicyFido2", "AADAuthenticationMethodPolicyHardware", "AADAuthenticationMethodPolicyQRCodeImage", "AADAuthenticationMethodPolicySms", "AADAuthenticationMethodPolicySoftware", "AADAuthenticationMethodPolicyTemporary", "AADAuthenticationMethodPolicyVoice", "AADAuthenticationMethodPolicyX509", "AADAuthenticationRequirement", "AADAuthenticationStrengthPolicy", "AADAuthorizationPolicy", "AADB2CAuthenticationMethodsPolicy", "AADClaimsMappingPolicy", "AADConditionalAccessPolicy", "AADConnectorGroupApplicationProxy", "AADCrossTenantAccessPolicy", "AADCrossTenantAccessPolicyConfigurationDefault", "AADCrossTenantAccessPolicyConfigurationPartner", "AADCustomAuthenticationExtension", "AADDeviceRegistrationPolicy", "AADDomain", "AADEntitlementManagementAccessPackage", "AADEntitlementManagementAccessPackageAssignmentPolicy", "AADEntitlementManagementAccessPackageCatalog", "AADEntitlementManagementAccessPackageCatalogResource", "AADEntitlementManagementConnectedOrganization", "AADEntitlementManagementRoleAssignment", "AADEntitlementManagementSettings", "AADExternalIdentityPolicy", "AADFeatureRolloutPolicy", "AADFederationConfiguration", "AADFilteringPolicyRule", "AADGroup", "AADGroupEligibilitySchedule", "AADGroupEligibilityScheduleSettings", "AADGroupLifecyclePolicy", "AADGroupsNamingPolicy", "AADGroupsSettings", "AADHomeRealmDiscoveryPolicy", "AADIdentityB2XUserFlow", "AADIdentityGovernanceLifecycleWorkflow", "AADIdentityGovernanceLifecycleWorkflowCustomTaskExtension", "AADIdentityProtectionPolicySettings", "AADLifecycleWorkflowSettings", "AADMultiTenantOrganizationIdentitySyncPolicyTemplate", "AADNamedLocationPolicy", "AADNetworkAccessForwardingProfile", "AADNetworkAccessSettingConditionalAccess", "AADNetworkAccessSettingCrossTenantAccess", "AADOnPremisesPublishingProfilesSettings", "AADOrganizationCertificateBasedAuthConfiguration", "AADPIMGroupSetting", "AADPasswordRuleSettings", "AADRoleAssignmentScheduleRequest", "AADRoleDefinition", "AADRoleEligibilityScheduleRequest", "AADRoleManagementPolicyRule", "AADRoleSetting", "AADSecurityDefaults", "AADServicePrincipal", "AADSocialIdentityProvider", "AADTenantAppManagementPolicy", "AADTenantDetails", "AADTokenIssuancePolicy", "AADTokenLifetimePolicy", "AADUser", "AADVerifiedIdAuthority", "AADVerifiedIdAuthorityContract", "ADOOrganizationOwner", "ADOPermissionGroup", "ADOPermissionGroupSettings", "ADOSecurityPolicy")
	
    "Exchange" = @("EXOATPBuiltInProtectionRule", "EXOAcceptedDomain", "EXOAddressBookPolicy", "EXOAddressList", "EXOAntiPhishPolicy", "EXOAntiPhishRule", "EXOApplicationAccessPolicy", "EXOArcConfig", "EXOAtpPolicyForO365", "EXOAtpProtectionPolicyRule", "EXOAuthenticationPolicy", "EXOAuthenticationPolicyAssignment", "EXOAvailabilityAddressSpace", "EXOAvailabilityConfig", "EXOCASMailboxPlan", "EXOCASMailboxSettings", "EXOCalendarProcessing", "EXODataAtRestEncryptionPolicy", "EXODataAtRestEncryptionPolicyAssignment", "EXODataClassification", "EXODataEncryptionPolicy", "EXODistributionGroup", "EXODkimSigningConfig", "EXODnssecForVerifiedDomain", "EXOEOPProtectionPolicyRule", "EXOEmailAddressPolicy", "EXOEmailTenantSettings", "EXOGlobalAddressList", "EXOGroupSettings", "EXOHostedConnectionFilterPolicy", "EXOHostedContentFilterPolicy", "EXOHostedContentFilterRule", "EXOHostedOutboundSpamFilterPolicy", "EXOHostedOutboundSpamFilterRule", "EXOIRMConfiguration", "EXOInboundConnector", "EXOIntraOrganizationConnector", "EXOJournalRule", "EXOMailContact", "EXOMailboxIRMAccess", "EXOMailboxPlan", "EXOMailboxSettings", "EXOMalwareFilterPolicy", "EXOMalwareFilterRule", "EXOManagementRole", "EXOManagementRoleAssignment", "EXOManagementRoleEntry", "EXOManagementScope", "EXOMessageClassification", "EXOMigration", "EXOMigrationEndpoint", "EXOMobileDeviceMailboxPolicy", "EXOOMEConfiguration", "EXOOfflineAddressBook", "EXOOnPremisesOrganization", "EXOOrganizationConfig", "EXOOrganizationRelationship", "EXOOutboundConnector", "EXOOwaMailboxPolicy", "EXOPartnerApplication", "EXOPerimeterConfiguration", "EXOPhishSimOverrideRule", "EXOPlace", "EXOPolicyTipConfig", "EXOQuarantinePolicy", "EXORecipientPermission", "EXORemoteDomain", "EXOReportSubmissionPolicy", "EXOReportSubmissionRule", "EXOResourceConfiguration", "EXORetentionPolicy", "EXORetentionPolicyTag", "EXORoleAssignmentPolicy", "EXORoleGroup", "EXOSafeAttachmentPolicy", "EXOSafeAttachmentRule", "EXOSafeLinksPolicy", "EXOSafeLinksRule", "EXOSecOpsOverrideRule", "EXOServicePrincipal", "EXOSharedMailbox", "EXOSharingPolicy", "EXOSmtpDaneInbound", "EXOSweepRule", "EXOTeamsProtectionPolicy", "EXOTenantAllowBlockListItems", "EXOTenantAllowBlockListSpoofItems", "EXOTransportConfig", "EXOTransportRule")
	
    "Intune" = @("IntuneAccountProtectionLocalAdministratorPasswordSolutionPolicy", "IntuneAccountProtectionLocalUserGroupMembershipPolicy", "IntuneAccountProtectionPolicyWindows10", "IntuneAndroidManagedStoreAppConfiguration", "IntuneAntivirusExclusionsPolicyLinux", "IntuneAntivirusExclusionsPolicyMacOS", "IntuneAntivirusPolicyLinux", "IntuneAntivirusPolicyMacOS", "IntuneAntivirusPolicySecurityExperienceWindows10ConfigMgr", "IntuneAntivirusPolicyWindows10ConfigMgr", "IntuneAntivirusPolicyWindows10SettingCatalog", "IntuneAppAndBrowserIsolationPolicyWindows10", "IntuneAppAndBrowserIsolationPolicyWindows10ConfigMgr", "IntuneAppCategory", "IntuneAppConfigurationDevicePolicy", "IntuneAppConfigurationPolicy", "IntuneAppControlForBusinessPolicyWindows10", "IntuneAppProtectionPolicyAndroid", "IntuneAppProtectionPolicyiOS", "IntuneAppleMDMPushNotificationCertificate", "IntuneApplicationControlPolicyWindows10", "IntuneAttackSurfaceReductionRulesPolicyWindows10ConfigManager", "IntuneAzureNetworkConnectionWindows365", "IntuneCloudProvisioningPolicyWindows365", "IntuneDefenderGlobalExclusionsPolicyLinux", "IntuneDerivedCredential", "IntuneDeviceAndAppManagementAssignmentFilter", "IntuneDeviceCategory", "IntuneDeviceCleanupRuleV2", "IntuneDeviceComplianceNotificationMessageTemplate", "IntuneDeviceCompliancePolicyAndroidDeviceOwner", "IntuneDeviceCompliancePolicyAndroidWorkProfile", "IntuneDeviceCompliancePolicyMacOS", "IntuneDeviceCompliancePolicyWindows10", "IntuneDeviceCompliancePolicyiOs", "IntuneDeviceComplianceScriptLinux", "IntuneDeviceComplianceScriptWindows10", "IntuneDeviceConfigurationAdministrativeTemplatePolicyWindows10", "IntuneDeviceConfigurationCustomPolicyWindows10", "IntuneDeviceConfigurationCustomPolicyiOS", "IntuneDeviceConfigurationDefenderForEndpointOnboardingPolicyWindows10", "IntuneDeviceConfigurationDeliveryOptimizationPolicyWindows10", "IntuneDeviceConfigurationDeliveryOptimizationPolicyWindows10V2", "IntuneDeviceConfigurationDomainJoinPolicyWindows10", "IntuneDeviceConfigurationEmailProfilePolicyWindows10", "IntuneDeviceConfigurationEndpointProtectionPolicyWindows10", "IntuneDeviceConfigurationFirmwareInterfacePolicyWindows10", "IntuneDeviceConfigurationHealthMonitoringConfigurationPolicyWindows10", "IntuneDeviceConfigurationIdentityProtectionPolicyWindows10", "IntuneDeviceConfigurationImportedPfxCertificatePolicyWindows10", "IntuneDeviceConfigurationKioskPolicyWindows10", "IntuneDeviceConfigurationNetworkBoundaryPolicyWindows10", "IntuneDeviceConfigurationPkcsCertificatePolicyWindows10", "IntuneDeviceConfigurationPlatformScriptMacOS", "IntuneDeviceConfigurationPlatformScriptWindows", "IntuneDeviceConfigurationPolicyAndroidDeviceOwner", "IntuneDeviceConfigurationPolicyAndroidOpenSourceProject", "IntuneDeviceConfigurationPolicyAndroidWorkProfile", "IntuneDeviceConfigurationPolicyMacOS", "IntuneDeviceConfigurationPolicyWindows10", "IntuneDeviceConfigurationPolicyiOS", "IntuneDeviceConfigurationSCEPCertificatePolicyWindows10", "IntuneDeviceConfigurationSecureAssessmentPolicyWindows10", "IntuneDeviceConfigurationSharedMultiDevicePolicyWindows10", "IntuneDeviceConfigurationTrustedCertificatePolicyWindows10", "IntuneDeviceConfigurationVpnPolicyWindows10", "IntuneDeviceConfigurationWindowsTeamPolicyWindows10", "IntuneDeviceConfigurationWiredNetworkPolicyWindows10", "IntuneDeviceControlPolicyWindows10", "IntuneDeviceEnrollmentLimitRestriction", "IntuneDeviceEnrollmentPlatformRestriction", "IntuneDeviceEnrollmentStatusPageWindows10", "IntuneDeviceFeaturesConfigurationPolicyIOS", "IntuneDeviceManagementAndroidDeviceOwnerEnrollmentProfile", "IntuneDeviceManagementComplianceSettings", "IntuneDeviceManagementEnrollmentAndroidGooglePlay", "IntuneDeviceRemediation", "IntuneDiskEncryptionMacOS", "IntuneDiskEncryptionPDEPolicyWindows10", "IntuneDiskEncryptionWindows10", "IntuneEndpointDetectionAndResponsePolicyLinux", "IntuneEndpointDetectionAndResponsePolicyMacOS", "IntuneEndpointDetectionAndResponsePolicyWindows10", "IntuneEpmElevationRulesPolicyWindows10", "IntuneEpmElevationSettingsPolicyWindows10", "IntuneExploitProtectionPolicyWindows10SettingCatalog", "IntuneFirewallPolicyWindows10", "IntuneFirewallRulesHyperVPolicyWindows10", "IntuneFirewallRulesPolicyWindows10", "IntuneFirewallRulesPolicyWindows10ConfigMgr", "IntuneMobileAppsBuiltInStoreApp", "IntuneMobileAppsBundleMacOS", "IntuneMobileAppsDefenderForEndpointMacOS", "IntuneMobileAppsLobAppAndroid", "IntuneMobileAppsLobAppMsiWindows10", "IntuneMobileAppsLobAppWindows10", "IntuneMobileAppsLobAppiOS", "IntuneMobileAppsMacOSLobApp", "IntuneMobileAppsManagedGooglePlayApp", "IntuneMobileAppsMicrosoft365SuiteMacOS", "IntuneMobileAppsMicrosoftEdge", "IntuneMobileAppsMicrosoftStoreAppWindows10", "IntuneMobileAppsStoreApp", "IntuneMobileAppsSystemAppAndroid", "IntuneMobileAppsWebLink", "IntuneMobileAppsWin32AppWindows10", "IntuneMobileAppsWindowsOfficeSuiteApp", "IntuneMobileThreatDefenseConnector", "IntunePolicySets", "IntuneRoleAssignment", "IntuneRoleDefinition", "IntuneRoleScopeTag", "IntuneSecurityBaselineDefenderForEndpoint", "IntuneSecurityBaselineHoloLens2Advanced", "IntuneSecurityBaselineHoloLens2Standard", "IntuneSecurityBaselineMicrosoft365AppsForEnterprise", "IntuneSecurityBaselineMicrosoftEdge", "IntuneSecurityBaselineWindows10", "IntuneSecurityBaselineWindows365", "IntuneSettingCatalogASRRulesPolicyWindows10", "IntuneSettingCatalogCustomPolicyWindows10", "IntuneTrustedRootCertificateAndroidDeviceOwner", "IntuneTrustedRootCertificateAndroidWork", "IntuneTrustedRootCertificateIOS", "IntuneUserSettingsPolicyWindows365", "IntuneVPNConfigurationPolicyAndroidDeviceOwner", "IntuneVPNConfigurationPolicyAndroidWork", "IntuneVPNConfigurationPolicyIOS", "IntuneWifiConfigurationPolicyAndroidEnterpriseDeviceOwner", "IntuneWifiConfigurationPolicyAndroidEnterpriseWorkProfile", "IntuneWifiConfigurationPolicyAndroidForWork", "IntuneWifiConfigurationPolicyAndroidOpenSourceProject", "IntuneWifiConfigurationPolicyIOS", "IntuneWifiConfigurationPolicyMacOS", "IntuneWifiConfigurationPolicyWindows10", "IntuneWindowsAutopilotDeploymentProfileAzureADHybridJoined", "IntuneWindowsAutopilotDeploymentProfileAzureADJoined", "IntuneWindowsBackupForOrganizationConfiguration", "IntuneWindowsHelloForBusinessGlobalPolicy", "IntuneWindowsInformationProtectionPolicyWindows10MdmEnrolled")
	
    "SharePoint" = @("ODSettings", "SPOAccessControlSettings", "SPOApp", "SPOBrowserIdleSignout", "SPOHomeSite", "SPOHubSite", "SPOOrgAssetsLibrary", "SPORetentionLabelsSettings", "SPOSharingSettings", "SPOSite", "SPOSiteAuditSettings", "SPOSiteDesign", "SPOSiteDesignRights", "SPOSiteScript", "SPOStorageEntity", "SPOTenantCdnEnabled", "SPOTenantCdnPolicy", "SPOTenantSettings", "SPOTheme")
    
	"Compliance" = @("SCAuditConfigurationPolicy", "SCAutoSensitivityLabelPolicy", "SCAutoSensitivityLabelRule", "SCCaseHoldPolicy", "SCCaseHoldRule", "SCComplianceCase", "SCComplianceSearch", "SCComplianceSearchAction", "SCComplianceTag", "SCDLPCompliancePolicy", "SCDLPComplianceRule", "SCDeviceConditionalAccessPolicy", "SCDeviceConditionalAccessRule", "SCDeviceConfigurationPolicy", "SCDeviceConfigurationRule", "SCFilePlanPropertyAuthority", "SCFilePlanPropertyCategory", "SCFilePlanPropertyCitation", "SCFilePlanPropertyDepartment", "SCFilePlanPropertyReferenceId", "SCFilePlanPropertySubCategory", "SCInsiderRiskEntityList", "SCInsiderRiskPolicy", "SCLabelPolicy", "SCPolicyConfig", "SCProtectionAlert", "SCRecordReviewNotificationTemplateConfig", "SCRetentionCompliancePolicy", "SCRetentionComplianceRule", "SCRetentionEventType", "SCRoleGroup", "SCRoleGroupMember", "SCSecurityFilter", "SCSensitivityLabel", "SCSupervisoryReviewPolicy", "SCSupervisoryReviewRule", "SCUnifiedAuditLogRetentionPolicy")
    
	"Teams" = @("TeamsAppPermissionPolicy", "TeamsAppSetupPolicy", "TeamsApplicationInstance", "TeamsAudioConferencingPolicy", "TeamsCallHoldPolicy", "TeamsCallParkPolicy", "TeamsCallQueue", "TeamsCallingPolicy", "TeamsChannel", "TeamsChannelsPolicy", "TeamsClientConfiguration", "TeamsComplianceRecordingPolicy", "TeamsCortanaPolicy", "TeamsDialInConferencingTenantSettings", "TeamsEmergencyCallRoutingPolicy", "TeamsEmergencyCallingPolicy", "TeamsEnhancedEncryptionPolicy", "TeamsEventsPolicy", "TeamsFederationConfiguration", "TeamsFeedbackPolicy", "TeamsFilesPolicy", "TeamsGroupPolicyAssignment", "TeamsGuestCallingConfiguration", "TeamsGuestMeetingConfiguration", "TeamsGuestMessagingConfiguration", "TeamsIPPhonePolicy", "TeamsM365App", "TeamsMeetingBroadcastConfiguration", "TeamsMeetingBroadcastPolicy", "TeamsMeetingConfiguration", "TeamsMeetingPolicy", "TeamsMessagingConfiguration", "TeamsMessagingPolicy", "TeamsMobilityPolicy", "TeamsNetworkRoamingPolicy", "TeamsOnlineVoiceUser", "TeamsOnlineVoicemailPolicy", "TeamsOnlineVoicemailUserSettings", "TeamsPstnUsage", "TeamsShiftsPolicy", "TeamsTeam", "TeamsTemplatesPolicy", "TeamsTenantDialPlan", "TeamsTenantNetworkRegion", "TeamsTenantNetworkSite", "TeamsTenantNetworkSubnet", "TeamsTenantTrustedIPAddress", "TeamsTranslationRule", "TeamsUnassignedNumberTreatment", "TeamsUpdateManagementPolicy", "TeamsUpgradeConfiguration", "TeamsUpgradePolicy", "TeamsUser", "TeamsUserCallingSettings", "TeamsUserPolicyAssignment", "TeamsVdiPolicy", "TeamsVoiceRoute", "TeamsVoiceRoutingPolicy", "TeamsWorkloadPolicy")
}

$SelectedComponents = if ($Workload -and $WorkloadComponents.ContainsKey($Workload)) {
    $WorkloadComponents[$Workload]
} else {
    $WorkloadComponents.Values | ForEach-Object { $_ }
}

# New-M365DSCDeltaReport -Source "$PathCurrent\M365TenantConfig.ps1" -Destination "$PathDrift\M365TenantConfig.ps1" -OutputPath "$PathReport\$TenantName-DriftReport-M365-$Workload.html"
# New-M365DSCDeltaReport -Source "$PathCurrent\M365TenantConfig.ps1" -Destination "$PathDrift\M365TenantConfig.ps1" -Type JSON -OutputPath "$PathReport\$TenantName-DriftReport-M365-$Workload.json"


# -----------------------------------------------------------------------------------
# 1. Generate drift report JSON
# -----------------------------------------------------------------------------------
New-M365DSCDeltaReport -Source "$PathCurrent\M365TenantConfig.ps1" -Destination "$PathDrift\M365TenantConfig.ps1" -Type JSON -OutputPath "$PathReport\$TenantName-DriftReport-M365-$Workload.json"

# Path to the generated JSON file
$jsonPath = "$PathReport\$TenantName-DriftReport-M365-$Workload.json"

if (-not (Test-Path $jsonPath)) {
    Write-Warning "JSON drift file not found: $jsonPath"
    return
}

# -----------------------------------------------------------------------------------
# 2. Determine drift based on system file size
#    Rule: if file size < 1 byte  → geen wijzigingen
#          if file size > 1 byte  → wijzigingen gevonden
# -----------------------------------------------------------------------------------
$file          = Get-Item -Path $jsonPath
$fileSizeBytes = [int64]$file.Length

$driftDetected = $false
if ($fileSizeBytes -gt 1) {
    $driftDetected = $true
}

Write-Verbose "Drift JSON size: $fileSizeBytes bytes. DriftDetected = $driftDetected"

# -----------------------------------------------------------------------------------
# 3. Build HTML content for the email (altijd mail sturen)
# -----------------------------------------------------------------------------------
$htmlContent = @"
<h2>Microsoft 365 configuration drift report from Rubicon Cloud Advisor</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU"
     width="10%" height="10%" alt="Banner Image" class="banner">
<h4>Organization Domain: $TenantName</h4>
"@

if ($driftDetected) {
    # Tekst wanneer er wijzigingen zijn
    $htmlContent += @"
<p>Er zijn configuratiewijzigingen gedetecteerd in de Microsoft 365 tenant voor workload <strong>$Workload</strong>.</p>
<p>Het JSON drift-rapport is opgeslagen op locatie:<br><code>$jsonPath</code></p>
<p>Bestandsgrootte drift JSON: <strong>$fileSizeBytes</strong> bytes.</p>
"@
}
else {
    # Tekst wanneer er géén wijzigingen zijn
    $htmlContent += @"
<p>Er zijn <strong>geen</strong> configuratiewijzigingen gedetecteerd in de Microsoft 365 tenant voor workload <strong>$Workload</strong>.</p>
<p>Het (lege) JSON drift-rapport is opgeslagen op locatie:<br><code>$jsonPath</code></p>
<p>Bestandsgrootte drift JSON: <strong>$fileSizeBytes</strong> bytes.</p>
"@
}

# -----------------------------------------------------------------------------------
# 4. Send the email via Microsoft Graph (altijd mail sturen als we hier komen)
# -----------------------------------------------------------------------------------

# Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# (Optioneel kun je het subject dynamisch maken, maar hier is het neutraal gehouden)
$params = @{
    message = @{
        subject = "$Customer | Drift Detection M365 for $Workload"
        body    = @{
            contentType = "HTML"
            content     = $htmlContent
        }
        toRecipients = @(
            @{
                emailAddress = @{
                    address = $EXOMailTo
                }
            }
        )
    }
}

Write-Verbose "Sending email with the M365 drift detection notification (driftDetected = $driftDetected, fileSizeBytes = $fileSizeBytes)"
Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params



# Disconnect from Microsoft Graph for email operations
# Disconnect-MgGraph

Write-Verbose "Email sent successfully"