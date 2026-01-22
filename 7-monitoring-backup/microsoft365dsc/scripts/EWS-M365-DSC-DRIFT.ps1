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
     "EntraID" = @("AADAccessReviewPolicy", "AADActivityBasedTimeoutPolicy", "AADAdminConsentRequestPolicy", "AADAdministrativeUnit", "AADAgreement", "AADAppManagementPolicy", "AADApplication", "AADAttributeSet", "AADAuthenticationContextClassReference", "AADAuthenticationFlowPolicy", "AADAuthenticationMethodPolicy", "AADAuthenticationMethodPolicyAuthenticator", "AADAuthenticationMethodPolicyEmail", "AADAuthenticationMethodPolicyExternal", "AADAuthenticationMethodPolicyFido2", "AADAuthenticationMethodPolicyHardware", "AADAuthenticationMethodPolicyQRCodeImage", "AADAuthenticationMethodPolicySms", "AADAuthenticationMethodPolicySoftware", "AADAuthenticationMethodPolicyTemporary", "AADAuthenticationMethodPolicyVoice", "AADAuthenticationMethodPolicyX509", "AADAuthenticationStrengthPolicy", "AADAuthorizationPolicy", "AADB2CAuthenticationMethodsPolicy", "AADConditionalAccessPolicy", "AADConnectorGroupApplicationProxy", "AADCrossTenantAccessPolicy", "AADCrossTenantAccessPolicyConfigurationDefault", "AADCrossTenantAccessPolicyConfigurationPartner", "AADCustomAuthenticationExtension", "AADDeviceRegistrationPolicy", "AADDomain", "AADEntitlementManagementAccessPackage", "AADEntitlementManagementAccessPackageCatalog", "AADEntitlementManagementAccessPackageCatalogResource", "AADEntitlementManagementConnectedOrganization", "AADEntitlementManagementRoleAssignment", "AADEntitlementManagementSettings", "AADExternalIdentityPolicy", "AADFeatureRolloutPolicy", "AADFederationConfiguration", "AADFilteringPolicyRule", "AADGroup", "AADGroupLifecyclePolicy", "AADGroupsNamingPolicy", "AADGroupsSettings", "AADHomeRealmDiscoveryPolicy", "AADIdentityGovernanceLifecycleWorkflow", "AADIdentityGovernanceLifecycleWorkflowCustomTaskExtension", "AADIdentityProtectionPolicySettings", "AADLifecycleWorkflowSettings", "AADMultiTenantOrganizationIdentitySyncPolicyTemplate", "AADNamedLocationPolicy", "AADNetworkAccessSettingConditionalAccess", "AADNetworkAccessSettingCrossTenantAccess", "AADOnPremisesPublishingProfilesSettings", "AADOrganizationCertificateBasedAuthConfiguration", "AADPasswordRuleSettings", "AADRoleManagementPolicyRule", "AADRoleSetting", "AADSecurityDefaults", "AADServicePrincipal", "AADSocialIdentityProvider", "AADTenantAppManagementPolicy", "AADTenantDetails", "AADTokenIssuancePolicy", "AADTokenLifetimePolicy", "AADUser", "AADVerifiedIdAuthority", "AADVerifiedIdAuthorityContract", "ADOOrganizationOwner", "ADOPermissionGroup", "ADOPermissionGroupSettings", "ADOSecurityPolicy")
	
    "Exchange" = @("EXOATPBuiltInProtectionRule", "EXOAcceptedDomain", "EXOAddressBookPolicy", "EXOAddressList", "EXOAntiPhishPolicy", "EXOAntiPhishRule", "EXOApplicationAccessPolicy", "EXOArcConfig", "EXOAtpPolicyForO365", "EXOAtpProtectionPolicyRule", "EXOAuthenticationPolicy", "EXOAuthenticationPolicyAssignment", "EXODataAtRestEncryptionPolicy", "EXODataAtRestEncryptionPolicyAssignment", "EXODataClassification", "EXODataEncryptionPolicy", "EXODkimSigningConfig", "EXODnssecForVerifiedDomain", "EXOEOPProtectionPolicyRule", "EXOEmailAddressPolicy", "EXOEmailTenantSettings", "EXOGlobalAddressList", "EXOGroupSettings", "EXOHostedConnectionFilterPolicy", "EXOHostedContentFilterPolicy", "EXOHostedContentFilterRule", "EXOHostedOutboundSpamFilterPolicy", "EXOHostedOutboundSpamFilterRule", "EXOIRMConfiguration", "EXOInboundConnector", "EXOIntraOrganizationConnector", "EXOJournalRule", "EXOMailContact", "EXOMalwareFilterPolicy", "EXOMalwareFilterRule", "EXOManagementRole", "EXOManagementRoleAssignment", "EXOManagementScope", "EXOMessageClassification", "EXOMigration", "EXOMigrationEndpoint", "EXOMobileDeviceMailboxPolicy", "EXOOMEConfiguration", "EXOOnPremisesOrganization", "EXOOrganizationConfig", "EXOOrganizationRelationship", "EXOOutboundConnector", "EXOOwaMailboxPolicy", "EXOPartnerApplication", "EXOPerimeterConfiguration", "EXOPlace", "EXOPolicyTipConfig", "EXOQuarantinePolicy", "EXORemoteDomain", "EXOReportSubmissionPolicy", "EXOReportSubmissionRule", "EXORetentionPolicy", "EXORetentionPolicyTag", "EXORoleAssignmentPolicy", "EXORoleGroup", "EXOSafeAttachmentPolicy", "EXOSafeAttachmentRule", "EXOSafeLinksPolicy", "EXOSafeLinksRule", "EXOSharedMailbox", "EXOSharingPolicy", "EXOSmtpDaneInbound", "EXOTeamsProtectionPolicy", "EXOTenantAllowBlockListItems", "EXOTenantAllowBlockListSpoofItems", "EXOTransportConfig", "EXOTransportRule")
	
    "Intune" = @("IntuneAccountProtectionLocalAdministratorPasswordSolutionPolicy", "IntuneAccountProtectionLocalUserGroupMembershipPolicy", "IntuneAccountProtectionPolicyWindows10", "IntuneAndroidManagedStoreAppConfiguration", "IntuneAntivirusExclusionsPolicyLinux", "IntuneAntivirusExclusionsPolicyMacOS", "IntuneAntivirusPolicyLinux", "IntuneAntivirusPolicyMacOS", "IntuneAntivirusPolicySecurityExperienceWindows10ConfigMgr", "IntuneAntivirusPolicyWindows10ConfigMgr", "IntuneAntivirusPolicyWindows10SettingCatalog", "IntuneAppAndBrowserIsolationPolicyWindows10", "IntuneAppAndBrowserIsolationPolicyWindows10ConfigMgr", "IntuneAppCategory", "IntuneAppConfigurationDevicePolicy", "IntuneAppConfigurationPolicy", "IntuneAppControlForBusinessPolicyWindows10", "IntuneAppProtectionPolicyAndroid", "IntuneAppProtectionPolicyiOS", "IntuneAppleMDMPushNotificationCertificate", "IntuneApplicationControlPolicyWindows10", "IntuneAttackSurfaceReductionRulesPolicyWindows10ConfigManager", "IntuneDefenderGlobalExclusionsPolicyLinux", "IntuneDerivedCredential", "IntuneDeviceCategory", "IntuneDeviceCleanupRuleV2", "IntuneDeviceComplianceNotificationMessageTemplate", "IntuneDeviceCompliancePolicyAndroidDeviceOwner", "IntuneDeviceCompliancePolicyAndroidWorkProfile", "IntuneDeviceCompliancePolicyMacOS", "IntuneDeviceCompliancePolicyWindows10", "IntuneDeviceCompliancePolicyiOs", "IntuneDeviceComplianceScriptLinux", "IntuneDeviceComplianceScriptWindows10", "IntuneDeviceConfigurationAdministrativeTemplatePolicyWindows10", "IntuneDeviceConfigurationCustomPolicyWindows10", "IntuneDeviceConfigurationCustomPolicyiOS", "IntuneDeviceConfigurationDefenderForEndpointOnboardingPolicyWindows10", "IntuneDeviceConfigurationDeliveryOptimizationPolicyWindows10", "IntuneDeviceConfigurationDeliveryOptimizationPolicyWindows10V2", "IntuneDeviceConfigurationDomainJoinPolicyWindows10", "IntuneDeviceConfigurationEmailProfilePolicyWindows10", "IntuneDeviceConfigurationEndpointProtectionPolicyWindows10", "IntuneDeviceConfigurationFirmwareInterfacePolicyWindows10", "IntuneDeviceConfigurationHealthMonitoringConfigurationPolicyWindows10", "IntuneDeviceConfigurationIdentityProtectionPolicyWindows10", "IntuneDeviceConfigurationImportedPfxCertificatePolicyWindows10", "IntuneDeviceConfigurationKioskPolicyWindows10", "IntuneDeviceConfigurationNetworkBoundaryPolicyWindows10", "IntuneDeviceConfigurationPkcsCertificatePolicyWindows10", "IntuneDeviceConfigurationPlatformScriptMacOS", "IntuneDeviceConfigurationPlatformScriptWindows", "IntuneDeviceConfigurationPolicyAndroidDeviceOwner", "IntuneDeviceConfigurationPolicyAndroidOpenSourceProject", "IntuneDeviceConfigurationPolicyAndroidWorkProfile", "IntuneDeviceConfigurationPolicyMacOS", "IntuneDeviceConfigurationPolicyWindows10", "IntuneDeviceConfigurationPolicyiOS", "IntuneDeviceConfigurationSCEPCertificatePolicyWindows10", "IntuneDeviceConfigurationSecureAssessmentPolicyWindows10", "IntuneDeviceConfigurationSharedMultiDevicePolicyWindows10", "IntuneDeviceConfigurationTrustedCertificatePolicyWindows10", "IntuneDeviceConfigurationVpnPolicyWindows10", "IntuneDeviceConfigurationWindowsTeamPolicyWindows10", "IntuneDeviceConfigurationWiredNetworkPolicyWindows10", "IntuneDeviceControlPolicyWindows10", "IntuneDeviceEnrollmentLimitRestriction", "IntuneDeviceEnrollmentPlatformRestriction", "IntuneDeviceEnrollmentStatusPageWindows10", "IntuneDeviceFeaturesConfigurationPolicyIOS", "IntuneDeviceManagementAndroidDeviceOwnerEnrollmentProfile", "IntuneDeviceManagementComplianceSettings", "IntuneDeviceManagementEnrollmentAndroidGooglePlay", "IntuneDeviceRemediation", "IntuneDiskEncryptionMacOS", "IntuneDiskEncryptionPDEPolicyWindows10", "IntuneDiskEncryptionWindows10", "IntuneEndpointDetectionAndResponsePolicyLinux", "IntuneEndpointDetectionAndResponsePolicyMacOS", "IntuneEndpointDetectionAndResponsePolicyWindows10", "IntuneEpmElevationRulesPolicyWindows10", "IntuneEpmElevationSettingsPolicyWindows10", "IntuneExploitProtectionPolicyWindows10SettingCatalog", "IntuneFirewallPolicyWindows10", "IntuneFirewallRulesHyperVPolicyWindows10", "IntuneFirewallRulesPolicyWindows10", "IntuneFirewallRulesPolicyWindows10ConfigMgr", "IntunePolicySets", "IntuneRoleAssignment", "IntuneRoleDefinition", "IntuneRoleScopeTag", "IntuneSecurityBaselineDefenderForEndpoint", "IntuneSecurityBaselineHoloLens2Advanced", "IntuneSecurityBaselineHoloLens2Standard", "IntuneSecurityBaselineMicrosoft365AppsForEnterprise", "IntuneSecurityBaselineMicrosoftEdge", "IntuneSecurityBaselineWindows10", "IntuneSecurityBaselineWindows365", "IntuneSettingCatalogASRRulesPolicyWindows10", "IntuneSettingCatalogCustomPolicyWindows10", "IntuneTrustedRootCertificateAndroidDeviceOwner", "IntuneTrustedRootCertificateAndroidWork", "IntuneTrustedRootCertificateIOS", "IntuneVPNConfigurationPolicyAndroidDeviceOwner", "IntuneVPNConfigurationPolicyAndroidWork", "IntuneVPNConfigurationPolicyIOS", "IntuneWifiConfigurationPolicyAndroidEnterpriseDeviceOwner", "IntuneWifiConfigurationPolicyAndroidEnterpriseWorkProfile", "IntuneWifiConfigurationPolicyAndroidForWork", "IntuneWifiConfigurationPolicyAndroidOpenSourceProject", "IntuneWifiConfigurationPolicyIOS", "IntuneWifiConfigurationPolicyMacOS", "IntuneWifiConfigurationPolicyWindows10", "IntuneWindowsAutopilotDeploymentProfileAzureADHybridJoined", "IntuneWindowsAutopilotDeploymentProfileAzureADJoined", "IntuneWindowsBackupForOrganizationConfiguration", "IntuneWindowsHelloForBusinessGlobalPolicy", "IntuneWindowsInformationProtectionPolicyWindows10MdmEnrolled")
	
    "SharePoint" = @("ODSettings", "SPOAccessControlSettings", "SPOBrowserIdleSignout", "SPOHomeSite", "SPOHubSite", "SPOOrgAssetsLibrary", "SPORetentionLabelsSettings", "SPOSite", "SPOSiteAuditSettings", "SPOSiteDesign", "SPOSiteDesignRights", "SPOSiteScript", "SPOStorageEntity", "SPOTenantCdnEnabled", "SPOTenantCdnPolicy", "SPOTenantSettings", "SPOTheme")
    
	"Compliance" = @("SCAuditConfigurationPolicy", "SCAutoSensitivityLabelPolicy", "SCAutoSensitivityLabelRule", "SCCaseHoldPolicy", "SCCaseHoldRule", "SCComplianceCase", "SCComplianceSearch", "SCComplianceSearchAction", "SCComplianceTag", "SCDLPCompliancePolicy", "SCDeviceConditionalAccessPolicy", "SCDeviceConditionalAccessRule", "SCDeviceConfigurationPolicy", "SCDeviceConfigurationRule", "SCFilePlanPropertyAuthority", "SCFilePlanPropertyCategory", "SCFilePlanPropertyCitation", "SCFilePlanPropertyDepartment", "SCFilePlanPropertyReferenceId", "SCFilePlanPropertySubCategory", "SCInsiderRiskEntityList", "SCInsiderRiskPolicy", "SCLabelPolicy", "SCPolicyConfig", "SCProtectionAlert", "SCRecordReviewNotificationTemplateConfig", "SCRetentionCompliancePolicy", "SCRetentionComplianceRule", "SCRetentionEventType", "SCRoleGroup", "SCRoleGroupMember", "SCSensitivityLabel", "SCSupervisoryReviewPolicy", "SCSupervisoryReviewRule", "SCUnifiedAuditLogRetentionPolicy")
    
	"Teams" = @("TeamsAppPermissionPolicy", "TeamsAppSetupPolicy", "TeamsApplicationInstance", "TeamsAudioConferencingPolicy", "TeamsCallHoldPolicy", "TeamsCallParkPolicy", "TeamsCallQueue", "TeamsCallingPolicy", "TeamsChannelsPolicy", "TeamsClientConfiguration", "TeamsComplianceRecordingPolicy", "TeamsCortanaPolicy", "TeamsDialInConferencingTenantSettings", "TeamsEmergencyCallRoutingPolicy", "TeamsEmergencyCallingPolicy", "TeamsEnhancedEncryptionPolicy", "TeamsEventsPolicy", "TeamsFederationConfiguration", "TeamsFeedbackPolicy", "TeamsFilesPolicy", "TeamsGroupPolicyAssignment", "TeamsGuestCallingConfiguration", "TeamsGuestMeetingConfiguration", "TeamsGuestMessagingConfiguration", "TeamsIPPhonePolicy", "TeamsM365App", "TeamsMeetingBroadcastConfiguration", "TeamsMeetingBroadcastPolicy", "TeamsMeetingConfiguration", "TeamsMeetingPolicy", "TeamsMessagingConfiguration", "TeamsMessagingPolicy", "TeamsMobilityPolicy", "TeamsNetworkRoamingPolicy", "TeamsOnlineVoicemailPolicy", "TeamsPstnUsage", "TeamsShiftsPolicy", "TeamsTeam", "TeamsTemplatesPolicy", "TeamsTenantDialPlan", "TeamsTenantNetworkRegion", "TeamsTenantNetworkSite", "TeamsTenantNetworkSubnet", "TeamsTenantTrustedIPAddress", "TeamsTranslationRule", "TeamsUnassignedNumberTreatment", "TeamsUpdateManagementPolicy", "TeamsUpgradeConfiguration", "TeamsUpgradePolicy", "TeamsVdiPolicy", "TeamsVoiceRoute", "TeamsVoiceRoutingPolicy", "TeamsWorkloadPolicy")
}

$SelectedComponents = if ($Workload -and $WorkloadComponents.ContainsKey($Workload)) {
    $WorkloadComponents[$Workload]
} else {
    $WorkloadComponents.Values | ForEach-Object { $_ }
}

Export-M365DSCConfiguration -Components $SelectedComponents -ApplicationId $WorkloadClientId -CertificateThumbprint $WorkloadThumbprint -TenantId $TenantName -Path $PathDrift

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
# Determine drift
# -----------------------------------------------------------------------------------

$fileSizeBytes = (Get-Item $jsonPath).Length
$driftDetected = ($fileSizeBytes -gt 18)

Write-Verbose "Drift JSON size: $fileSizeBytes bytes. DriftDetected = $driftDetected"

# ❌ EXIT if no drift detected
if (-not $driftDetected) {
    Write-Verbose "No drift detected. Email will NOT be sent."
    return
}

# -----------------------------------------------------------------------------------
# Build HTML email (ONLY when drift exists)
# -----------------------------------------------------------------------------------

# Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Extract and summarize changed resources from the JSON drift file
$driftJson = Get-Content -Raw -Path $jsonPath | ConvertFrom-Json
$allResourceNames = @()

if ($driftJson -is [System.Collections.IEnumerable]) {
    foreach ($entry in $driftJson) {
        if ($null -ne $entry.ResourceName) {
            $allResourceNames += $entry.ResourceName
        }
        elseif ($entry.Delta) {
            foreach ($deltaItem in $entry.Delta) {
                if ($null -ne $deltaItem.ResourceName) {
                    $allResourceNames += $deltaItem.ResourceName
                }
            }
        }
    }
}
elseif ($driftJson.Delta) {
    foreach ($deltaItem in $driftJson.Delta) {
        if ($null -ne $deltaItem.ResourceName) {
            $allResourceNames += $deltaItem.ResourceName
        }
    }
}

if (-not $allResourceNames) {
    $allResourceNames = @()
}

$resCount = $allResourceNames | Group-Object | Sort-Object -Property Count -Descending

if ($resCount.Count -gt 0) {
    $resourceTable = "<h3>Changed Resources Summary</h3>"
    $resourceTable += "<table border='1' cellpadding='5' cellspacing='0'><tr><th>Resource Name</th><th>Count</th></tr>"
    foreach ($res in $resCount) {
        $resourceTable += "<tr><td>$($res.Name)</td><td>$($res.Count)</td></tr>"
    }
    $resourceTable += "</table>"
}
else {
    $resourceTable = "<p>No changed resources detected in drift report.</p>"
}

$htmlContent = @"
<h2>Microsoft 365 configuration drift report from Rubicon Cloud Advisor</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU"
     width="10%" height="10%" alt="Banner Image">
<h4>Organization Domain: $TenantName</h4>

<p><strong>Configuration drift detected</strong> in the Microsoft 365 tenant.</p>
<p>Workload: <strong>$Workload</strong></p>
<p>Drift report location:<br><code>$jsonPath</code></p>
<p>Drift JSON size: <strong>$fileSizeBytes</strong> bytes</p>
$resourceTable
"@

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
    saveToSentItems = $true  # optional, but recommended
}

# Ensure Connect-MgGraph has run and is connected

Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params
# Disconnect-MgGraph