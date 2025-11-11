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
    "EntraID"      = @("AADActivityBasedTimeoutPolicy", "AADAdministrativeUnit", "AADApplication", "AADAttributeSet", "AADAuthenticationContextClassReference", "AADAuthenticationFlowPolicy", "AADAuthenticationMethodPolicy", "AADAuthenticationMethodPolicyAuthenticator", "AADAuthenticationMethodPolicyEmail", "AADAuthenticationMethodPolicyFido2", "AADAuthenticationMethodPolicySms", "AADAuthenticationMethodPolicySoftware", "AADAuthenticationMethodPolicyTemporary", "AADAuthenticationMethodPolicyVoice", "AADAuthenticationMethodPolicyX509", "AADAuthenticationStrengthPolicy", "AADAuthorizationPolicy", "AADConditionalAccessPolicy", "AADCrossTenantAccessPolicy", "AADCrossTenantAccessPolicyConfigurationDefault", "AADCrossTenantAccessPolicyConfigurationPartner", "AADEntitlementManagementAccessPackage", "AADEntitlementManagementAccessPackageAssignmentPolicy", "AADEntitlementManagementAccessPackageCatalog", "AADEntitlementManagementAccessPackageCatalogResource", "AADEntitlementManagementConnectedOrganization", "AADEntitlementManagementRoleAssignment", "AADExternalIdentityPolicy", "AADGroup", "AADGroupLifecyclePolicy", "AADGroupsNamingPolicy", "AADGroupsSettings", "AADNamedLocationPolicy", "AADRoleDefinition", "AADRoleEligibilityScheduleRequest", "AADRoleSetting", "AADSecurityDefaults", "AADServicePrincipal", "AADSocialIdentityProvider", "AADTenantDetails", "AADTokenLifetimePolicy", "AADUser")
	
    "Exchange" = @("EXOAcceptedDomain", "EXOActiveSyncDeviceAccessRule", "EXOAddressBookPolicy", "EXOAddressList", "EXOAntiPhishPolicy", "EXOAntiPhishRule", "EXOApplicationAccessPolicy", "EXOAtpPolicyForO365", "EXOAuthenticationPolicy", "EXOAuthenticationPolicyAssignment", "EXOAvailabilityAddressSpace", "EXOAvailabilityConfig", "EXOCalendarProcessing", "EXOCASMailboxPlan", "EXOCASMailboxSettings", "EXOClientAccessRule", "EXODataClassification", "EXODataEncryptionPolicy", "EXODistributionGroup", "EXODkimSigningConfig", "EXOEmailAddressPolicy", "EXOGlobalAddressList", "EXOGroupSettings", "EXOHostedConnectionFilterPolicy", "EXOHostedContentFilterPolicy", "EXOHostedContentFilterRule", "EXOHostedOutboundSpamFilterPolicy", "EXOHostedOutboundSpamFilterRule", "EXOInboundConnector", "EXOIntraOrganizationConnector", "EXOIRMConfiguration", "EXOJournalRule", "EXOMailboxCalendarFolder", "EXOMailboxPermission", "EXOMailboxPlan", "EXOMailboxSettings", "EXOMailContact", "EXOMailTips", "EXOMalwareFilterPolicy", "EXOMalwareFilterRule", "EXOManagementRole", "EXOManagementRoleAssignment", "EXOManagementRoleEntry", "EXOMessageClassification", "EXOMobileDeviceMailboxPolicy", "EXOOfflineAddressBook", "EXOOMEConfiguration", "EXOOnPremisesOrganization", "EXOOrganizationConfig", "EXOOrganizationRelationship", "EXOOutboundConnector", "EXOOwaMailboxPolicy", "EXOPartnerApplication", "EXOPerimeterConfiguration", "EXOPlace", "EXOPolicyTipConfig", "EXOQuarantinePolicy", "EXORecipientPermission", "EXORemoteDomain", "EXOReportSubmissionPolicy", "EXOReportSubmissionRule", "EXOResourceConfiguration", "EXORoleAssignmentPolicy", "EXORoleGroup", "EXOSafeAttachmentPolicy", "EXOSafeAttachmentRule", "EXOSafeLinksPolicy", "EXOSafeLinksRule", "EXOSharedMailbox", "EXOSharingPolicy", "EXOTransportConfig", "EXOTransportRule")
	
    "Intune" = @("IntuneAccountProtectionLocalAdministratorPasswordSolutionPolicy", "IntuneAccountProtectionLocalUserGroupMembershipPolicy", "IntuneAccountProtectionPolicy", "IntuneAntivirusPolicyWindows10SettingCatalog", "IntuneAppConfigurationDevicePolicy", "IntuneAppConfigurationPolicy", "IntuneApplicationControlPolicyWindows10", "IntuneAppProtectionPolicyAndroid", "IntuneAppProtectionPolicyiOS", "IntuneASRRulesPolicyWindows10", "IntuneAttackSurfaceReductionRulesPolicyWindows10ConfigManager", "IntuneDeviceAndAppManagementAssignmentFilter", "IntuneDeviceCategory", "IntuneDeviceCleanupRule", "IntuneDeviceCompliancePolicyAndroid", "IntuneDeviceCompliancePolicyAndroidDeviceOwner", "IntuneDeviceCompliancePolicyAndroidWorkProfile", "IntuneDeviceCompliancePolicyiOs", "IntuneDeviceCompliancePolicyMacOS", "IntuneDeviceCompliancePolicyWindows10", "IntuneDeviceConfigurationAdministrativeTemplatePolicyWindows10", "IntuneDeviceConfigurationCustomPolicyWindows10", "IntuneDeviceConfigurationDefenderForEndpointOnboardingPolicyWindows10", "IntuneDeviceConfigurationDeliveryOptimizationPolicyWindows10", "IntuneDeviceConfigurationDomainJoinPolicyWindows10", "IntuneDeviceConfigurationEmailProfilePolicyWindows10", "IntuneDeviceConfigurationEndpointProtectionPolicyWindows10", "IntuneDeviceConfigurationFirmwareInterfacePolicyWindows10", "IntuneDeviceConfigurationHealthMonitoringConfigurationPolicyWindows10", "IntuneDeviceConfigurationIdentityProtectionPolicyWindows10", "IntuneDeviceConfigurationImportedPfxCertificatePolicyWindows10", "IntuneDeviceConfigurationKioskPolicyWindows10", "IntuneDeviceConfigurationNetworkBoundaryPolicyWindows10", "IntuneDeviceConfigurationPkcsCertificatePolicyWindows10", "IntuneDeviceConfigurationPlatformScriptMacOS", "IntuneDeviceConfigurationPlatformScriptWindows", "IntuneDeviceConfigurationPolicyAndroidDeviceAdministrator", "IntuneDeviceConfigurationPolicyAndroidDeviceOwner", "IntuneDeviceConfigurationPolicyAndroidOpenSourceProject", "IntuneDeviceConfigurationPolicyAndroidWorkProfile", "IntuneDeviceConfigurationPolicyiOS", "IntuneDeviceConfigurationPolicyMacOS", "IntuneDeviceConfigurationPolicyWindows10", "IntuneDeviceConfigurationSCEPCertificatePolicyWindows10", "IntuneDeviceConfigurationSecureAssessmentPolicyWindows10", "IntuneDeviceConfigurationSharedMultiDevicePolicyWindows10", "IntuneDeviceConfigurationTrustedCertificatePolicyWindows10", "IntuneDeviceConfigurationVpnPolicyWindows10", "IntuneDeviceConfigurationWindowsTeamPolicyWindows10", "IntuneDeviceConfigurationWiredNetworkPolicyWindows10", "IntuneDeviceEnrollmentLimitRestriction", "IntuneDeviceEnrollmentPlatformRestriction", "IntuneDeviceEnrollmentStatusPageWindows10", "IntuneDeviceRemediation", "IntuneDiskEncryptionMacOS", "IntuneEndpointDetectionAndResponsePolicyWindows10", "IntuneExploitProtectionPolicyWindows10SettingCatalog", "IntunePolicySets", "IntuneRoleAssignment", "IntuneRoleDefinition", "IntuneSettingCatalogASRRulesPolicyWindows10", "IntuneSettingCatalogCustomPolicyWindows10", "IntuneWifiConfigurationPolicyAndroidDeviceAdministrator", "IntuneWifiConfigurationPolicyAndroidEnterpriseDeviceOwner", "IntuneWifiConfigurationPolicyAndroidEnterpriseWorkProfile", "IntuneWifiConfigurationPolicyAndroidForWork", "IntuneWifiConfigurationPolicyAndroidOpenSourceProject", "IntuneWifiConfigurationPolicyIOS", "IntuneWifiConfigurationPolicyMacOS", "IntuneWifiConfigurationPolicyWindows10", "IntuneWindowsAutopilotDeploymentProfileAzureADHybridJoined", "IntuneWindowsAutopilotDeploymentProfileAzureADJoined", "IntuneWindowsInformationProtectionPolicyWindows10MdmEnrolled", "IntuneWindowsUpdateForBusinessDriverUpdateProfileWindows10", "IntuneWindowsUpdateForBusinessFeatureUpdateProfileWindows10", "IntuneWindowsUpdateForBusinessRingUpdateProfileWindows10")
	
    "SharePoint" = @("SPOAccessControlSettings", "SPOApp", "SPOBrowserIdleSignout", "SPOHomeSite", "SPOHubSite", "SPOOrgAssetsLibrary", "SPOPropertyBag", "SPOSearchManagedProperty", "SPOSearchResultSource", "SPOSharingSettings", "SPOSite", "SPOSiteAuditSettings", "SPOSiteDesign", "SPOSiteDesignRights", "SPOSiteGroup", "SPOSiteScript", "SPOStorageEntity", "SPOTenantCdnEnabled", "SPOTenantCdnPolicy", "SPOTenantSettings", "SPOTheme", "SPOUserProfileProperty", "ODSettings", "O365AdminAuditLogConfig", "O365Group", "O365OrgCustomizationSetting", "O365OrgSettings", "O365SearchAndIntelligenceConfigurations")
	
    "Compliance" = @("SCAuditConfigurationPolicy", "SCAutoSensitivityLabelPolicy", "SCAutoSensitivityLabelRule", "SCCaseHoldPolicy", "SCCaseHoldRule", "SCComplianceCase", "SCComplianceSearch", "SCComplianceSearchAction", "SCComplianceTag", "SCDeviceConditionalAccessPolicy", "SCDeviceConfigurationPolicy", "SCDLPCompliancePolicy", "SCDLPComplianceRule", "SCFilePlanPropertyAuthority", "SCFilePlanPropertyCategory", "SCFilePlanPropertyCitation", "SCFilePlanPropertyDepartment", "SCFilePlanPropertyReferenceId", "SCFilePlanPropertySubCategory", "SCLabelPolicy", "SCProtectionAlert", "SCRetentionCompliancePolicy", "SCRetentionComplianceRule", "SCRetentionEventType", "SCRoleGroup", "SCRoleGroupMember", "SCSecurityFilter", "SCSensitivityLabel", "SCSupervisoryReviewPolicy", "SCSupervisoryReviewRule")
	
    "Teams"      = @("TeamsAppPermissionPolicy", "TeamsAppSetupPolicy", "TeamsAudioConferencingPolicy", "TeamsCallHoldPolicy", "TeamsCallingPolicy", "TeamsCallParkPolicy", "TeamsCallQueue", "TeamsChannel", "TeamsChannelsPolicy", "TeamsClientConfiguration", "TeamsComplianceRecordingPolicy", "TeamsCortanaPolicy", "TeamsDialInConferencingTenantSettings", "TeamsEmergencyCallingPolicy", "TeamsEmergencyCallRoutingPolicy", "TeamsEnhancedEncryptionPolicy", "TeamsEventsPolicy", "TeamsFederationConfiguration", "TeamsFeedbackPolicy", "TeamsFilesPolicy", "TeamsGroupPolicyAssignment", "TeamsGuestCallingConfiguration", "TeamsGuestMeetingConfiguration", "TeamsGuestMessagingConfiguration", "TeamsIPPhonePolicy", "TeamsMeetingBroadcastConfiguration", "TeamsMeetingBroadcastPolicy", "TeamsMeetingConfiguration", "TeamsMeetingPolicy", "TeamsMessagingPolicy", "TeamsMobilityPolicy", "TeamsNetworkRoamingPolicy", "TeamsOnlineVoicemailPolicy", "TeamsOnlineVoicemailUserSettings", "TeamsOnlineVoiceUser", "TeamsOrgWideAppSettings", "TeamsPstnUsage", "TeamsShiftsPolicy", "TeamsTeam", "TeamsTemplatesPolicy", "TeamsTenantDialPlan", "TeamsTenantNetworkRegion", "TeamsTenantNetworkSite", "TeamsTenantNetworkSubnet", "TeamsTenantTrustedIPAddress", "TeamsTranslationRule", "TeamsUnassignedNumberTreatment", "TeamsUpdateManagementPolicy", "TeamsUpgradeConfiguration", "TeamsUpgradePolicy", "TeamsUser", "TeamsUserCallingSettings", "TeamsUserPolicyAssignment", "TeamsVdiPolicy", "TeamsVoiceRoute", "TeamsVoiceRoutingPolicy", "TeamsWorkloadPolicy")
}

$SelectedComponents = if ($Workload -and $WorkloadComponents.ContainsKey($Workload)) {
    $WorkloadComponents[$Workload]
} else {
    $WorkloadComponents.Values | ForEach-Object { $_ }
}

Export-M365DSCConfiguration -Components $SelectedComponents -ApplicationId $WorkloadClientId -CertificateThumbprint $WorkloadThumbprint -TenantId $TenantName -Path $PathDrift

New-M365DSCDeltaReport -Source "$PathCurrent\M365TenantConfig.ps1" -Destination "$PathDrift\M365TenantConfig.ps1" -OutputPath "$PathReport\$TenantName-DriftReport-M365-$Workload.html"
New-M365DSCDeltaReport -Source "$PathCurrent\M365TenantConfig.ps1" -Destination "$PathDrift\M365TenantConfig.ps1" -Type JSON -OutputPath "$PathReport\$TenantName-DriftReport-M365-$Workload.json"


$content = Get-Content -Path "$PathReport\$TenantName-DriftReport-M365-$Workload.html" -Raw

$regexPattern = "<h1>Delta Report</h1>.*?</div>" 

# Use [regex]::Match to find the first match of the <div style='width:100%;text-align:center;'>.*?</div> block
$match = [regex]::Match($content, $regexPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
$updatedContent = $content.Replace($match.Value, "")

Set-Content -Path "$PathReport\$TenantName-DriftReport-M365-$Workload.html" -Value $updatedContent -Encoding UTF8

# Wait for 30 seconds to allow policy replication
Start-Sleep -Seconds 5

# Read the content of the HTML report
$htmlReport = Get-Content -Path "$PathReport\$TenantName-DriftReport-M365-$Workload.html" -Raw

$htmlContent = @"
<h2>Microsoft 365 drift detection report from Rubicon Cloud Advisor</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" hight="10%" alt="Banner Image" class="banner">
<h4>Organization Domain: $TenantName</h4>
<p>This email reports changes in the Microsoft 365 Tenant configuration.</p>
$htmlReport
"@



# Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
$params = @{
	message = @{
		subject = "$Customer | Drift Detection M365: $Workload"
		body = @{
			contentType = "HTML"
			content = $htmlContent
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



# Send the email
Write-Verbose "Sending email with the Secure Score report"
Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

# Disconnect from Microsoft Graph for email operations
# Disconnect-MgGraph

Write-Verbose "Email sent successfully"