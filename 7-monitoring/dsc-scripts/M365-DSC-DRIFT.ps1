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
    [String]$TenantID,
    
    [Parameter(Mandatory=$false)]
    [String]$ApplicationID,
    
    [Parameter(Mandatory=$false)]
    [String]$CertificateThumbprint,
    
    [Parameter(Mandatory=$false)]
    [String]$MailAppID,
    
    [Parameter(Mandatory=$false)]
    [String]$MailAppSecret,
    
    [Parameter(Mandatory=$false)]
    [String]$Workload
)

# Define workload components
$WorkloadComponents = @{
    "EntraID"      = @("AADAdministrativeUnit", "AADApplication", "AADAttributeSet", "AADAuthenticationContextClassReference", "AADAuthenticationMethodPolicy", "AADAuthenticationMethodPolicyAuthenticator", "AADAuthenticationMethodPolicyEmail", "AADAuthenticationMethodPolicyFido2", "AADAuthenticationMethodPolicySms", "AADAuthenticationMethodPolicySoftware", "AADAuthenticationMethodPolicyTemporary", "AADAuthenticationMethodPolicyVoice", "AADAuthenticationMethodPolicyX509", "AADAuthenticationStrengthPolicy", "AADAuthorizationPolicy", "AADConditionalAccessPolicy", "AADCrossTenantAccessPolicy", "AADCrossTenantAccessPolicyConfigurationDefault", "AADCrossTenantAccessPolicyConfigurationPartner", "AADExternalIdentityPolicy", "AADGroup", "AADGroupLifecyclePolicy", "AADNamedLocationPolicy", "AADSecurityDefaults", "AADSocialIdentityProvider", "AADTenantDetails", "AADTokenLifetimePolicy")
	
    "Exchange" = @("EXOAcceptedDomain", "EXOActiveSyncDeviceAccessRule", "EXOAddressBookPolicy", "EXOAntiPhishPolicy", "EXOAntiPhishRule", "EXOApplicationAccessPolicy", "EXOAtpPolicyForO365", "EXOAuthenticationPolicy", "EXOAuthenticationPolicyAssignment", "EXOAvailabilityAddressSpace", "EXOAvailabilityConfig", "EXOClientAccessRule", "EXODataClassification", "EXODataEncryptionPolicy", "EXODkimSigningConfig", "EXOEmailAddressPolicy","EXOHostedConnectionFilterPolicy", "EXOHostedContentFilterPolicy", "EXOHostedContentFilterRule", "EXOHostedOutboundSpamFilterPolicy", "EXOHostedOutboundSpamFilterRule", "EXOInboundConnector", "EXOIntraOrganizationConnector", "EXOIRMConfiguration", "EXOJournalRule", "EXOMailTips", "EXOMalwareFilterPolicy", "EXOMalwareFilterRule", "EXOMessageClassification", "EXOMobileDeviceMailboxPolicy", "EXOOMEConfiguration", "EXOOnPremisesOrganization", "EXOOrganizationConfig", "EXOOrganizationRelationship", "EXOOutboundConnector", "EXOOwaMailboxPolicy", "EXOPartnerApplication", "EXOPerimeterConfiguration", "EXOPolicyTipConfig", "EXOQuarantinePolicy", "EXORemoteDomain", "EXOReportSubmissionPolicy", "EXOReportSubmissionRule", "EXORoleAssignmentPolicy", "EXORoleGroup", "EXOSafeAttachmentPolicy", "EXOSafeAttachmentRule", "EXOSafeLinksPolicy", "EXOSafeLinksRule",  "EXOSharingPolicy", "EXOTransportConfig", "EXOTransportRule", "O365AdminAuditLogConfig", "O365OrgCustomizationSetting", "O365OrgSettings", "O365SearchAndIntelligenceConfigurations")
	
    "Intune" = @("IntuneAccountProtectionLocalAdministratorPasswordSolutionPolicy", "IntuneAccountProtectionLocalUserGroupMembershipPolicy", "IntuneAccountProtectionPolicy", "IntuneAntivirusPolicyWindows10SettingCatalog", "IntuneAppConfigurationDevicePolicy", "IntuneAppConfigurationPolicy", "IntuneApplicationControlPolicyWindows10", "IntuneAppProtectionPolicyAndroid", "IntuneAppProtectionPolicyiOS", "IntuneASRRulesPolicyWindows10", "IntuneAttackSurfaceReductionRulesPolicyWindows10ConfigManager", "IntuneDeviceAndAppManagementAssignmentFilter", "IntuneDeviceCategory", "IntuneDeviceCleanupRule", "IntuneDeviceCompliancePolicyAndroid", "IntuneDeviceCompliancePolicyAndroidDeviceOwner", "IntuneDeviceCompliancePolicyAndroidWorkProfile", "IntuneDeviceCompliancePolicyiOs", "IntuneDeviceCompliancePolicyMacOS", "IntuneDeviceCompliancePolicyWindows10", "IntuneDeviceConfigurationAdministrativeTemplatePolicyWindows10", "IntuneDeviceConfigurationCustomPolicyWindows10", "IntuneDeviceConfigurationDefenderForEndpointOnboardingPolicyWindows10", "IntuneDeviceConfigurationDeliveryOptimizationPolicyWindows10", "IntuneDeviceConfigurationDomainJoinPolicyWindows10", "IntuneDeviceConfigurationEmailProfilePolicyWindows10", "IntuneDeviceConfigurationEndpointProtectionPolicyWindows10", "IntuneDeviceConfigurationFirmwareInterfacePolicyWindows10", "IntuneDeviceConfigurationHealthMonitoringConfigurationPolicyWindows10", "IntuneDeviceConfigurationIdentityProtectionPolicyWindows10", "IntuneDeviceConfigurationImportedPfxCertificatePolicyWindows10", "IntuneDeviceConfigurationKioskPolicyWindows10", "IntuneDeviceConfigurationNetworkBoundaryPolicyWindows10", "IntuneDeviceConfigurationPkcsCertificatePolicyWindows10", "IntuneDeviceConfigurationPlatformScriptMacOS", "IntuneDeviceConfigurationPlatformScriptWindows", "IntuneDeviceConfigurationPolicyAndroidDeviceAdministrator", "IntuneDeviceConfigurationPolicyAndroidDeviceOwner", "IntuneDeviceConfigurationPolicyAndroidOpenSourceProject", "IntuneDeviceConfigurationPolicyAndroidWorkProfile", "IntuneDeviceConfigurationPolicyiOS", "IntuneDeviceConfigurationPolicyMacOS", "IntuneDeviceConfigurationPolicyWindows10", "IntuneDeviceConfigurationSCEPCertificatePolicyWindows10", "IntuneDeviceConfigurationSecureAssessmentPolicyWindows10", "IntuneDeviceConfigurationSharedMultiDevicePolicyWindows10", "IntuneDeviceConfigurationTrustedCertificatePolicyWindows10", "IntuneDeviceConfigurationVpnPolicyWindows10", "IntuneDeviceConfigurationWindowsTeamPolicyWindows10", "IntuneDeviceConfigurationWiredNetworkPolicyWindows10", "IntuneDeviceEnrollmentLimitRestriction", "IntuneDeviceEnrollmentPlatformRestriction", "IntuneDeviceEnrollmentStatusPageWindows10", "IntuneDeviceRemediation", "IntuneDiskEncryptionMacOS", "IntuneEndpointDetectionAndResponsePolicyWindows10", "IntuneExploitProtectionPolicyWindows10SettingCatalog", "IntunePolicySets", "IntuneRoleAssignment", "IntuneRoleDefinition", "IntuneSettingCatalogASRRulesPolicyWindows10", "IntuneSettingCatalogCustomPolicyWindows10", "IntuneWifiConfigurationPolicyAndroidDeviceAdministrator", "IntuneWifiConfigurationPolicyAndroidEnterpriseDeviceOwner", "IntuneWifiConfigurationPolicyAndroidEnterpriseWorkProfile", "IntuneWifiConfigurationPolicyAndroidForWork", "IntuneWifiConfigurationPolicyAndroidOpenSourceProject", "IntuneWifiConfigurationPolicyIOS", "IntuneWifiConfigurationPolicyMacOS", "IntuneWifiConfigurationPolicyWindows10", "IntuneWindowsAutopilotDeploymentProfileAzureADHybridJoined", "IntuneWindowsAutopilotDeploymentProfileAzureADJoined", "IntuneWindowsInformationProtectionPolicyWindows10MdmEnrolled", "IntuneWindowsUpdateForBusinessDriverUpdateProfileWindows10", "IntuneWindowsUpdateForBusinessFeatureUpdateProfileWindows10", "IntuneWindowsUpdateForBusinessRingUpdateProfileWindows10")
	
    "SharePoint" = @("SPOAccessControlSettings", "SPOApp", "SPOBrowserIdleSignout", "SPOHomeSite", "SPOHubSite", "SPOOrgAssetsLibrary", "SPOSearchManagedProperty", "SPOSearchResultSource", "SPOSharingSettings", "SPOSiteAuditSettings", "SPOSiteDesign", "SPOSiteDesignRights", "SPOSiteScript", "SPOStorageEntity", "SPOTenantCdnEnabled", "SPOTenantCdnPolicy", "SPOTenantSettings", "SPOTheme", "ODSettings")
	
    "Compliance" = @("SCAuditConfigurationPolicy", "SCAutoSensitivityLabelPolicy", "SCAutoSensitivityLabelRule", "SCCaseHoldPolicy", "SCCaseHoldRule", "SCComplianceCase", "SCComplianceSearch", "SCComplianceSearchAction", "SCComplianceTag", "SCDeviceConditionalAccessPolicy", "SCDeviceConfigurationPolicy", "SCDLPCompliancePolicy", "SCDLPComplianceRule", "SCFilePlanPropertyAuthority", "SCFilePlanPropertyCategory", "SCFilePlanPropertyCitation", "SCFilePlanPropertyDepartment", "SCFilePlanPropertyReferenceId", "SCFilePlanPropertySubCategory", "SCLabelPolicy", "SCProtectionAlert", "SCRetentionCompliancePolicy", "SCRetentionComplianceRule", "SCRetentionEventType", "SCRoleGroup", "SCRoleGroupMember", "SCSecurityFilter", "SCSensitivityLabel", "SCSupervisoryReviewPolicy", "SCSupervisoryReviewRule")
	
    "Teams"      = @("TeamsAppPermissionPolicy", "TeamsAppSetupPolicy", "TeamsAudioConferencingPolicy", "TeamsCallHoldPolicy", "TeamsCallingPolicy", "TeamsCallParkPolicy", "TeamsCallQueue", "TeamsChannel", "TeamsChannelsPolicy", "TeamsChannelTab", "TeamsClientConfiguration", "TeamsComplianceRecordingPolicy", "TeamsCortanaPolicy", "TeamsDialInConferencingTenantSettings", "TeamsEmergencyCallingPolicy", "TeamsEmergencyCallRoutingPolicy", "TeamsEnhancedEncryptionPolicy", "TeamsEventsPolicy", "TeamsFederationConfiguration", "TeamsFeedbackPolicy", "TeamsFilesPolicy", "TeamsGroupPolicyAssignment", "TeamsGuestCallingConfiguration", "TeamsGuestMeetingConfiguration", "TeamsGuestMessagingConfiguration", "TeamsIPPhonePolicy", "TeamsMeetingBroadcastConfiguration", "TeamsMeetingBroadcastPolicy", "TeamsMeetingConfiguration", "TeamsMeetingPolicy", "TeamsMessagingPolicy", "TeamsMobilityPolicy", "TeamsNetworkRoamingPolicy", "TeamsOnlineVoicemailPolicy", "TeamsOnlineVoicemailUserSettings", "TeamsOnlineVoiceUser", "TeamsOrgWideAppSettings", "TeamsPstnUsage", "TeamsShiftsPolicy", "TeamsTeam", "TeamsTemplatesPolicy", "TeamsTenantDialPlan", "TeamsTenantNetworkRegion", "TeamsTenantNetworkSite", "TeamsTenantNetworkSubnet", "TeamsTenantTrustedIPAddress", "TeamsTranslationRule", "TeamsUnassignedNumberTreatment", "TeamsUpdateManagementPolicy", "TeamsUpgradeConfiguration", "TeamsUpgradePolicy", "TeamsUser", "TeamsUserCallingSettings", "TeamsUserPolicyAssignment", "TeamsVdiPolicy", "TeamsVoiceRoute", "TeamsVoiceRoutingPolicy", "TeamsWorkloadPolicy")
}

$SelectedComponents = if ($Workload -and $WorkloadComponents.ContainsKey($Workload)) {
    $WorkloadComponents[$Workload]
} else {
    $WorkloadComponents.Values | ForEach-Object { $_ }
}

Export-M365DSCConfiguration -Components $SelectedComponents -ApplicationId $ApplicationID -CertificateThumbprint $CertificateThumbprint -TenantId $TenantName -Path $PathDrift

New-M365DSCDeltaReport -Source "$PathCurrent\M365TenantConfig.ps1" -Destination "$PathDrift\M365TenantConfig.ps1" -OutputPath "$PathReport\$TenantName-DriftReport-M365-$Workload.html"

$MailSender = "rubicon-monitor@$TenantName"
$Attachment = "$PathReport\$TenantName-DriftReport-M365-$Workload.html"
$Recipient = "support@rubicon.nl"

$FileName = (Get-Item -Path $Attachment).name
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Attachment))

$tokenBody = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    Client_Id     = $MailAppID
    Client_Secret = $MailAppSecret
}
$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody
$headers = @{
    "Authorization" = "Bearer $($tokenResponse.access_token)"
    "Content-type"  = "application/json"
}

$URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"
$BodyJsonsend = @"
{
    "message": {
      "subject": "$Customer | Drift Detection M365 - $Workload",
      "body": {
        "contentType": "HTML",
        "content": "This mail is scheduled every day for detecting Microsoft 365 configuration drift. Download the attachment.<br><br>"
      },
      "toRecipients": [
        {
          "emailAddress": {
            "address": "$Recipient"
          }
        }
      ],
      "attachments": [
        {
          "@odata.type": "#microsoft.graph.fileAttachment",
          "name": "$FileName",
          "contentType": "text/plain",
          "contentBytes": "$base64string"
        }
      ]
    },
    "saveToSentItems": "false"
}
"@

Invoke-RestMethod -Method POST -Uri $URLsend -Headers $headers -Body $BodyJsonsend