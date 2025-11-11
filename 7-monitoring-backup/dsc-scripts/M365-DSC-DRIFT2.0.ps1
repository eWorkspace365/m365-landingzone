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
    "EntraID" = @("AADAccessReviewDefinition", "AADAccessReviewPolicy", "AADActivityBasedTimeoutPolicy", "AADAdminConsentRequestPolicy", "AADAdministrativeUnit", "AADAgreement", "AADAppManagementPolicy", "AADApplication", "AADAttributeSet", "AADAuthenticationContextClassReference", "AADAuthenticationFlowPolicy", "AADAuthenticationMethodPolicy", "AADAuthenticationMethodPolicyAuthenticator", "AADAuthenticationMethodPolicyEmail", "AADAuthenticationMethodPolicyExternal", "AADAuthenticationMethodPolicyFido2", "AADAuthenticationMethodPolicyHardware", "AADAuthenticationMethodPolicyQRCodeImage", "AADAuthenticationMethodPolicySms", "AADAuthenticationMethodPolicySoftware", "AADAuthenticationMethodPolicyTemporary", "AADAuthenticationMethodPolicyVoice", "AADAuthenticationMethodPolicyX509", "AADAuthenticationRequirement", "AADAuthenticationStrengthPolicy", "AADAuthorizationPolicy", "AADB2CAuthenticationMethodsPolicy", "AADClaimsMappingPolicy", "AADConditionalAccessPolicy", "AADConnectorGroupApplicationProxy", "AADCrossTenantAccessPolicy", "AADCrossTenantAccessPolicyConfigurationDefault", "AADCrossTenantAccessPolicyConfigurationPartner", "AADCrossTenantIdentitySyncPolicyPartner", "AADCustomAuthenticationExtension", "AADCustomSecurityAttributeDefinition", "AADDeviceRegistrationPolicy", "AADDomain", "AADEntitlementManagementAccessPackage", "AADEntitlementManagementAccessPackageAssignmentPolicy", "AADEntitlementManagementAccessPackageCatalog", "AADEntitlementManagementAccessPackageCatalogResource", "AADEntitlementManagementConnectedOrganization", "AADEntitlementManagementRoleAssignment", "AADEntitlementManagementSettings", "AADExternalIdentityPolicy", "AADFeatureRolloutPolicy", "AADFederationConfiguration", "AADFilteringPolicy", "AADFilteringPolicyRule", "AADFilteringProfile", "AADGroup", "AADGroupEligibilitySchedule", "AADGroupEligibilityScheduleSettings", "AADGroupLifecyclePolicy", "AADGroupsNamingPolicy", "AADGroupsSettings", "AADHomeRealmDiscoveryPolicy", "AADIdentityAPIConnector", "AADIdentityB2XUserFlow", "AADIdentityGovernanceLifecycleWorkflow", "AADIdentityGovernanceLifecycleWorkflowCustomTaskExtension", "AADIdentityGovernanceProgram", "AADIdentityProtectionPolicySettings", "AADLifecycleWorkflowSettings", "AADMultiTenantOrganizationIdentitySyncPolicyTemplate", "AADNamedLocationPolicy", "AADNetworkAccessForwardingPolicy", "AADNetworkAccessForwardingProfile", "AADNetworkAccessSettingConditionalAccess", "AADNetworkAccessSettingCrossTenantAccess", "AADOnPremisesPublishingProfilesSettings", "AADOrganizationCertificateBasedAuthConfiguration", "AADPIMGroupSetting", "AADPasswordRuleSettings", "AADRemoteNetwork", "AADRoleAssignmentScheduleRequest", "AADRoleDefinition", "AADRoleEligibilityScheduleRequest", "AADRoleManagementPolicyRule", "AADRoleSetting", "AADSecurityDefaults", "AADServicePrincipal", "AADSocialIdentityProvider", "AADTenantAppManagementPolicy", "AADTenantDetails", "AADTokenIssuancePolicy", "AADTokenLifetimePolicy", "AADUser", "AADUserFlowAttribute", "AADVerifiedIdAuthority", "AADVerifiedIdAuthorityContract", "ADOOrganizationOwner", "ADOPermissionGroup", "ADOPermissionGroupSettings", "ADOSecurityPolicy", "AzureBillingAccountPolicy", "AzureBillingAccountScheduledAction", "AzureBillingAccountsAssociatedTenant", "AzureBillingAccountsRoleAssignment", "AzureDiagnosticSettings", "AzureDiagnosticSettingsCustomSecurityAttribute", "AzureSubscription", "AzureVerifiedIdFaceCheck", "CommerceSelfServicePurchase", "FabricAdminTenantSettings", "M365DSCGraphAPIRuleEvaluation", "M365DSCRuleEvaluation")
	
    "Exchange" = @("EXOATPBuiltInProtectionRule", "EXOAcceptedDomain", "EXOActiveSyncDeviceAccessRule", "EXOActiveSyncMailboxPolicy", "EXOAddressBookPolicy", "EXOAddressList", "EXOAntiPhishPolicy", "EXOAntiPhishRule", "EXOApplicationAccessPolicy", "EXOArcConfig", "EXOAtpPolicyForO365", "EXOAtpProtectionPolicyRule", "EXOAuthenticationPolicy", "EXOAuthenticationPolicyAssignment", "EXOAvailabilityAddressSpace", "EXOAvailabilityConfig", "EXOCASMailboxPlan", "EXOCASMailboxSettings", "EXOCalendarProcessing", "EXODataAtRestEncryptionPolicy", "EXODataAtRestEncryptionPolicyAssignment", "EXODataClassification", "EXODataEncryptionPolicy", "EXODistributionGroup", "EXODkimSigningConfig", "EXODnssecForVerifiedDomain", "EXOEOPProtectionPolicyRule", "EXOEmailAddressPolicy", "EXOEmailTenantSettings", "EXOExternalInOutlook", "EXOFocusedInbox", "EXOGlobalAddressList", "EXOGroupSettings", "EXOHostedConnectionFilterPolicy", "EXOHostedContentFilterPolicy", "EXOHostedContentFilterRule", "EXOHostedOutboundSpamFilterPolicy", "EXOHostedOutboundSpamFilterRule", "EXOIRMConfiguration", "EXOInboundConnector", "EXOIntraOrganizationConnector", "EXOJournalRule", "EXOMailContact", "EXOMailboxAuditBypassAssociation", "EXOMailboxAutoReplyConfiguration", "EXOMailboxCalendarConfiguration", "EXOMailboxCalendarFolder", "EXOMailboxFolderPermission", "EXOMailboxIRMAccess", "EXOMailboxPermission", "EXOMailboxPlan", "EXOMailboxSettings", "EXOMalwareFilterPolicy", "EXOMalwareFilterRule", "EXOManagementRole", "EXOManagementRoleAssignment", "EXOManagementRoleEntry", "EXOManagementScope", "EXOMessageClassification", "EXOMigration", "EXOMigrationEndpoint", "EXOMobileDeviceMailboxPolicy", "EXOOMEConfiguration", "EXOOfflineAddressBook", "EXOOnPremisesOrganization", "EXOOrganizationConfig", "EXOOrganizationRelationship", "EXOOutboundConnector", "EXOOwaMailboxPolicy", "EXOPartnerApplication", "EXOPerimeterConfiguration", "EXOPhishSimOverrideRule", "EXOPlace", "EXOPolicyTipConfig", "EXOQuarantinePolicy", "EXORecipientPermission", "EXORemoteDomain", "EXOReportSubmissionPolicy", "EXOReportSubmissionRule", "EXOResourceConfiguration", "EXORetentionPolicy", "EXORetentionPolicyTag", "EXORoleAssignmentPolicy", "EXORoleGroup", "EXOSafeAttachmentPolicy", "EXOSafeAttachmentRule", "EXOSafeLinksPolicy", "EXOSafeLinksRule", "EXOSecOpsOverrideRule", "EXOServicePrincipal", "EXOSharedMailbox", "EXOSharingPolicy", "EXOSmtpDaneInbound", "EXOSweepRule", "EXOTeamsProtectionPolicy", "EXOTenantAllowBlockListItems", "EXOTenantAllowBlockListSpoofItems", "EXOTransportConfig", "EXOTransportRule")
	
    "Intune" = @("IntuneAccountProtectionLocalAdministratorPasswordSolutionPolicy", "IntuneAccountProtectionLocalUserGroupMembershipPolicy", "IntuneAccountProtectionPolicyWindows10", "IntuneAndroidManagedStoreAppConfiguration", "IntuneAntivirusExclusionsPolicyLinux", "IntuneAntivirusExclusionsPolicyMacOS", "IntuneAntivirusPolicyLinux", "IntuneAntivirusPolicyMacOS", "IntuneAntivirusPolicySecurityExperienceWindows10ConfigMgr", "IntuneAntivirusPolicyWindows10ConfigMgr", "IntuneAntivirusPolicyWindows10SettingCatalog", "IntuneAppAndBrowserIsolationPolicyWindows10", "IntuneAppAndBrowserIsolationPolicyWindows10ConfigMgr", "IntuneAppCategory", "IntuneAppConfigurationDevicePolicy", "IntuneAppConfigurationPolicy", "IntuneAppControlForBusinessPolicyWindows10", "IntuneAppProtectionPolicyAndroid", "IntuneAppProtectionPolicyiOS", "IntuneAppleMDMPushNotificationCertificate", "IntuneApplicationControlPolicyWindows10", "IntuneAttackSurfaceReductionRulesPolicyWindows10ConfigManager", "IntuneAzureNetworkConnectionWindows365", "IntuneCloudProvisioningPolicyWindows365", "IntuneDefenderGlobalExclusionsPolicyLinux", "IntuneDerivedCredential", "IntuneDeviceAndAppManagementAssignmentFilter", "IntuneDeviceCategory", "IntuneDeviceCleanupRuleV2", "IntuneDeviceComplianceNotificationMessageTemplate", "IntuneDeviceCompliancePolicyAndroidDeviceOwner", "IntuneDeviceCompliancePolicyAndroidWorkProfile", "IntuneDeviceCompliancePolicyMacOS", "IntuneDeviceCompliancePolicyWindows10", "IntuneDeviceCompliancePolicyiOs", "IntuneDeviceComplianceScriptLinux", "IntuneDeviceComplianceScriptWindows10", "IntuneDeviceConfigurationAdministrativeTemplatePolicyWindows10", "IntuneDeviceConfigurationCustomPolicyWindows10", "IntuneDeviceConfigurationCustomPolicyiOS", "IntuneDeviceConfigurationDefenderForEndpointOnboardingPolicyWindows10", "IntuneDeviceConfigurationDeliveryOptimizationPolicyWindows10", "IntuneDeviceConfigurationDeliveryOptimizationPolicyWindows10V2", "IntuneDeviceConfigurationDomainJoinPolicyWindows10", "IntuneDeviceConfigurationEmailProfilePolicyWindows10", "IntuneDeviceConfigurationEndpointProtectionPolicyWindows10", "IntuneDeviceConfigurationFirmwareInterfacePolicyWindows10", "IntuneDeviceConfigurationHealthMonitoringConfigurationPolicyWindows10", "IntuneDeviceConfigurationIdentityProtectionPolicyWindows10", "IntuneDeviceConfigurationImportedPfxCertificatePolicyWindows10", "IntuneDeviceConfigurationKioskPolicyWindows10", "IntuneDeviceConfigurationNetworkBoundaryPolicyWindows10", "IntuneDeviceConfigurationPkcsCertificatePolicyWindows10", "IntuneDeviceConfigurationPlatformScriptMacOS", "IntuneDeviceConfigurationPlatformScriptWindows", "IntuneDeviceConfigurationPolicyAndroidDeviceOwner", "IntuneDeviceConfigurationPolicyAndroidOpenSourceProject", "IntuneDeviceConfigurationPolicyAndroidWorkProfile", "IntuneDeviceConfigurationPolicyMacOS", "IntuneDeviceConfigurationPolicyWindows10", "IntuneDeviceConfigurationPolicyiOS", "IntuneDeviceConfigurationSCEPCertificatePolicyWindows10", "IntuneDeviceConfigurationSecureAssessmentPolicyWindows10", "IntuneDeviceConfigurationSharedMultiDevicePolicyWindows10", "IntuneDeviceConfigurationTrustedCertificatePolicyWindows10", "IntuneDeviceConfigurationVpnPolicyWindows10", "IntuneDeviceConfigurationWindowsTeamPolicyWindows10", "IntuneDeviceConfigurationWiredNetworkPolicyWindows10", "IntuneDeviceControlPolicyWindows10", "IntuneDeviceEnrollmentLimitRestriction", "IntuneDeviceEnrollmentPlatformRestriction", "IntuneDeviceEnrollmentStatusPageWindows10", "IntuneDeviceFeaturesConfigurationPolicyIOS", "IntuneDeviceManagementAndroidDeviceOwnerEnrollmentProfile", "IntuneDeviceManagementComplianceSettings", "IntuneDeviceManagementEnrollmentAndroidGooglePlay", "IntuneDeviceRemediation", "IntuneDiskEncryptionMacOS", "IntuneDiskEncryptionPDEPolicyWindows10", "IntuneDiskEncryptionWindows10", "IntuneEndpointDetectionAndResponsePolicyLinux", "IntuneEndpointDetectionAndResponsePolicyMacOS", "IntuneEndpointDetectionAndResponsePolicyWindows10", "IntuneEpmElevationRulesPolicyWindows10", "IntuneEpmElevationSettingsPolicyWindows10", "IntuneExploitProtectionPolicyWindows10SettingCatalog", "IntuneFirewallPolicyWindows10", "IntuneFirewallRulesHyperVPolicyWindows10", "IntuneFirewallRulesPolicyWindows10", "IntuneFirewallRulesPolicyWindows10ConfigMgr", "IntuneMobileAppsBuiltInStoreApp", "IntuneMobileAppsBundleMacOS", "IntuneMobileAppsDefenderForEndpointMacOS", "IntuneMobileAppsLobAppAndroid", "IntuneMobileAppsLobAppMsiWindows10", "IntuneMobileAppsLobAppWindows10", "IntuneMobileAppsLobAppiOS", "IntuneMobileAppsMacOSLobApp", "IntuneMobileAppsManagedGooglePlayApp", "IntuneMobileAppsMicrosoft365SuiteMacOS", "IntuneMobileAppsMicrosoftEdge", "IntuneMobileAppsMicrosoftStoreAppWindows10", "IntuneMobileAppsStoreApp", "IntuneMobileAppsSystemAppAndroid", "IntuneMobileAppsWebLink", "IntuneMobileAppsWin32AppWindows10", "IntuneMobileAppsWindowsOfficeSuiteApp", "IntuneMobileThreatDefenseConnector", "IntunePolicySets", "IntuneRoleAssignment", "IntuneRoleDefinition", "IntuneRoleScopeTag", "IntuneSecurityBaselineDefenderForEndpoint", "IntuneSecurityBaselineHoloLens2Advanced", "IntuneSecurityBaselineHoloLens2Standard", "IntuneSecurityBaselineMicrosoft365AppsForEnterprise", "IntuneSecurityBaselineMicrosoftEdge", "IntuneSecurityBaselineWindows10", "IntuneSecurityBaselineWindows365", "IntuneSettingCatalogASRRulesPolicyWindows10", "IntuneSettingCatalogCustomPolicyWindows10", "IntuneTrustedRootCertificateAndroidDeviceOwner", "IntuneTrustedRootCertificateAndroidWork", "IntuneTrustedRootCertificateIOS", "IntuneUserSettingsPolicyWindows365", "IntuneVPNConfigurationPolicyAndroidDeviceOwner", "IntuneVPNConfigurationPolicyAndroidWork", "IntuneVPNConfigurationPolicyIOS", "IntuneWifiConfigurationPolicyAndroidEnterpriseDeviceOwner", "IntuneWifiConfigurationPolicyAndroidEnterpriseWorkProfile", "IntuneWifiConfigurationPolicyAndroidForWork", "IntuneWifiConfigurationPolicyAndroidOpenSourceProject", "IntuneWifiConfigurationPolicyIOS", "IntuneWifiConfigurationPolicyMacOS", "IntuneWifiConfigurationPolicyWindows10", "IntuneWindowsAutopilotDeploymentProfileAzureADHybridJoined", "IntuneWindowsAutopilotDeploymentProfileAzureADJoined", "IntuneWindowsBackupForOrganizationConfiguration", "IntuneWindowsHelloForBusinessGlobalPolicy", "IntuneWindowsInformationProtectionPolicyWindows10MdmEnrolled")
	
    "SharePoint" = @("O365AdminAuditLogConfig", "O365ExternalConnection", "O365Group", "O365OrgCustomizationSetting", "O365OrgSettings", "O365SearchAndIntelligenceConfigurations", "ODSettings", "SHSpaceGroup", "SHSpaceUser", "SPOAccessControlSettings", "SPOApp", "SPOBrowserIdleSignout", "SPOHomeSite", "SPOHubSite", "SPOOrgAssetsLibrary", "SPOPropertyBag", "SPORetentionLabelsSettings", "SPOSearchManagedProperty", "SPOSearchResultSource", "SPOSharingSettings", "SPOSite", "SPOSiteAuditSettings", "SPOSiteDesign", "SPOSiteDesignRights", "SPOSiteGroup", "SPOSiteScript", "SPOStorageEntity", "SPOTenantCdnEnabled", "SPOTenantCdnPolicy", "SPOTenantSettings", "SPOTheme", "SPOUserProfileProperty")
	
    "Compliance" = @("SCAuditConfigurationPolicy", "SCAutoSensitivityLabelPolicy", "SCAutoSensitivityLabelRule", "SCCaseHoldPolicy", "SCCaseHoldRule", "SCComplianceCase", "SCComplianceSearch", "SCComplianceSearchAction", "SCComplianceTag", "SCDLPCompliancePolicy", "SCDLPComplianceRule", "SCDeviceConditionalAccessPolicy", "SCDeviceConditionalAccessRule", "SCDeviceConfigurationPolicy", "SCDeviceConfigurationRule", "SCFilePlanPropertyAuthority", "SCFilePlanPropertyCategory", "SCFilePlanPropertyCitation", "SCFilePlanPropertyDepartment", "SCFilePlanPropertyReferenceId", "SCFilePlanPropertySubCategory", "SCInsiderRiskEntityList", "SCInsiderRiskPolicy", "SCLabelPolicy", "SCPolicyConfig", "SCProtectionAlert", "SCRecordReviewNotificationTemplateConfig", "SCRetentionCompliancePolicy", "SCRetentionComplianceRule", "SCRetentionEventType", "SCRoleGroup", "SCRoleGroupMember", "SCSecurityFilter", "SCSensitivityLabel", "SCSupervisoryReviewPolicy", "SCSupervisoryReviewRule", "SCUnifiedAuditLogRetentionPolicy")
	
    "Teams" = @("PlannerBucket", "PlannerPlan", "PlannerTask", "TeamsAppPermissionPolicy", "TeamsAppSetupPolicy", "TeamsApplicationInstance", "TeamsAudioConferencingPolicy", "TeamsCallHoldPolicy", "TeamsCallParkPolicy", "TeamsCallQueue", "TeamsCallingPolicy", "TeamsChannel", "TeamsChannelTab", "TeamsChannelsPolicy", "TeamsClientConfiguration", "TeamsComplianceRecordingPolicy", "TeamsCortanaPolicy", "TeamsDialInConferencingTenantSettings", "TeamsEmergencyCallRoutingPolicy", "TeamsEmergencyCallingPolicy", "TeamsEnhancedEncryptionPolicy", "TeamsEventsPolicy", "TeamsFederationConfiguration", "TeamsFeedbackPolicy", "TeamsFilesPolicy", "TeamsGroupPolicyAssignment", "TeamsGuestCallingConfiguration", "TeamsGuestMeetingConfiguration", "TeamsGuestMessagingConfiguration", "TeamsIPPhonePolicy", "TeamsM365App", "TeamsMeetingBroadcastConfiguration", "TeamsMeetingBroadcastPolicy", "TeamsMeetingConfiguration", "TeamsMeetingPolicy", "TeamsMessagingConfiguration", "TeamsMessagingPolicy", "TeamsMobilityPolicy", "TeamsNetworkRoamingPolicy", "TeamsOnlineVoiceUser", "TeamsOnlineVoicemailPolicy", "TeamsOnlineVoicemailUserSettings", "TeamsOrgWideAppSettings", "TeamsPstnUsage", "TeamsShiftsPolicy", "TeamsTeam", "TeamsTemplatesPolicy", "TeamsTenantDialPlan", "TeamsTenantNetworkRegion", "TeamsTenantNetworkSite", "TeamsTenantNetworkSubnet", "TeamsTenantTrustedIPAddress", "TeamsTranslationRule", "TeamsUnassignedNumberTreatment", "TeamsUpdateManagementPolicy", "TeamsUpgradeConfiguration", "TeamsUpgradePolicy", "TeamsUser", "TeamsUserCallingSettings", "TeamsUserPolicyAssignment", "TeamsVdiPolicy", "TeamsVoiceRoute", "TeamsVoiceRoutingPolicy", "TeamsWorkloadPolicy", "VivaEngagementRoleMember")
}

$SelectedComponents = if ($Workload -and $WorkloadComponents.ContainsKey($Workload)) {
    $WorkloadComponents[$Workload]
} else {
    $WorkloadComponents.Values | ForEach-Object { $_ }
}

Export-M365DSCConfiguration -Components $SelectedComponents -ApplicationId $WorkloadClientId -CertificateThumbprint $WorkloadThumbprint -TenantId $TenantName -Path $PathDrift

New-M365DSCDeltaReport -Source "$PathCurrent\M365TenantConfig.ps1" -Destination "$PathDrift\M365TenantConfig.ps1" -OutputPath "$PathReport\$TenantName-DeltaReport-M365-$Workload.html"
New-M365DSCDeltaReport -Source "$PathCurrent\M365TenantConfig.ps1" -Destination "$PathDrift\M365TenantConfig.ps1" -Type JSON -OutputPath "$PathReport\$TenantName-DriftReport-M365-$Workload.json"


# Build Custom HTML report
$JsonPath = "$PathReport\$TenantName-DriftReport-M365-$Workload.json"
$OutputPath = "$PathReport\$TenantName-DriftReport-M365-$Workload.html"
$Title = "Microsoft 365 drift detection report from Rubicon Cloud Advisor"

# ----------------- Validatie & setup -----------------

if (-not (Test-Path -Path $JsonPath)) {
    throw "JSON file not found: $JsonPath"
}

if (-not $OutputPath) {
    $baseName   = [System.IO.Path]::GetFileNameWithoutExtension($JsonPath)
    $directory  = [System.IO.Path]::GetDirectoryName($JsonPath)
    $OutputPath = Join-Path $directory "$baseName-report.html"
}

# Voor HTML-encoding
Add-Type -AssemblyName System.Web

# ----------------- Helpers -----------------

function Get-DriftStatus {
    param(
        [array]$Properties
    )

    $status = "Modified"

    if ($Properties) {
        foreach ($p in $Properties) {
            $src = $p.ValueInSource
            $dst = $p.ValueInDestination

            $srcStr = [string]$src
            $dstStr = [string]$dst

            if ($srcStr -eq "Absent" -and $dstStr -ne "Absent") {
                return "Added"
            }
            elseif ($dstStr -eq "Absent" -and $srcStr -ne "Absent") {
                return "Removed"
            }
        }
    }

    return $status
}

function Get-CleanJsonText {
    param(
        $Value
    )

    if ($null -eq $Value) {
        return ""
    }

    $json = $Value | ConvertTo-Json -Depth 10

    # Strip { en } en lege regels weghalen
    $noBraces = $json -replace '[{}]', ''
    $lines = $noBraces -split "`r?`n" |
        ForEach-Object { $_.TrimEnd() } |
        Where-Object { $_.Trim() -ne '' }

    return ($lines -join "`r`n")
}

function Build-PropertiesHtml {
    param(
        [array]$Properties
    )

    if (-not $Properties -or $Properties.Count -eq 0) {
        return "<em>No property differences</em>"
    }

    $blocks = @()

    foreach ($prop in $Properties) {
        $paramName    = [string]$prop.ParameterName
        $paramNameEnc = [System.Web.HttpUtility]::HtmlEncode($paramName)

        $srcText = Get-CleanJsonText $prop.ValueInSource
        $dstText = Get-CleanJsonText $prop.ValueInDestination

        $srcHtml = [System.Web.HttpUtility]::HtmlEncode($srcText)
        $dstHtml = [System.Web.HttpUtility]::HtmlEncode($dstText)

        $blocks += @"
<div class='prop-block'>
  <table class='prop-table'>
    <tr>
      <th class='prop-title' colspan='2'>$paramNameEnc</th>
    </tr>
    <tr>
      <th class='prop-colhead'>ValueInSource</th>
      <th class='prop-colhead'>ValueInDestination</th>
    </tr>
    <tr>
      <td><pre class='json-block'>$srcHtml</pre></td>
      <td><pre class='json-block'>$dstHtml</pre></td>
    </tr>
  </table>
</div>
"@
    }

    return ($blocks -join "<hr class='prop-separator' />")
}

# ----------------- JSON inlezen -----------------

$jsonRaw = Get-Content -Path $JsonPath -Raw
$items   = $jsonRaw | ConvertFrom-Json

if ($items -isnot [System.Collections.IEnumerable] -or $items -is [string]) {
    $items = @($items)
}

$rows = foreach ($item in $items) {
    $status    = Get-DriftStatus -Properties $item.Properties
    $propsHtml = Build-PropertiesHtml -Properties $item.Properties

    [PSCustomObject]@{
        ResourceName         = [string]$item.ResourceName
        ResourceInstanceName = [string]$item.ResourceInstanceName
        Status               = $status
        PropertiesHtml       = $propsHtml
    }
}

$total     = $rows.Count
$added     = ($rows | Where-Object { $_.Status -eq "Added" }).Count
$removed   = ($rows | Where-Object { $_.Status -eq "Removed" }).Count
$modified  = ($rows | Where-Object { $_.Status -eq "Modified" }).Count
$generated = Get-Date

# ----------------- HTML opbouwen -----------------

$rowsHtml = foreach ($r in $rows) {
    $resName = [System.Web.HttpUtility]::HtmlEncode($r.ResourceName)
    $resInst = [System.Web.HttpUtility]::HtmlEncode($r.ResourceInstanceName)
    $status  = [System.Web.HttpUtility]::HtmlEncode($r.Status)

    $icon = switch ($r.Status) {
        "Added"    { "&#x2795;" }   # plus
        "Removed"  { "&#x2796;" }   # minus
        "Modified" { "&#x270E;" }   # pencil
        default    { "&#x270E;" }
    }

@"
<tr>
    <td>$resName</td>
    <td>$resInst</td>
    <td><span class='status-badge status-$($r.Status.ToLower())'>$icon $status</span></td>
    <td>$($r.PropertiesHtml)</td>
</tr>
"@
}

$rowsHtmlJoined = $rowsHtml -join "`r`n"

$html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='utf-8' />
    <title>$Title</title>
    <style>
        body {
            font-family: Consolas, 'Fira Code', 'Segoe UI', monospace;
            background-color: #0b1120;
            color: #e5e7eb;
            margin: 0;
            padding: 2rem;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
        }

        .banner {
            display: flex;
            align-items: center;
            gap: 1.25rem;
            padding: 1rem 1.25rem;
            border-radius: 1rem;
            background: linear-gradient(90deg, #1d4ed8, #38bdf8);
            box-shadow: 0 18px 60px rgba(0,0,0,.65);
            margin-bottom: 1.5rem;
        }

        .banner-image-wrapper {
            flex: 0 0 auto;
        }

		.banner-img {
			height: 52px;              /* vaste hoogte, mooi compact */
			width: auto;               /* breedte schaalt mee met verhouding */
			max-width: 120px;          /* voorkomt extreem brede logo's */
			border-radius: 0.75rem;
			object-fit: contain;       /* hele logo zichtbaar, niet afgesneden */
			border: 2px solid rgba(15,23,42,.85);
			background-color: #ffffff;
			padding: 12px;              /* wat lucht rondom het logo */
		}

        .banner-text {
            flex: 1 1 auto;
            min-width: 0;
        }

        .banner-text h1 {
            margin: 0;
            font-size: 1.6rem;
            line-height: 1.25;
        }

        .banner-subtitle {
            margin: .25rem 0 0;
            font-size: .9rem;
            color: #e5e7eb;
            opacity: .95;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: .85rem;
            background-color: #020617;
            border-radius: .75rem;
            overflow: hidden;
        }

        thead {
            background-color: #020617;
        }

        thead th {
            padding: .6rem .7rem;
            text-align: left;
            border-bottom: 1px solid #1f2937;
            white-space: nowrap;
        }

        tbody tr:nth-child(odd)  { background-color: #020617; }
        tbody tr:nth-child(even) { background-color: #020617; }

        tbody td {
            padding: .5rem .7rem;
            vertical-align: top;
            border-bottom: 1px solid #111827;
        }

        td:nth-child(1) { width: 15%; }
        td:nth-child(2) { width: 25%; }
        td:nth-child(3) { width: 10%; }
        td:nth-child(4) { width: 50%; }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: .25rem;
            padding: .1rem .45rem;
            border-radius: 999px;
            font-size: .7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: .06em;
            border: 1px solid transparent;
        }

        .status-added {
            color: #16a34a;
            border-color: rgba(34,197,94,.4);
            background: rgba(22,163,74,.15);
        }

        .status-removed {
            color: #b91c1c;
            border-color: rgba(248,113,113,.4);
            background: rgba(185,28,28,.15);
        }

        .status-modified {
            color: #d97706;
            border-color: rgba(245,158,11,.4);
            background: rgba(217,119,6,.15);
        }

        .prop-block {
            margin-bottom: .5rem;
        }

        .prop-table {
            width: 100%;
            border-collapse: collapse;
            border: 1px solid #1f2937;
            table-layout: fixed;
        }

        .prop-table th,
        .prop-table td {
            border: 1px solid #1f2937;
            padding: .25rem .35rem;
            vertical-align: top;
            word-wrap: break-word;
            overflow-wrap: anywhere;
        }

        .prop-title {
            background-color: #111827;
            text-align: left;
            font-weight: 700;
        }

        .prop-colhead {
            background-color: #020617;
            font-weight: 600;
            text-align: left;
        }

        .json-block {
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow-wrap: anywhere;
        }

        .prop-separator {
            border: 0;
            border-top: 1px dashed #1f2937;
            margin: .4rem 0;
        }
    </style>
</head>
<body>
    <div class='container'>
        <div class='banner'>
            <div class='banner-image-wrapper'>
                <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU"
                     alt="Microsoft 365 Drift Detection"
                     class="banner-img" />
            </div>
            <div class='banner-text'>
                <h1>$Title</h1>
                <p class='banner-subtitle'>
                    Generated on $generated | Total: $total | Added: $added | Removed: $removed | Modified: $modified
                </p>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>ResourceName</th>
                    <th>ResourceInstanceName</th>
                    <th>Status</th>
                    <th>Properties (ParameterName / ValueInSource / ValueInDestination)</th>
                </tr>
            </thead>
            <tbody>
                $rowsHtmlJoined
            </tbody>
        </table>
    </div>
</body>
</html>
"@

# ----------------- Schrijven & openen -----------------

$html | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host "Drift report generated:" -ForegroundColor Green
Write-Host " $OutputPath"

# Read the content of the HTML report
$htmlReport = Get-Content -Path "$PathReport\$TenantName-DriftReport-M365-$Workload.html" -Raw

$htmlContent = @"
<h2></h2>
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