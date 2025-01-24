[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$Customer,
    
    [Parameter(Mandatory=$false)]
    [String]$PathBaseline,
    
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
    [String]$MailAppSecret
)

Export-M365DSCConfiguration -Components @("AADAdministrativeUnit", "AADApplication", "AADAttributeSet", "AADAuthenticationContextClassReference", "AADAuthenticationMethodPolicy", "AADAuthenticationMethodPolicyAuthenticator", "AADAuthenticationMethodPolicyEmail", "AADAuthenticationMethodPolicyFido2", "AADAuthenticationMethodPolicySms", "AADAuthenticationMethodPolicySoftware", "AADAuthenticationMethodPolicyTemporary", "AADAuthenticationMethodPolicyVoice", "AADAuthenticationMethodPolicyX509", "AADAuthenticationStrengthPolicy", "AADAuthorizationPolicy", "AADConditionalAccessPolicy", "AADCrossTenantAccessPolicy", "AADCrossTenantAccessPolicyConfigurationDefault", "AADCrossTenantAccessPolicyConfigurationPartner", "AADExternalIdentityPolicy", "AADGroup", "AADGroupLifecyclePolicy", "AADNamedLocationPolicy", "AADSecurityDefaults", "AADSocialIdentityProvider", "AADTenantDetails", "AADTokenLifetimePolicy", "EXOAcceptedDomain", "EXOActiveSyncDeviceAccessRule", "EXOAntiPhishPolicy", "EXOAntiPhishRule", "EXOApplicationAccessPolicy", "EXOAtpPolicyForO365", "EXOAuthenticationPolicy", "EXOAuthenticationPolicyAssignment", "EXOAvailabilityAddressSpace", "EXOAvailabilityConfig",  "EXOClientAccessRule", "EXODataEncryptionPolicy", "EXODkimSigningConfig", "EXOEmailAddressPolicy", "EXOHostedConnectionFilterPolicy", "EXOHostedContentFilterPolicy", "EXOHostedContentFilterRule", "EXOHostedOutboundSpamFilterPolicy", "EXOHostedOutboundSpamFilterRule", "EXOInboundConnector", "EXOIntraOrganizationConnector", "EXOIRMConfiguration", "EXOMailTips", "EXOMalwareFilterPolicy", "EXOMalwareFilterRule", "EXOMobileDeviceMailboxPolicy",  "EXOOMEConfiguration", "EXOOnPremisesOrganization", "EXOOrganizationConfig", "EXOOrganizationRelationship", "EXOPartnerApplication", "EXOPerimeterConfiguration", "EXOPlace", "EXOPolicyTipConfig", "EXOQuarantinePolicy", "EXORemoteDomain", "EXOReportSubmissionPolicy", "EXOReportSubmissionRule", "EXORoleAssignmentPolicy", "EXOSafeAttachmentPolicy", "EXOSafeAttachmentRule", "EXOSafeLinksPolicy", "EXOSafeLinksRule", "EXOSharingPolicy", "IntuneAccountProtectionLocalAdministratorPasswordSolutionPolicy", "IntuneAccountProtectionLocalUserGroupMembershipPolicy", "IntuneAccountProtectionPolicy", "IntuneAntivirusPolicyWindows10SettingCatalog", "IntuneAppConfigurationPolicy", "IntuneApplicationControlPolicyWindows10", "IntuneAppProtectionPolicyAndroid", "IntuneAppProtectionPolicyiOS", "IntuneASRRulesPolicyWindows10", "IntuneAttackSurfaceReductionRulesPolicyWindows10ConfigManager", "IntuneDeviceCategory", "IntuneDeviceCleanupRule", "IntuneDeviceCompliancePolicyAndroid", "IntuneDeviceCompliancePolicyAndroidDeviceOwner", "IntuneDeviceCompliancePolicyAndroidWorkProfile", "IntuneDeviceCompliancePolicyiOs", "IntuneDeviceCompliancePolicyMacOS", "IntuneDeviceCompliancePolicyWindows10", "IntuneDeviceConfigurationAdministrativeTemplatePolicyWindows10", "IntuneDeviceConfigurationDefenderForEndpointOnboardingPolicyWindows10", "IntuneDeviceConfigurationEndpointProtectionPolicyWindows10", "IntuneDeviceConfigurationHealthMonitoringConfigurationPolicyWindows10", "IntuneDeviceConfigurationIdentityProtectionPolicyWindows10", "IntuneDeviceConfigurationPolicyAndroidDeviceAdministrator", "IntuneDeviceConfigurationPolicyAndroidDeviceOwner", "IntuneDeviceConfigurationPolicyAndroidOpenSourceProject", "IntuneDeviceConfigurationPolicyAndroidWorkProfile", "IntuneDeviceConfigurationPolicyiOS", "IntuneDeviceConfigurationPolicyMacOS", "IntuneDeviceConfigurationPolicyWindows10", "IntuneDeviceConfigurationSecureAssessmentPolicyWindows10", "IntuneDeviceEnrollmentLimitRestriction", "IntuneDeviceEnrollmentPlatformRestriction","IntuneEndpointDetectionAndResponsePolicyWindows10", "IntuneExploitProtectionPolicyWindows10SettingCatalog", "IntuneSettingCatalogASRRulesPolicyWindows10", "IntuneSettingCatalogCustomPolicyWindows10", "O365AdminAuditLogConfig", "O365OrgCustomizationSetting", "ODSettings", "SCAuditConfigurationPolicy", "SCComplianceTag", "SCDeviceConditionalAccessPolicy", "SCDeviceConfigurationPolicy", "SPOAccessControlSettings", "SPOBrowserIdleSignout", "SPOSharingSettings", "SPOSiteScript", "SPOStorageEntity", "SPOTenantCdnEnabled", "SPOTenantCdnPolicy", "SPOTenantSettings", "TeamsAppPermissionPolicy", "TeamsAppSetupPolicy", "TeamsAudioConferencingPolicy", "TeamsCallHoldPolicy", "TeamsCallingPolicy", "TeamsCallParkPolicy", "TeamsCallQueue", "TeamsChannelsPolicy", "TeamsClientConfiguration", "TeamsComplianceRecordingPolicy", "TeamsCortanaPolicy", "TeamsDialInConferencingTenantSettings", "TeamsEmergencyCallingPolicy", "TeamsEmergencyCallRoutingPolicy", "TeamsEnhancedEncryptionPolicy", "TeamsEventsPolicy", "TeamsFederationConfiguration", "TeamsFeedbackPolicy", "TeamsFilesPolicy", "TeamsGuestMeetingConfiguration", "TeamsGuestMessagingConfiguration",  "TeamsMeetingConfiguration", "TeamsMeetingPolicy", "TeamsTenantNetworkRegion", "TeamsTenantNetworkSite", "TeamsTenantNetworkSubnet", "TeamsTenantTrustedIPAddress") -ApplicationId $ApplicationID -CertificateThumbprint $CertificateThumbprint -TenantId $TenantName -Path $PathDrift

New-M365DSCDeltaReport -Source "$PathBaseline\M365TenantConfig.ps1" -Destination "$PathDrift\M365TenantConfig.ps1" -OutputPath "$PathReport\$TenantName-DriftReport-M365.html"



$MailSender = "rubicon-monitor@$TenantName"
$Attachment = "$PathReport\$TenantName-DriftReport-M365.html"
$Recipient = "a.bode@rubicon.nl"

#Get File Name and Base64 string
$FileName=(Get-Item -Path $Attachment).name
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Attachment))

#Connect to GRAPH API
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

#Send Mail    
$URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"
$BodyJsonsend = @"
                    {
                        "message": {
                          "subject": "$Customer | Drift Detection M365",
                          "body": {
                            "contentType": "HTML",
                            "content": "This mail is scheduled every day for detecting Microsoft 365 configuration drift. Download the attachment<br>
                             <br>
                            <br>
                            <br>
                            "
                          },
                          
                          "toRecipients": [
                            {
                              "emailAddress": {
                                "address": "$Recipient"
                              }
                            }
                          ]
                          ,"attachments": [
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
