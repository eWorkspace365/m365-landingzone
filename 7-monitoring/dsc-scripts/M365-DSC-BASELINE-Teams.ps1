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

Export-M365DSCConfiguration -Components @("TeamsAppPermissionPolicy", "TeamsAppSetupPolicy", "TeamsAudioConferencingPolicy", "TeamsCallHoldPolicy", "TeamsCallingPolicy", "TeamsCallParkPolicy", "TeamsCallQueue", "TeamsChannelsPolicy", "TeamsClientConfiguration", "TeamsComplianceRecordingPolicy", "TeamsCortanaPolicy", "TeamsDialInConferencingTenantSettings", "TeamsEmergencyCallingPolicy", "TeamsEmergencyCallRoutingPolicy", "TeamsEnhancedEncryptionPolicy", "TeamsEventsPolicy", "TeamsFederationConfiguration", "TeamsFeedbackPolicy", "TeamsFilesPolicy", "TeamsGuestMeetingConfiguration", "TeamsGuestMessagingConfiguration",  "TeamsMeetingConfiguration", "TeamsMeetingPolicy", "TeamsTenantNetworkRegion", "TeamsTenantNetworkSite", "TeamsTenantNetworkSubnet", "TeamsTenantTrustedIPAddress") -ApplicationId $ApplicationID -CertificateThumbprint $CertificateThumbprint -TenantId $TenantName -Path $PathBaseline














