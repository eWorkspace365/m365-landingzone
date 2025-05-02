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

Export-M365DSCConfiguration -Components @("SPOAccessControlSettings", "SPOBrowserIdleSignout", "SPOHomeSite", "SPOHubSite", "SPOOrgAssetsLibrary", "SPOSearchManagedProperty", "SPOSearchResultSource", "SPOSharingSettings", "SPOStorageEntity", "SPOTenantCdnEnabled", "SPOTenantCdnPolicy", "SPOTenantSettings", "SPOTheme") -ApplicationId $ApplicationID -CertificateThumbprint $CertificateThumbprint -TenantId $TenantName -Path $PathBaseline














