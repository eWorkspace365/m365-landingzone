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

Export-M365DSCConfiguration -Components @("AADAdministrativeUnit", "AADAttributeSet", "AADAuthenticationContextClassReference", "AADAuthenticationMethodPolicy", "AADAuthenticationMethodPolicyAuthenticator", "AADAuthenticationMethodPolicyEmail", "AADAuthenticationMethodPolicyFido2", "AADAuthenticationMethodPolicySms", "AADAuthenticationMethodPolicySoftware", "AADAuthenticationMethodPolicyTemporary", "AADAuthenticationMethodPolicyVoice", "AADAuthenticationMethodPolicyX509", "AADAuthenticationStrengthPolicy", "AADAuthorizationPolicy", "AADCrossTenantAccessPolicy", "AADCrossTenantAccessPolicyConfigurationDefault", "AADCrossTenantAccessPolicyConfigurationPartner", "AADExternalIdentityPolicy", "AADGroupLifecyclePolicy", "AADNamedLocationPolicy", "AADSecurityDefaults", "AADSocialIdentityProvider", "AADTenantDetails", "AADTokenLifetimePolicy") -ApplicationId $ApplicationID -CertificateThumbprint $CertificateThumbprint -TenantId $TenantName -Path $PathBaseline














