[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$Customer,
    
	[Parameter(Mandatory=$false)]
    [String]$TenantID,
	
    [Parameter(Mandatory=$false)]
    [String]$AppID,
    
    [Parameter(Mandatory=$false)]
    [String]$CertificateThumbprint,
    
    [Parameter(Mandatory=$false)]
    [String]$Organization,
    
    [Parameter(Mandatory=$false)]
    [String]$AdminURL,
    
    [Parameter(Mandatory=$false)]
    [String]$TenantURL,
    
    [Parameter(Mandatory=$false)]
    [String]$Config
)


# Execute M365-HC-AAD.ps1
& "F:\Scripts\HC\M365\M365-HC-AAD.ps1" $Customer $TenantID $AppID $CertificateThumbprint

# Execute M365-HC-MFA.ps1
# & "F:\Scripts\HC\M365\M365-HC-MFA.ps1" $Customer $TenantID $AppID $CertificateThumbprint

# Execute M365-HC-CA.ps1
# & "F:\Scripts\HC\M365\M365-HC-CA.ps1" $Customer $TenantID $AppID $CertificateThumbprint

# Execute M365-HC-SC.ps1
& "F:\Scripts\HC\M365\M365-HC-SC.ps1" $Customer $TenantID $AppID $CertificateThumbprint

# Execute M365-HC-EXO.ps1
& "F:\Scripts\HC\M365\M365-HC-EXO.ps1" $Customer $TenantID $AppID $CertificateThumbprint $Organization

# Execute M365-HC-CIS.ps1
# & "F:\Scripts\HC\M365\M365-HC-CIS.ps1" $Customer $TenantID $AppID $CertificateThumbprint $Organization $AdminURL

# Execute M365-HC-SPO.ps1
& "F:\Scripts\HC\M365\M365-HC-SPO.ps1" $Customer $TenantID $AppID $CertificateThumbprint $Organization $AdminURL $TenantURL

# Execute M365-HC-CopyJSON.ps1
& "F:\Scripts\HC\M365\M365-HC-CopyJSON.ps1" $Customer