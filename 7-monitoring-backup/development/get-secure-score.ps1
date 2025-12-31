<#
.SYNOPSIS
    Export Microsoft 365 Secure Score and recommendations (control profiles) to a JSON file using app-only certificate auth.

.DESCRIPTION
    Connects to Microsoft Graph (Microsoft.Graph PowerShell) using a certificate for app-only auth, retrieves secure score objects and secure score control profiles,
    optionally retrieves the beta control profiles, merges them into a friendly structure and writes JSON to disk.

.PARAMETER AppId
    Application (client) id for the registered Azure AD app.

.PARAMETER TenantId
    Tenant (directory) id.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate installed on the running machine/user store that contains the private key for app auth.

.PARAMETER OutputPath
    Path to write the JSON file. Default: .\secureScore-recommendations.json

.PARAMETER UseBeta
    If specified, uses the beta Microsoft.Graph cmdlets for control profiles (may return additional fields).

.EXAMPLE
    .\Export-SecureScoreRecommendations.ps1 -AppId '...' -TenantId '...' -CertificateThumbprint '...' -OutputPath C:\temp\secureScore.json

.NOTES
    Permissions required (Application): SecurityEvents.Read.All (admin consent required).
#>

param(
    [Parameter(Mandatory = $true)] [string]$TenantId,
    [Parameter(Mandatory = $true)] [string]$ClientId,
    [Parameter(Mandatory = $true)] [string]$CertificateThumbprint,
    [Parameter(Mandatory = $false)] [string]$OutputPath = ".\secureScore-recommendations.json",
    [switch]$UseBeta
)


Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint

# Alternative Secure Score Dump
Write-Host "Retrieving secure score results..." -ForegroundColor DarkGray
try {
    $getYesterday = Get-Date((Get-Date).AddDays(-1)) -Format "yyyy-MM-dd"
    $getTime = "T18:09:31Z"
    $combineTime = $getYesterday + $getTime

    $url = "https://graph.microsoft.com/beta/security/secureScores?`$filter=createdDateTime ge $combineTime"
    $secureScoreResponse = Invoke-MgGraphRequest -Uri $url -Method Get

    # Save secure score results to file
    $secureScoreDumpFile = "./SecureScoreDump.json"
    $secureScoreResponse | ConvertTo-Json -Depth 100 | Out-File -FilePath $secureScoreDumpFile
} catch {
    Write-Host "Error retrieving secure score: $_" -ForegroundColor Red
}

