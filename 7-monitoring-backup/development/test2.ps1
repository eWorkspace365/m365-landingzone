#Requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AADClientId,

    [Parameter(Mandatory = $true)]
    [string]$AADThumbprint,

    [Parameter(Mandatory = $true)]
    [string]$OrganizationDomain,  # e.g. tenant.onmicrosoft.com

    [Parameter(Mandatory = $true)]
    [string]$AdminUrl,            # e.g. https://tenant-admin.sharepoint.com

    [Parameter(Mandatory = $false)]
    [string]$TenantUrl            # optional filter for sites, e.g. https://tenant.sharepoint.com
)

###############################
# Helper: Save JSON locally
###############################
function Save-ObjectToJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $true)]
        $ItemToSave
    )

    $basePath = $PSScriptRoot
    if (-not $basePath) {
        $basePath = (Get-Location).Path
    }

    $filePath = Join-Path $basePath $FileName
    $ItemToSave | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8

    Write-Host "Saved JSON to '$filePath'" -ForegroundColor Green
    return $filePath
}

###############################
# Helper: get domain from UPN/email/label
###############################
function Get-DomainFromPrincipal {
    param(
        [string]$Principal
    )

    if ([string]::IsNullOrWhiteSpace($Principal)) {
        return $null
    }

    if ($Principal -eq 'Anyone with the link') {
        return 'anonymous'
    }

    if ($Principal -match '@(.+)$') {
        return $Matches[1].ToLower()
    }

    return $null
}



# Will hold all sites from PnP so we can reuse for external users
$allSites = @()


##########################################################
# Region 2: Site labels & sharing (PnP.PowerShell / SPO)
##########################################################
Write-Host "=== Region 2: SharePoint sites (labels & sharing) ===" -ForegroundColor Cyan

if (-not (Get-Module PnP.PowerShell -ListAvailable)) {
    Write-Host "PnP.PowerShell module not found. Install-Module PnP.PowerShell" -ForegroundColor Red
}
else {
    if (-not (Get-Module PnP.PowerShell)) {
        Import-Module PnP.PowerShell
    }

    try {
        Write-Host "Connecting to Tenant Admin Site '$AdminUrl' with PnP..." -ForegroundColor Yellow
        Connect-PnPOnline -Url $AdminUrl -ClientId $AADClientId -Thumbprint $AADThumbprint -Tenant $OrganizationDomain
        Write-Host "PnP connection successful." -ForegroundColor Green

        $siteCollections = Get-PnPTenantSite
        $allSites        = $siteCollections  # Save for external users region
        $siteInfoArray   = @()

        foreach ($site in $siteCollections) {
            $siteUrl = $site.Url

            # Skip OneDrive MySites
            if ($siteUrl -like "*-my.sharepoint.com*") {
                continue
            }

            # Optional filter by TenantUrl if specified
            if ($TenantUrl -and ($siteUrl -notlike "$TenantUrl*")) {
                continue
            }

            $siteDetails = Get-PnPTenantSite -Url $siteUrl | Select-Object Title, SensitivityLabel, SharingCapability

            $siteInfo = [PSCustomObject]@{
                Title             = $siteDetails.Title
                SiteUrl           = $siteUrl
                SensitivityLabel  = $siteDetails.SensitivityLabel
                SharingCapability = $siteDetails.SharingCapability
            }
            $siteInfoArray += $siteInfo
        }

        if ($siteInfoArray.Count -gt 0) {
            Save-ObjectToJsonFile -FileName "sharepointonline-sites-labels.json" -ItemToSave $siteInfoArray
        }
        else {
            Write-Host "No site information collected from PnP (after filters)." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error while retrieving site info with PnP:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

################################################
# Region 3: SharePoint Online External Users Report
################################################
Write-Host "=== Region 3: External users per site ===" -ForegroundColor Cyan

# Global collection for external users
$global:ExternalUsersData = @()

function Get-ExternalUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SiteUrl,

        [Parameter(Mandatory = $true)]
        $SiteObject
    )

    try {
        # Connect to site (app-only)
        Write-Host "Connecting to site '$SiteUrl'..." -ForegroundColor Yellow
        Connect-PnPOnline -Url $SiteUrl -ClientId $AADClientId -Thumbprint $AADThumbprint -Tenant $OrganizationDomain -ErrorAction Stop
        Write-Host "Connection successful to site '$SiteUrl'" -ForegroundColor Green

        $ExternalUsers = Get-PnPUser | Where-Object {
            $_.LoginName -like "*#ext#*" -or $_.LoginName -like "*urn:spo:guest*"
        }

        Write-Host "Found '$($ExternalUsers.Count)' external users on '$SiteUrl'" -ForegroundColor Gray

        foreach ($User in $ExternalUsers) {
            $global:ExternalUsersData += [pscustomobject]@{
                SiteName  = $SiteObject.Title
                SiteUrl   = $SiteUrl
                UserName  = $User.Title
                Email     = $User.Email
                LoginName = $User.LoginName
            }
        }
    }
    catch {
        Write-Host "Error in getting external users for '$SiteUrl' : $($_.Exception.Message)" -ForegroundColor Red
    }
}

if ($allSites -and $allSites.Count -gt 0) {
    # Only sites with sharing enabled
    $sitesWithSharing = $allSites | Where-Object { $_.SharingCapability -ne "Disabled" }

    foreach ($site in $sitesWithSharing) {
        $siteUrl = $site.Url

        # Skip OneDrive my-sites again for safety
        if ($siteUrl -like "*-my.sharepoint.com*") {
            continue
        }

        Get-ExternalUsers -SiteUrl $siteUrl -SiteObject $site
    }

    if ($ExternalUsersData.Count -gt 0) {
        Save-ObjectToJsonFile -FileName "sharepointonline-sites-externalusers.json" -ItemToSave $ExternalUsersData
    }
    else {
        Write-Host "No external users found on any site (with sharing enabled)." -ForegroundColor Yellow
    }
}
else {
    Write-Host "PnP site list not available; skipping external users report." -ForegroundColor Yellow
}


# Retrieve sensitivity label, sharing capability, title, and conditional access policy information for each site and export to JSON
Write-Host "Retrieving tenant sites for label export..." -ForegroundColor Cyan
$siteCollections = Get-PnPTenantSite

$siteInfoArray = @()

foreach ($site in $siteCollections) {
    $siteUrl = $site.Url

    # Skip OneDrive my-sites
    if ($siteUrl -like "*-my.sharepoint.com*") {
        continue
    }

    $siteDetails = Get-PnPTenantSite -Url $siteUrl | Select-Object Title, SensitivityLabel, SharingCapability

    $siteInfo = [pscustomobject]@{
        Title             = $siteDetails.Title
        SiteUrl           = $siteUrl
        SensitivityLabel  = $siteDetails.SensitivityLabel
        SharingCapability = $siteDetails.SharingCapability
    }
    $siteInfoArray += $siteInfo
}

Save-ObjectToJsonFile -filename "sharepointonline-sites-labels.json" -itemToSave $siteInfoArray