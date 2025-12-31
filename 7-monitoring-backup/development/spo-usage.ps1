<#
.SYNOPSIS
    Get internal and external sharing activity for SharePoint Online and OneDrive (per user)
    using direct Graph URLs + Invoke-MgGraphRequest.

.DESCRIPTION
    Uses the Microsoft Graph reports endpoints via URL:

      https://graph.microsoft.com/v1.0/reports/getSharePointActivityUserDetail(period='D30')
      https://graph.microsoft.com/v1.0/reports/getOneDriveActivityUserDetail(period='D30')

    Downloads the CSV files with Invoke-MgGraphRequest -OutputFilePath
    and merges them into one per-user CSV with internal/external sharing counts.

.PARAMETER TenantId
    Entra ID tenant ID (GUID).

.PARAMETER AppId
    Client ID of the Graph app registration.

.PARAMETER CertificateThumbprint
    Thumbprint of the certificate used for app-only auth.

.PARAMETER Period
    D7, D30, D90, D180

.PARAMETER OutputPath
    Folder for final CSV.

.PARAMETER OpenReport
    Open the CSV after generation.
#>

#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$AppId,

    [Parameter(Mandatory = $true)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [ValidateSet('D7','D30','D90','D180')]
    [string]$Period = 'D30',

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".",

    [switch]$OpenReport
)

#region Prep & module checks
Write-Verbose "Validating Microsoft Graph module..."

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw "Module 'Microsoft.Graph.Authentication' is not installed. Run: Install-Module Microsoft.Graph -Scope CurrentUser"
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

if (-not (Test-Path -Path $OutputPath)) {
    Write-Verbose "OutputPath '$OutputPath' does not exist. Creating..."
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$tempFolder = Join-Path -Path $env:TEMP -ChildPath "M365SharingReports"
if (-not (Test-Path $tempFolder)) {
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
}

#endregion Prep & module checks

#region Connect to Graph (app-only with cert)

Write-Verbose "Connecting to Microsoft Graph using app-only certificate auth..."

Connect-MgGraph -ClientId $AppId `
                -TenantId $TenantId `
                -CertificateThumbprint $CertificateThumbprint `
                -NoWelcome `
                -ErrorAction Stop

$ctx = Get-MgContext
if (-not $ctx) {
    throw "Unable to obtain Graph context after Connect-MgGraph."
}

Write-Verbose ("Connected to tenant: {0}" -f $ctx.TenantId)

#endregion Connect

#region Build URLs and download CSVs via Invoke-MgGraphRequest

# Graph URLs (usage reports – SharePoint & OneDrive user detail)
$spUrl = "https://graph.microsoft.com/v1.0/reports/getSharePointActivityUserDetail(period='$Period')"
$odUrl = "https://graph.microsoft.com/v1.0/reports/getOneDriveActivityUserDetail(period='$Period')"

$spCsv = Join-Path $tempFolder "SharePointActivityUserDetail_$($Period).csv"
$odCsv = Join-Path $tempFolder "OneDriveActivityUserDetail_$($Period).csv"

Write-Verbose "Downloading SharePoint activity user detail (URL: $spUrl)..."
Invoke-MgGraphRequest -Method GET -Uri $spUrl -OutputFilePath $spCsv -ErrorAction Stop

Write-Verbose "Downloading OneDrive activity user detail (URL: $odUrl)..."
Invoke-MgGraphRequest -Method GET -Uri $odUrl -OutputFilePath $odCsv -ErrorAction Stop

if (-not (Test-Path $spCsv) -or -not (Test-Path $odCsv)) {
    throw "Failed to download one or both CSV reports. Check Reports.Read.All (Application) permissions and try again."
}

#endregion Build URLs and download CSVs

#region Import & normalize CSVs

Write-Verbose "Importing CSVs..."

# Some tenants add BOM, so strip it if needed by piping through -replace before ConvertFrom-Csv if you ever hit issues
$spRaw = Import-Csv -Path $spCsv
$odRaw = Import-Csv -Path $odCsv

Write-Verbose ("Imported {0} SharePoint rows and {1} OneDrive rows." -f $spRaw.Count, $odRaw.Count)

# Build lookup for SharePoint by UPN (latest row per user)
$spByUpn = @{}

foreach ($row in $spRaw) {
    $upn = $row.'User Principal Name'

    if ([string]::IsNullOrWhiteSpace($upn)) { continue }

    if ($spByUpn.ContainsKey($upn)) {
        $existing    = $spByUpn[$upn]
        $existingDate = [datetime]::MinValue
        $newDate      = [datetime]::MinValue

        if ($existing.SP_LastActivityDate) { [void][datetime]::TryParse($existing.SP_LastActivityDate, [ref]$existingDate) }
        if ($row.'Last Activity Date')     { [void][datetime]::TryParse($row.'Last Activity Date', [ref]$newDate) }

        if ($newDate -le $existingDate) { continue }
    }

    $spByUpn[$upn] = [pscustomobject]@{
        UserPrincipalName   = $upn
        SP_LastActivityDate = $row.'Last Activity Date'
        SP_ViewedOrEdited   = [int]$row.'Viewed Or Edited File Count'
        SP_Synced           = [int]$row.'Synced File Count'
        SP_SharedInternal   = [int]$row.'Shared Internally File Count'
        SP_SharedExternal   = [int]$row.'Shared Externally File Count'
        SP_PagesVisited     = [int]$row.'Visited Page Count'
    }
}

# Build lookup for OneDrive by UPN (latest row per user)
$odByUpn = @{}
foreach ($row in $odRaw) {
    $upn = $row.'User Principal Name'
    if ([string]::IsNullOrWhiteSpace($upn)) { continue }

    if ($odByUpn.ContainsKey($upn)) {
        $existing     = $odByUpn[$upn]
        $existingDate = [datetime]::MinValue
        $newDate      = [datetime]::MinValue

        if ($existing.OD_LastActivityDate) { [void][datetime]::TryParse($existing.OD_LastActivityDate, [ref]$existingDate) }
        if ($row.'Last Activity Date')     { [void][datetime]::TryParse($row.'Last Activity Date', [ref]$newDate) }

        if ($newDate -le $existingDate) { continue }
    }

    $odByUpn[$upn] = [pscustomobject]@{
        UserPrincipalName   = $upn
        OD_LastActivityDate = $row.'Last Activity Date'
        OD_ViewedOrEdited   = [int]$row.'Viewed Or Edited File Count'
        OD_Synced           = [int]$row.'Synced File Count'
        OD_SharedInternal   = [int]$row.'Shared Internally File Count'
        OD_SharedExternal   = [int]$row.'Shared Externally File Count'
    }
}

#endregion Import & normalize

#region Merge datasets per user

Write-Verbose "Merging SharePoint and OneDrive activity per user..."

$allUpns = New-Object System.Collections.Generic.HashSet[string]
$spByUpn.Keys | ForEach-Object { [void]$allUpns.Add($_) }
$odByUpn.Keys | ForEach-Object { [void]$allUpns.Add($_) }

$result = foreach ($upn in $allUpns) {
    $sp = $spByUpn[$upn]
    $od = $odByUpn[$upn]

    [pscustomobject]@{
        UserPrincipalName              = $upn

        SharePointLastActivityDate     = if ($sp) { $sp.SP_LastActivityDate } else { $null }
        SharePointFilesViewedOrEdited  = if ($sp) { $sp.SP_ViewedOrEdited } else { 0 }
        SharePointFilesSynced          = if ($sp) { $sp.SP_Synced } else { 0 }
        SharePointSharedInternally     = if ($sp) { $sp.SP_SharedInternal } else { 0 }
        SharePointSharedExternally     = if ($sp) { $sp.SP_SharedExternal } else { 0 }
        SharePointPagesVisited         = if ($sp) { $sp.SP_PagesVisited } else { 0 }

        OneDriveLastActivityDate       = if ($od) { $od.OD_LastActivityDate } else { $null }
        OneDriveFilesViewedOrEdited    = if ($od) { $od.OD_ViewedOrEdited } else { 0 }
        OneDriveFilesSynced            = if ($od) { $od.OD_Synced } else { 0 }
        OneDriveSharedInternally       = if ($od) { $od.OD_SharedInternal } else { 0 }
        OneDriveSharedExternally       = if ($od) { $od.OD_SharedExternal } else { 0 }
    }
}

#endregion Merge

#region Output report

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outFile   = Join-Path $OutputPath "SharingActivity_SPO_OneDrive_${Period}_$timestamp.csv"

Write-Verbose "Writing combined report to '$outFile'..."
$result |
    Sort-Object UserPrincipalName |
    Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8

Write-Host "Sharing activity report created:" -ForegroundColor Green
Write-Host "  $outFile"

if ($OpenReport) {
    Write-Verbose "Opening report file..."
    Invoke-Item -Path $outFile
}

#endregion Output

#region Cleanup

Write-Verbose "Disconnecting from Microsoft Graph..."
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

#endregion Cleanup
