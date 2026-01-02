<#
.SYNOPSIS
Back up all SharePoint Online site collections by calling a per-site backup script.

.DESCRIPTION
Enumerates tenant sites from the SharePoint Admin Center and, for each site (excluding OneDrive
sites with "-my.sharepoint.com" in the URL), calls the provided per-site backup script
(e.g. backup-sharepoint-site.ps1).

Per-site backup location layout:
  <RootFolder>\<SafeSiteName>\<yyyy-MM-dd>\ ...

The date subfolder is created by the per-site script; this orchestrator sets BackupRoot to
<RootFolder>\<SafeSiteName> so the date folder lands inside that site folder.

.AUTH
Supports:
- Certificate-based app-only: TenantId, ClientId, Thumbprint
- Interactive login: -Interactive

.REQUIREMENTS
- PnP.PowerShell
- The per-site script (default: backup-sharepoint-site.ps1) in the same folder as this script

.EXAMPLE
# Cert-based auth
./backup-all-sharepoint-sites.ps1 \ 
  -AdminUrl "https://contoso-admin.sharepoint.com" \ 
  -RootFolder "D:\\SPO-Backups" \ 
  -TenantId "<TENANT-GUID>" -ClientId "<APP-ID>" -Thumbprint "<CERT-THUMBPRINT>" -PersistBrandingFiles

.EXAMPLE
# Interactive auth
./backup-all-sharepoint-sites.ps1 -AdminUrl "https://contoso-admin.sharepoint.com" -RootFolder "D:\\SPO-Backups" -Interactive

.NOTES
- Uses robust retry for transient errors and throttling
- Creates a CSV summary under <RootFolder>\_logs
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$AdminUrl,  # e.g., https://tenant-admin.sharepoint.com

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$RootFolder,

    # Auth (choose either interactive or cert)
    [string]$TenantId,
    [string]$ClientId,
    [string]$Thumbprint,
    [switch]$Interactive,

    # Behavior
    [int]$MaxRetry = 5,
    [switch]$PersistBrandingFiles,

    # Optionally restrict to sites whose URL matches patterns (wildcards) or exclude patterns
    [string[]]$IncludeUrlLike,
    [string[]]$ExcludeUrlLike = @('-my.sharepoint.com'),

    # Path to the single-site backup script
    [string]$BackupScriptPath = $(Join-Path -Path $PSScriptRoot -ChildPath 'spo-site-backup.ps1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info($m){ Write-Host $m -ForegroundColor Cyan }
function Write-Warn($m){ Write-Host $m -ForegroundColor Yellow }
function Write-Err ($m){ Write-Host $m -ForegroundColor Red }

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)][scriptblock]$Operation,
        [int]$MaxRetry = 5,
        [string]$Activity = "operation"
    )
    for ($i=0; $i -le $MaxRetry; $i++) {
        try { return & $Operation }
        catch {
            $msg = $_.Exception.Message
            $isThrottle  = ($msg -match '429|Too Many Requests|rate.*too.*large|throttl')
            $isTransient = ($msg -match '5\d\d|timed out|aborted|forcibly closed|connect|reset|temporarily|gateway|unavailable')
            if (($isThrottle -or $isTransient) -and $i -lt $MaxRetry) {
                $delay = [int][Math]::Min(90, [Math]::Pow(2, $i) * 2)
                Write-Warn ("Transient/{0}: {1} -> retry {2}/{3} in {4}s" -f $Activity, $msg, ($i+1), $MaxRetry, $delay)
                Start-Sleep -Seconds $delay
            } else { throw }
        }
    }
}

function Convert-ToSafeName {
    param([Parameter(Mandatory)][string]$Name)
    $invalid = [IO.Path]::GetInvalidFileNameChars()
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Name.ToCharArray()) {
        $toAppend = if ($invalid -contains $ch) { '_' } else { $ch }
        [void]$sb.Append($toAppend)
    }
    $sb.ToString().TrimEnd('.',' ')
}

function Test-UrlIncluded {
    param([string]$Url, [string[]]$Includes)
    if (-not $Includes -or $Includes.Count -eq 0) { return $true }
    foreach ($pat in $Includes) { if ($Url -like "*${pat}*") { return $true } }
    return $false
}

function Test-UrlExcluded {
    param([string]$Url, [string[]]$Excludes)
    foreach ($pat in $Excludes) { if ($Url -like "*${pat}*") { return $true } }
    return $false
}

# --- Pre-flight checks ---
if (-not (Get-Module -ListAvailable -Name PnP.PowerShell)) {
    throw "PnP.PowerShell not found. Install-Module PnP.PowerShell -Scope CurrentUser"
}

if (-not (Test-Path -LiteralPath $BackupScriptPath)) {
    throw "Per-site backup script not found at '$BackupScriptPath'. Place 'spo-site-backup.ps1' beside this script or pass -BackupScriptPath."
}

# Ensure root folders exist
$null = New-Item -ItemType Directory -Force -Path $RootFolder
$logsFolder = Join-Path $RootFolder '_logs'
$null = New-Item -ItemType Directory -Force -Path $logsFolder
$startStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$transcriptPath = Join-Path $logsFolder ("backup-all_{0}.log" -f $startStamp)
Start-Transcript -Path $transcriptPath -Force | Out-Null

try {
    Write-Info ("Connecting to Admin Center: {0}" -f $AdminUrl)
    if ($Interactive -or (-not $TenantId) -or (-not $ClientId) -or (-not $Thumbprint)) {
        Connect-PnPOnline -Url $AdminUrl -Interactive
    } else {
        Connect-PnPOnline -Url $AdminUrl -Tenant $TenantId -ClientId $ClientId -Thumbprint $Thumbprint
    }

    Write-Info "Retrieving site collections ..."
    $siteCollections = Invoke-WithRetry -Activity 'Get-PnPTenantSite' -MaxRetry $MaxRetry -Operation {
        # -Detailed fetches more properties (Template, Title, HubSiteId, etc.)
        Get-PnPTenantSite -Detailed
    }

    if (-not $siteCollections) {
        Write-Warn 'No site collections returned.'
        return
    }

    # Summary collector
    $summary = New-Object System.Collections.Generic.List[object]

    $index = 0
    foreach ($site in $siteCollections) {
        $index++
        $siteUrl = $site.Url

        # Skip OneDrive and any excluded patterns
        if (Test-UrlExcluded -Url $siteUrl -Excludes $ExcludeUrlLike) {
            Write-Info ("Skipping (excluded): {0}" -f $siteUrl)
            continue
        }
        if (-not (Test-UrlIncluded -Url $siteUrl -Includes $IncludeUrlLike)) {
            Write-Info ("Skipping (not included by filter): {0}" -f $siteUrl)
            continue
        }

        # Refresh details for the site in loop (as requested)
        $siteDetails = $null
$skipSite = $false
try {
    $siteDetails = Invoke-WithRetry -Activity ("Get-PnPTenantSite -Url {0}" -f $siteUrl) -MaxRetry $MaxRetry -Operation {
        Get-PnPTenantSite -Url $siteUrl -Detailed -Connection $AdminConn
    }
} catch {
    $msg = $_.Exception.Message
    Write-Warn ("Could not read site details for {0}: {1}" -f $siteUrl, $msg)
    if ($msg -match 'not a tenant administration site') {
        Write-Warn ("Skipping (admin context lost): {0}" -f $siteUrl)
        $skipSite = $true
    }
}
if ($skipSite) { continue }

# Safe title resolution
$siteTitle = $null
if ($siteDetails -and ($siteDetails.PSObject.Properties.Name -contains 'Title')) {
    $siteTitle = $siteDetails.Title
}
        if ([string]::IsNullOrWhiteSpace($siteTitle)) {
            # Fallback: last segment of the path, or 'RootSite'
            $uri = [uri]$siteUrl
            $seg = ($uri.AbsolutePath.Trim('/').Split('/') | Select-Object -Last 1)
            if ([string]::IsNullOrWhiteSpace($seg)) { $seg = 'RootSite' }
            $siteTitle = $seg
        }

        $safeSiteName = Convert-ToSafeName $siteTitle
        $perSiteRoot  = Join-Path $RootFolder $safeSiteName
        $null = New-Item -ItemType Directory -Force -Path $perSiteRoot

        Write-Host ""  # blank line between sites
        Write-Host ("=== [{0}/{1}] Backing up: {2}  (Title: {3}) ===" -f $index, ($siteCollections.Count), $siteUrl, $siteTitle) -ForegroundColor Green

        $result = 'Success'
        $errorMsg = $null
        $dateFolderPreview = (Get-Date -Format 'yyyy-MM-dd')
        $expectedBackupRoot = $perSiteRoot  # per-site script adds the date folder under this
        try {
            $args = @{
                SiteUrl = $siteUrl
                BackupRoot = $expectedBackupRoot
                MaxRetry = $MaxRetry
            }
            if ($PersistBrandingFiles) { $args.PersistBrandingFiles = $true }

            if (-not $Interactive -and $TenantId -and $ClientId -and $Thumbprint) {
                $args.TenantId  = $TenantId
                $args.ClientId  = $ClientId
                $args.Thumbprint = $Thumbprint
            } else {
                $args.Interactive = $true
            }

            # Call the per-site script in-process
            & $BackupScriptPath @args
        }
        catch {
            $result = 'Failed'
            $errorMsg = $_.Exception.Message
            Write-Err ("Backup FAILED for {0}: {1}" -f $siteUrl, $errorMsg)
        }

        $summary.Add([pscustomobject]@{
            SiteUrl          = $siteUrl
            Title            = $siteTitle
            SafeSiteName     = $safeSiteName
            BackupRoot       = $expectedBackupRoot
            DateFolder       = $dateFolderPreview
            Result           = $result
            Error            = $errorMsg
        })
    }

    # Write summary CSV
    $sumPath = Join-Path $logsFolder ("backup-summary_{0}.csv" -f $startStamp)
    $summary | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $sumPath
    Write-Info ("\nSummary written: {0}" -f $sumPath)
}
finally {
    Stop-Transcript | Out-Null
}
