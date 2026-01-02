<#
Restores a SharePoint site from a local backup created by the companion backup script.

What it does
- Re-uploads all files to their libraries, preserving folder structure.
- For Site Pages / Pages: imports each page from _PnPPageModel\<subfolders>\<Page>.aspx
  using Invoke-PnPSiteTemplate and publishes the page.
- Optionally disables DenyAddAndCustomizePages before import and restores it afterwards.

Input backup layout (from the backup script):
  <BackupPath>\
      └─ <Library Title (safe)>\
           ├─ (same folders/files as SharePoint)
           └─ _PnPPageModel\
               └─ <subfolders mirrored>\
                   └─ <PageName>.aspx    # PnP page export, NOT a raw ASPX file

Requirements:
- PnP.PowerShell

Tested with:
- Windows PowerShell 5.1 and PowerShell 7+

#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$true)]
    [string]$SiteUrl,

    # Path to the dated backup folder, e.g. C:\SPO\Backups\InformationPortal_2025-09-10
    [Parameter(Mandatory=$true)]
    [string]$BackupPath,

    # --- Auth (choose one) ---
    [string]$TenantId,
    [string]$ClientId,
    [string]$Thumbprint,      # certificate thumbprint (CurrentUser/LocalMachine\My)
    [switch]$Interactive,     # interactive auth (handy for testing)

    # --- Optional Admin Center URL to toggle DenyAddAndCustomizePages ---
    [string]$AdminUrl,        # e.g. https://contoso-admin.sharepoint.com
    [switch]$ToggleCustomScript, # if set: disable before import, restore after

    # --- Behavior ---
    [int]$MaxRetry = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- helpers ----------
function Write-Info($m){ Write-Host $m -ForegroundColor Cyan }
function Write-Warn($m){ Write-Host $m -ForegroundColor Yellow }
function Write-Err ($m){ Write-Host $m -ForegroundColor Red }

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
            $isThrottle  = ($msg -match '429|Too Many Requests|throttl|rate')
            $isTransient = ($msg -match '5\d\d|timed out|aborted|forcibly closed|connect|reset|temporarily|gateway|unavailable')
            if (($isThrottle -or $isTransient) -and $i -lt $MaxRetry) {
                $delay = [int][Math]::Min(90, [Math]::Pow(2, $i) * 2)
                Write-Warn ("Transient/{0}: {1} -> retry {2}/{3} in {4}s" -f $Activity, $msg, ($i+1), $MaxRetry, $delay)
                Start-Sleep -Seconds $delay
            } else { throw }
        }
    }
}

function Connect-PnPUrl {
    param([Parameter(Mandatory)][string]$Url)
    if ($Interactive -or (-not $TenantId) -or (-not $ClientId) -or (-not $Thumbprint)) {
        Connect-PnPOnline -Url $Url -Interactive
    } else {
        Connect-PnPOnline -Url $Url -Tenant $TenantId -ClientId $ClientId -Thumbprint $Thumbprint
    }
}

# Get a list object by comparing safe title to backup folder name
function Resolve-ListByBackupFolder {
    param(
        [Parameter(Mandatory)][string]$FolderName,
        [Parameter(Mandatory)][Microsoft.SharePoint.Client.List[]]$Lists
    )
    foreach ($l in $Lists) {
        if ((Convert-ToSafeName $l.Title) -eq $FolderName) { return $l }
    }
    return $null
}

# Ensure/return a folder path (site-relative) using Resolve-PnPFolder
function Ensure-Folder {
    param([Parameter(Mandatory)][string]$SiteRelativePath)
    # e.g. "Shared Documents/Folder/Sub"
    Invoke-WithRetry -Activity "Resolve-PnPFolder" -MaxRetry $MaxRetry -Operation {
        Resolve-PnPFolder -SiteRelativePath $SiteRelativePath
    } | Out-Null
}

# Upload a single file to a site-relative folder path
function Upload-File {
    param(
        [Parameter(Mandatory)][string]$LocalPath,
        [Parameter(Mandatory)][string]$SiteRelativeFolder
    )
    Invoke-WithRetry -Activity "Add-PnPFile" -MaxRetry $MaxRetry -Operation {
        Add-PnPFile -Path $LocalPath -Folder $SiteRelativeFolder -ErrorAction Stop
    } | Out-Null
}

# Import one modern page export and publish it
function Import-ModernPage {
    param(
        [Parameter(Mandatory)][string]$ExportFilePath,        # path to _PnPPageModel\...\Home.aspx (template file)
        [Parameter(Mandatory)][string]$PageSiteRelativePath   # e.g. "SitePages/HR/Home.aspx"
    )
    $resourceFolder = Split-Path -Parent $ExportFilePath

    try {
        Invoke-WithRetry -Activity "Invoke-PnPSiteTemplate($($ExportFilePath | Split-Path -Leaf))" -MaxRetry $MaxRetry -Operation {
            Invoke-PnPSiteTemplate -Path $ExportFilePath -Handlers Pages,PageContents -ResourceFolder $resourceFolder -ErrorAction Stop
        }
        # Publish the created/updated page
        Invoke-WithRetry -Activity "Set-PnPPage -Publish ($PageSiteRelativePath)" -MaxRetry $MaxRetry -Operation {
            Set-PnPPage -Identity $PageSiteRelativePath -Publish -ErrorAction SilentlyContinue
        }
        return "OK"
    } catch {
        $msg = $_.Exception.Message
        Write-Warn ("Page import failed for {0}: {1}" -f $PageSiteRelativePath, $msg)
        if ($msg -match 'NoComponentId') {
            Write-Warn "→ Likely missing an SPFx web part/extension on the target site. Install the solution or replace the web part, then re-run."
        }
        return "Failed: $msg"
    }
}

# ---------- start ----------
if (-not (Get-Module -ListAvailable -Name PnP.PowerShell)) {
    throw "PnP.PowerShell not found. Install-Module PnP.PowerShell -Scope CurrentUser"
}

if (!(Test-Path $BackupPath)) { throw "BackupPath not found: $BackupPath" }

Write-Info ("Connecting to site: {0}" -f $SiteUrl)
Connect-PnPUrl -Url $SiteUrl

# Connect to Admin if we need to toggle Custom Script
$adminConn = $null
$originalDACP = $null
if ($ToggleCustomScript) {
    if (-not $AdminUrl) { Write-Warn "ToggleCustomScript requested but -AdminUrl not provided. Skipping toggle." }
    else {
        Write-Info ("Connecting to Admin: {0}" -f $AdminUrl)
        $adminConn = Connect-PnPUrl -Url $AdminUrl

        # Read current setting and disable if needed
        $siteInfo = Get-PnPTenantSite -Url $SiteUrl
        $originalDACP = $siteInfo.DenyAddAndCustomizePages
        if ($originalDACP -ne 'Disabled') {
            Write-Info "Disabling DenyAddAndCustomizePages for restore…"
            Set-PnPTenantSite -Url $SiteUrl -DenyAddAndCustomizePages $false
            Start-Sleep -Seconds 5
        } else {
            Write-Info "DenyAddAndCustomizePages already Disabled."
        }
    }
}

try {
    # Gather target web and lists
    $web = Get-PnPWeb -Includes ServerRelativeUrl
    $lists = Get-PnPList | Where-Object { $_.BaseType -eq 'DocumentLibrary' -and -not $_.Hidden }

    # For each library folder in the backup
    $libFolders = Get-ChildItem -Path $BackupPath -Directory | Sort-Object Name
    if (-not $libFolders) { Write-Warn "No library folders found under $BackupPath"; return }

    foreach ($libFolder in $libFolders) {
        $libNameSafe = $libFolder.Name
        $list = Resolve-ListByBackupFolder -FolderName $libNameSafe -Lists $lists
        if (-not $list) {
            Write-Warn ("Skipping '{0}' – no matching library found in site (by safe title)." -f $libNameSafe)
            continue
        }

        $libSrvRoot = $list.RootFolder.ServerRelativeUrl.Trim('/')
        $libSiteRel = $libSrvRoot.Substring($web.ServerRelativeUrl.TrimEnd('/').Length).Trim('/')

        Write-Info ("`n--- RESTORE LIBRARY: {0}  (-> {1}) ---" -f $list.Title, $libSiteRel)

        # 1) Upload all files except the special _PnPPageModel folder
        $allFiles = Get-ChildItem -Path $libFolder.FullName -Recurse -File `
                     | Where-Object { $_.FullName -notmatch '(\\|/)__?PnPPageModel(\\|/)' }

        # If this is Site Pages/Pages, do NOT upload raw .aspx (we'll create pages from templates next)
        $isPagesLib = ($libSrvRoot -match '/SitePages$' -or $libSrvRoot -match '/Pages$')
        if ($isPagesLib) {
            $allFiles = $allFiles | Where-Object { $_.Extension -ne '.aspx' }
        }

        $count = ($allFiles | Measure-Object).Count
        $i = 0
        foreach ($file in $allFiles) {
            $relative = $file.FullName.Substring($libFolder.FullName.Length + 1).Replace('\','/')
            $relDir = Split-Path $relative -Parent
            $targetSiteRelFolder = if ([string]::IsNullOrEmpty($relDir)) { $libSiteRel } else { "$libSiteRel/$relDir" }

            # Create folder path if needed, then upload
            Ensure-Folder -SiteRelativePath $targetSiteRelFolder
            $i++
            Write-Progress -Activity ("Uploading '{0}'" -f $list.Title) -Status ("{0}/{1}: {2}" -f $i, $count, $relative) -PercentComplete (($i/$count)*100)
            Upload-File -LocalPath $file.FullName -SiteRelativeFolder $targetSiteRelFolder
        }

        # 2) Import modern pages from _PnPPageModel (if present)
        $modelRoot = Join-Path $libFolder.FullName "_PnPPageModel"
        if (Test-Path $modelRoot) {
            $exports = Get-ChildItem -Path $modelRoot -Recurse -File -Include *.aspx, *.pnp
            if ($exports) {
                Write-Info ("Importing page models for '{0}'…" -f $list.Title)
                foreach ($exp in $exports) {
                    # Build the page site-relative path from modelRoot mirror
                    $relUnderModel = $exp.FullName.Substring($modelRoot.Length + 1).Replace('\','/')
                    $pageSiteRel = if ([string]::IsNullOrEmpty($relUnderModel)) {
                        $libSiteRel
                    } else {
                        # ensure library internal URL ("SitePages" or "Pages") + relative path under model
                        "$libSiteRel/$relUnderModel"
                    }
                    # Import & publish
                    [void](Import-ModernPage -ExportFilePath $exp.FullName -PageSiteRelativePath $pageSiteRel)
                }
            } else {
                Write-Warn ("No page exports found under {0}" -f $modelRoot)
            }
        } else {
            if ($isPagesLib) {
                Write-Warn "No _PnPPageModel folder found for Site Pages; pages won’t be recreated."
            }
        }

        Write-Info ("Finished: {0}" -f $list.Title)
    }
}
finally {
    # Restore DenyAddAndCustomizePages if we changed it
    if ($ToggleCustomScript -and $AdminUrl -and $originalDACP) {
        if ($originalDACP -ne 'Disabled') {
            Write-Info "Restoring DenyAddAndCustomizePages to original state…"
            Set-PnPTenantSite -Url $SiteUrl -DenyAddAndCustomizePages $true
        }
    }
}

Write-Host ""
Write-Host ("✔ Restore finished from → {0}" -f $BackupPath) -ForegroundColor Green
