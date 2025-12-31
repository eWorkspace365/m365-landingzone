<#
Backs up all non-hidden document libraries of a SharePoint site.
Special handling for Site Pages / Pages: export each modern page model with Export-PnPPage
to a file named exactly like the page (e.g., "Home.aspx") under _PnPPageModel\<subfolders>.

Output layout:
  <BackupRoot>\<yyyy-MM-dd>\
      └─ <Library Title (safe)>\
           ├─ (same folder structure as in SharePoint with files)
           └─ _PnPPageModel\
               └─ <optional-subfolders>\   # mirrors Site Pages subfolders
                   └─ <PageName>.aspx      # Export-PnPPage output (template content), named as the page

Extras:
- _PnPPageModel_manifest.csv at the date root with page→export info.

Requirements:
- PnP.PowerShell (Install-Module PnP.PowerShell -Scope CurrentUser)

Works with:
- Windows PowerShell 5.1 and PowerShell 7+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SiteUrl,

    [Parameter(Mandatory=$true)]
    [string]$BackupRoot,

    # --- Auth (choose one) ---
    [string]$TenantId,
    [string]$ClientId,
    [string]$Thumbprint,   # certificate thumbprint (in CurrentUser/LocalMachine\My)
    [switch]$Interactive,  # use interactive auth (recommended when testing)

    # --- Behavior ---
    [int]$MaxRetry = 5,
    [switch]$PersistBrandingFiles # also export referenced assets where supported
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- helpers ----------
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

function Connect-PnPUrl {
    param([Parameter(Mandatory)][string]$Url)
    if ($Interactive -or (-not $TenantId) -or (-not $ClientId) -or (-not $Thumbprint)) {
        Connect-PnPOnline -Url $Url -Interactive
    } else {
        Connect-PnPOnline -Url $Url -Tenant $TenantId -ClientId $ClientId -Thumbprint $Thumbprint
    }
}
# -----------------------------

# Check module
if (-not (Get-Module -ListAvailable -Name PnP.PowerShell)) {
    throw "PnP.PowerShell not found. Install-Module PnP.PowerShell -Scope CurrentUser"
}

# Connect
Write-Info ("Connecting to {0} ..." -f $SiteUrl)
Connect-PnPUrl -Url $SiteUrl

# Make dated folder
$BackupDate = Get-Date -Format "yyyy-MM-dd"
$BackupPath = Join-Path $BackupRoot $BackupDate
if (!(Test-Path $BackupPath)) { New-Item $BackupPath -ItemType Directory -Force | Out-Null }
Write-Info ("Backup folder: {0}" -f $BackupPath)

# Get web + libraries
$web = Get-PnPWeb -Includes ServerRelativeUrl, Title
$libraries = Get-PnPList | Where-Object { $_.BaseType -eq 'DocumentLibrary' -and -not $_.Hidden }

if (-not $libraries) { Write-Warn "No visible document libraries found."; return }

# Global manifest for page exports
$script:AllPageExports = New-Object System.Collections.Generic.List[object]

# Helper: download every file from a library
function Download-LibraryFiles {
    param(
        [Parameter(Mandatory)][Microsoft.SharePoint.Client.List]$List,
        [Parameter(Mandatory)][string]$LocalLibFolder,
        [int]$MaxRetry = 5
    )
    $libRoot = $List.RootFolder.ServerRelativeUrl.TrimEnd('/')

    $items = Get-PnPListItem -List $List.Id -PageSize 2000 -Fields "FileRef","FileLeafRef","FSObjType"
    $fileItems = $items | Where-Object { $_.FieldValues["FSObjType"] -eq 0 }

    $i = 0
    $total = ($fileItems | Measure-Object).Count
    foreach ($it in $fileItems) {
        $fileRef  = $it.FieldValues["FileRef"]                 # /sites/..../Lib/Sub/File.docx
        $fileName = $it.FieldValues["FileLeafRef"]
        $insideLib = $fileRef.Substring($libRoot.Length + 1)    # Sub/File.docx

        $localFile = Join-Path $LocalLibFolder $insideLib
        $localDir  = Split-Path $localFile -Parent
        if (!(Test-Path $localDir)) { New-Item $localDir -ItemType Directory -Force | Out-Null }

        $i++
        Write-Progress -Activity ("Downloading '{0}'" -f $List.Title) -Status ("{0}/{1}: {2}" -f $i, $total, $insideLib) -PercentComplete (($i/$total)*100)

        Invoke-WithRetry -Activity "Get-PnPFile" -MaxRetry $MaxRetry -Operation {
            Get-PnPFile -Url $fileRef -Path $localDir -FileName $fileName -AsFile -Force -ErrorAction Stop
        }
    }
}

# Helper: export page models using Export-PnPPage (for Site Pages / Pages)
function Export-PageModels {
    param(
        [Parameter(Mandatory)][Microsoft.SharePoint.Client.List]$List,
        [Parameter(Mandatory)][string]$LocalLibFolder,
        [switch]$PersistBrandingFiles,
        [int]$MaxRetry = 5
    )

    if (-not (Get-Command Export-PnPPage -ErrorAction SilentlyContinue)) {
        Write-Warn "Export-PnPPage not available in your PnP version. Skipping page model export."
        return
    }

    $exportFolder = Join-Path $LocalLibFolder "_PnPPageModel"
    if (!(Test-Path $exportFolder)) { New-Item $exportFolder -ItemType Directory -Force | Out-Null }

    $libRoot = $List.RootFolder.ServerRelativeUrl.TrimEnd('/')

    # Get all .aspx items under the library
    $items = Get-PnPListItem -List $List.Id -PageSize 1000 -Fields "FileRef","FileLeafRef","FSObjType" |
             Where-Object { $_.FieldValues["FSObjType"] -eq 0 -and $_.FieldValues["FileLeafRef"] -like "*.aspx" }

    $i=0; $total=($items | Measure-Object).Count
    foreach ($it in $items) {
        $leaf     = $it.FieldValues["FileLeafRef"]             # e.g. Home.aspx
        $fileRef  = $it.FieldValues["FileRef"]                 # /sites/.../SitePages/HR/Home.aspx or /Pages/Home.aspx
        $relative = $fileRef.Substring($libRoot.Length + 1)    # e.g. HR/Home.aspx or Home.aspx

        # Mirror subfolders under _PnPPageModel
        $relDir    = Split-Path $relative -Parent
        $targetDir = if ([string]::IsNullOrEmpty($relDir)) { $exportFolder } else { Join-Path $exportFolder $relDir }
        if (!(Test-Path $targetDir)) { New-Item $targetDir -ItemType Directory -Force | Out-Null }

        # IMPORTANT: write the export to a file named exactly like the page (Home.aspx)
        $outFile = Join-Path $targetDir $leaf

        $i++
        Write-Progress -Activity ("Exporting page models '{0}'" -f $List.Title) -Status ("{0}/{1}: {2}" -f $i, $total, $relative) -PercentComplete (($i/$total)*100)

        $status = "Exported"
        $errMsg = $null
        try {
            Invoke-WithRetry -Activity "Export-PnPPage($leaf)" -MaxRetry $MaxRetry -Operation {
                if ($PersistBrandingFiles) {
                    Export-PnPPage -Identity $leaf -Out $outFile -Force -PersistBrandingFiles -ErrorAction Stop
                } else {
                    Export-PnPPage -Identity $leaf -Out $outFile -Force -ErrorAction Stop
                }
            }
        } catch {
            try {
                Invoke-WithRetry -Activity "Export-PnPPage($fileRef)" -MaxRetry $MaxRetry -Operation {
                    if ($PersistBrandingFiles) {
                        Export-PnPPage -Identity $fileRef -Out $outFile -Force -PersistBrandingFiles -ErrorAction Stop
                    } else {
                        Export-PnPPage -Identity $fileRef -Out $outFile -Force -ErrorAction Stop
                    }
                }
            } catch {
                $status = "Failed"
                $errMsg = $_.Exception.Message
                Write-Warn ("Export-PnPPage failed for {0}: {1}" -f $relative, $errMsg)
            }
        }

        # Add to manifest
        $script:AllPageExports.Add([pscustomobject]@{
            LibraryTitle     = $List.Title
            PageFileRef      = $fileRef
            PageName         = $leaf
            ExportLocalPath  = $outFile
            Status           = $status
            Error            = $errMsg
        })
    }
}

# ---- main ----
$totalLibs = 0
foreach ($lib in $libraries) {
    $totalLibs++
    $safeTitle = Convert-ToSafeName $lib.Title
    $libFolder = Join-Path $BackupPath $safeTitle
    if (!(Test-Path $libFolder)) { New-Item $libFolder -ItemType Directory -Force | Out-Null }

    Write-Info ("`n--- LIBRARY: {0} ---" -f $lib.Title)

    # Always download physical files first
    Download-LibraryFiles -List $lib -LocalLibFolder $libFolder -MaxRetry $MaxRetry

    # If this is Site Pages or Pages, also export page models
    $libRootSrv = $lib.RootFolder.ServerRelativeUrl.TrimEnd('/')
    $isPagesLib = ($libRootSrv -match '/SitePages$' -or $libRootSrv -match '/Pages$')
    if ($isPagesLib) {
        Export-PageModels -List $lib -LocalLibFolder $libFolder -PersistBrandingFiles:$PersistBrandingFiles -MaxRetry $MaxRetry
    }

    Write-Info ("Finished: {0}" -f $lib.Title)
}

# Write manifest for all page exports
if ($script:AllPageExports.Count -gt 0) {
    $manifestPath = Join-Path $BackupPath "_PnPPageModel_manifest.csv"
    $script:AllPageExports | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $manifestPath
    Write-Info ("Page export manifest: {0}" -f $manifestPath)
} else {
    Write-Warn "No page exports captured (no Site Pages/Pages libraries or all exports failed)."
}

Write-Host ""
Write-Host ("✔ Backup finished → {0}  (Libraries processed: {1})" -f $BackupPath, $totalLibs) -ForegroundColor Green
