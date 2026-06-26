[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$SiteUrl,

    [Parameter(Mandatory=$true)]
    [string]$RootFolder,

    # Auth
    [Parameter(Mandatory=$false)]
    [string]$TenantId,

    [Parameter(Mandatory=$false)]
    [string]$ClientId,

    [Parameter(Mandatory=$false)]
    [string]$Thumbprint,

    [switch]$Interactive,

    # Behavior
    [int]$MaxRetry = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------
# Logging
# ---------------------------
function Write-Info($m){ Write-Host $m -ForegroundColor Cyan }
function Write-Warn($m){ Write-Host $m -ForegroundColor Yellow }
function Write-Err ($m){ Write-Host $m -ForegroundColor Red }

# ---------------------------
# Retry logic
# ---------------------------
function Invoke-WithRetry {
    param(
        [scriptblock]$Operation,
        [string]$Activity = "operation",
        [int]$MaxRetry = 5
    )

    for ($i=0; $i -le $MaxRetry; $i++) {
        try {
            return & $Operation
        }
        catch {
            $msg = $_.Exception.Message
            $retry = ($msg -match '429|throttl|timeout|5\d\d')

            if ($retry -and $i -lt $MaxRetry) {
                $delay = [math]::Min(60, [math]::Pow(2,$i))
                Write-Warn "Retry $($i+1)/$MaxRetry in $delay sec ($Activity)"
                Start-Sleep $delay
            }
            else {
                throw
            }
        }
    }
}

# ---------------------------
# Helpers
# ---------------------------
function Convert-ToSafeName {
    param([string]$Name)

    return ($Name -replace '[\\/:*?"<>|]', '_').Trim()
}

# ---------------------------
# FILE HANDLER
# ---------------------------
function Backup-FileWithLabelHandling {

    param(
        [string]$FileRef,
        [string]$FileName,
        [string]$LocalDir
    )

    $originalLabelId = $null

    try {

        # STEP 1 — Get label
        try {
            $labelInfo = Get-PnPFileSensitivityLabel -Identity $FileRef
            $originalLabelId = $labelInfo.LabelId
        }
        catch {}

        # STEP 2 — Remove label
        if ($originalLabelId) {

            Invoke-WithRetry -Activity "Remove label" -MaxRetry $MaxRetry -Operation {

                Add-PnPFileSensitivityLabel `
                    -Identity $FileRef `
                    -SensitivityLabelId "" `
                    -JustificationText "Backup process" `
                    -AssignmentMethod Privileged
            }
        }

        # STEP 3 — Download
        Invoke-WithRetry -Activity "Download file" -MaxRetry $MaxRetry -Operation {

            Get-PnPFile `
                -Url $FileRef `
                -Path $LocalDir `
                -FileName $FileName `
                -AsFile `
                -Force
        }

        # STEP 4 — Restore label
        if ($originalLabelId) {

            Invoke-WithRetry -Activity "Restore label" -MaxRetry $MaxRetry -Operation {

                Add-PnPFileSensitivityLabel `
                    -Identity $FileRef `
                    -SensitivityLabelId $originalLabelId `
                    -JustificationText "Restore after backup" `
                    -AssignmentMethod Privileged
            }
        }

        return "Success"
    }
    catch {

        # Safety restore
        if ($originalLabelId) {
            try {
                Add-PnPFileSensitivityLabel `
                    -Identity $FileRef `
                    -SensitivityLabelId $originalLabelId `
                    -JustificationText "Recovery" `
                    -AssignmentMethod Privileged
            }
            catch {}
        }

        return $_.Exception.Message
    }
}

# ---------------------------
# Backup single site
# ---------------------------
function Backup-Site {

    param(
        [string]$SiteUrl,
        [string]$SiteFolder
    )

    Write-Info "Connecting to site: $SiteUrl"

    if ($Interactive -or (-not $TenantId)) {

        Connect-PnPOnline -Url $SiteUrl -Interactive
    }
    else {

        Connect-PnPOnline `
            -Url $SiteUrl `
            -Tenant $TenantId `
            -ClientId $ClientId `
            -Thumbprint $Thumbprint
    }

    $dateFolder = Get-Date -Format "yyyy-MM-dd"
    $targetPath = Join-Path $SiteFolder $dateFolder

    $null = New-Item -ItemType Directory -Force -Path $targetPath

    $lists = Get-PnPList | Where-Object {
        $_.BaseTemplate -eq 101 -and -not $_.Hidden
    }

    foreach ($list in $lists) {

        Write-Info "Library: $($list.Title)"

        $items = Get-PnPListItem `
            -List $list `
            -PageSize 1000 `
            -Fields "FileRef","FileLeafRef","FSObjType"

        foreach ($item in $items) {

            if ($item["FSObjType"] -ne 0) {
                continue
            }

            $fileRef  = $item["FileRef"]
            $fileName = $item["FileLeafRef"]

            $relative = $fileRef -replace "^/sites/.+?/", ""

            $localPath = Join-Path $targetPath $relative
            $localDir  = Split-Path $localPath -Parent

            $null = New-Item -ItemType Directory -Force -Path $localDir

            Write-Host "Downloading: $fileRef"

            $result = Backup-FileWithLabelHandling `
                -FileRef $fileRef `
                -FileName $fileName `
                -LocalDir $localDir

            if ($result -ne "Success") {
                Write-Warn "Failed: $fileRef"
                Write-Warn $result
            }
        }
    }
}

# ---------------------------
# MAIN
# ---------------------------

$siteName = Convert-ToSafeName(
    ($SiteUrl.Split('/') | Select-Object -Last 1)
)

if (-not $siteName) {
    $siteName = "SharePointSite"
}

$siteFolder = Join-Path $RootFolder $siteName

$null = New-Item -ItemType Directory -Force -Path $siteFolder

$result = "Success"
$errorMsg = $null

try {

    Backup-Site `
        -SiteUrl $SiteUrl `
        -SiteFolder $siteFolder
}
catch {

    $result = "Failed"
    $errorMsg = $_.Exception.Message

    Write-Err "FAILED: $SiteUrl"
    Write-Err $errorMsg
}

# ---------------------------
# Export summary
# ---------------------------

$logPath = Join-Path $RootFolder "_logs"

$null = New-Item `
    -ItemType Directory `
    -Force `
    -Path $logPath

$csv = Join-Path `
    $logPath `
    ("backup-summary_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")

@(
    [pscustomobject]@{
        SiteUrl = $SiteUrl
        Result  = $result
        Error   = $errorMsg
    }
) | Export-Csv -NoTypeInformation -Path $csv

Write-Info "Done. Summary: $csv"