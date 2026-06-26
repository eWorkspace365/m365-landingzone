[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SiteUrl,

    [Parameter(Mandatory=$true)]
    [string]$RootFolder,

    [string]$TenantId,
    [string]$ClientId,
    [string]$Thumbprint,
    [switch]$Interactive,

    [int]$LabelTimeoutSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------
# LOGGING
# ---------------------------
function Write-Info($m){ Write-Host $m -ForegroundColor Cyan }
function Write-Warn($m){ Write-Host $m -ForegroundColor Yellow }

# ---------------------------
# SAFE LABEL READ (NO CRASH)
# ---------------------------
function Get-SafeLabel {
    param([string]$FileRef)

    try {
        $label = Get-PnPFileSensitivityLabel -Identity $FileRef

        if ($null -eq $label) { return $null }

        $id = $null
        $name = $null

        if ($label.PSObject.Properties.Name -contains "LabelId") {
            $id = $label.LabelId
        }

        if ($label.PSObject.Properties.Name -contains "DisplayName") {
            $name = $label.DisplayName
        }

        return [pscustomobject]@{
            LabelId = $id
            Name    = $name
        }
    }
    catch {
        return $null
    }
}

# ---------------------------
# WAIT FOR LABEL STATE
# ---------------------------
function Wait-LabelCleared {
    param(
        [string]$FileRef,
        [string]$OriginalLabelId,
        [int]$TimeoutSeconds
    )

    $start = Get-Date

    do {
        $l = Get-SafeLabel -FileRef $FileRef

        if ($null -eq $l -or [string]::IsNullOrWhiteSpace($l.LabelId)) {
            return $true
        }

        Start-Sleep 3

    } while (((Get-Date)-$start).TotalSeconds -lt $TimeoutSeconds)

    return $false
}

# ---------------------------
# PROCESS FILE
# ---------------------------
function Process-File {

    param(
        [string]$FileRef,
        [string]$FileName,
        [string]$LocalDir
    )

    $log = [ordered]@{
        FileRef       = $FileRef
        BeforeLabel   = $null
        AfterLabel    = $null
        FinalLabel    = $null
        Removed       = $false
        Reason        = $null
        DownloadOK    = $false
    }

    Write-Host ""
    Write-Host "===============================" -ForegroundColor DarkGray
    Write-Host "FILE: $FileRef" -ForegroundColor Cyan
    Write-Host "==============================="

    # STEP 1 - BEFORE
    $before = Get-SafeLabel -FileRef $FileRef

    if ($before) {
        $log.BeforeLabel = $before.LabelId
    }

    Write-Host "Before label : $($log.BeforeLabel)" -ForegroundColor Yellow

    # STEP 2 - REMOVE LABEL
    if (-not [string]::IsNullOrWhiteSpace($log.BeforeLabel)) {

        Write-Host "Action       : Removing label..." -ForegroundColor Cyan

        try {
            Set-PnPFileSensitivityLabel `
                -Identity $FileRef `
                -RemoveLabel `
                -JustificationText "Backup process"

            Start-Sleep -Seconds 2

            $after = Get-SafeLabel -FileRef $FileRef

            if ($after) {
                $log.AfterLabel = $after.LabelId
            }

            Write-Host "After remove : $($log.AfterLabel)" -ForegroundColor Magenta
        }
        catch {
            $log.Reason = "Remove failed: $($_.Exception.Message)"
            Write-Warn $log.Reason
        }
    }
    else {
        Write-Host "Action       : No label present" -ForegroundColor Green
    }

    # STEP 3 - FINAL CHECK
    $ok = Wait-LabelCleared `
        -FileRef $FileRef `
        -OriginalLabelId $log.BeforeLabel `
        -TimeoutSeconds $LabelTimeoutSeconds

    $final = Get-SafeLabel -FileRef $FileRef

    if ($final) {
        $log.FinalLabel = $final.LabelId
    }

    Write-Host "Final label  : $($log.FinalLabel)" -ForegroundColor Yellow

    if ([string]::IsNullOrWhiteSpace($log.FinalLabel)) {
        $log.Removed = $true
        Write-Host "Result       : LABEL REMOVED ✓" -ForegroundColor Green
    }
    else {
        $log.Removed = $false

        if ($log.FinalLabel -eq $log.BeforeLabel) {
            $log.Reason = "Policy re-applied label (Purview / mandatory labeling)"
        }
        elseif (-not $log.Reason) {
            $log.Reason = "Label persisted (unknown cause)"
        }

        Write-Host "Result       : LABEL STILL PRESENT ✗" -ForegroundColor Red
        Write-Host "Reason       : $($log.Reason)" -ForegroundColor Red
    }

    # STEP 4 - DOWNLOAD ALWAYS
    try {
        Get-PnPFile `
            -Url $FileRef `
            -Path $LocalDir `
            -FileName $FileName `
            -AsFile `
            -Force

        $log.DownloadOK = $true
    }
    catch {
        $log.Reason = $_.Exception.Message
    }

    return [pscustomobject]$log
}

# ---------------------------
# SITE BACKUP
# ---------------------------
function Run-Backup {

    param($SiteUrl,$RootFolder)

    Write-Info "Connecting to $SiteUrl"

    if ($Interactive -or (-not $TenantId)) {
        Connect-PnPOnline -Url $SiteUrl -Interactive
    }
    else {
        Connect-PnPOnline -Url $SiteUrl -Tenant $TenantId -ClientId $ClientId -Thumbprint $Thumbprint
    }

    $siteName = ($SiteUrl.Split('/') | Select-Object -Last 1) -replace '[\\/:*?"<>|]','_'
    $base = Join-Path $RootFolder $siteName

    New-Item -ItemType Directory -Force -Path $base | Out-Null

    $logFile = Join-Path $RootFolder ("backup_labels_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")

    $results = @()

    $lists = Get-PnPList | Where-Object { $_.BaseTemplate -eq 101 -and -not $_.Hidden }

    foreach ($list in $lists) {

        Write-Info "Library: $($list.Title)"

        $items = Get-PnPListItem -List $list -PageSize 1000 -Fields "FileRef","FileLeafRef","FSObjType"

        foreach ($item in $items) {

            if ($item["FSObjType"] -ne 0) { continue }

            $fileRef = $item["FileRef"]
            $fileName = $item["FileLeafRef"]

            $relative = $fileRef -replace "^/sites/.+?/", ""
            $localDir = Join-Path $base (Split-Path $relative -Parent)

            New-Item -ItemType Directory -Force -Path $localDir | Out-Null

            $res = Process-File `
                -FileRef $fileRef `
                -FileName $fileName `
                -LocalDir $localDir

            $results += $res

            Write-Host "$fileRef | Before=$($res.BeforeLabel) | Final=$($res.FinalLabel) | OK=$($res.Removed)"
        }
    }

    $results | Export-Csv -NoTypeInformation -Path $logFile

    Write-Info "Log saved: $logFile"
}

# ---------------------------
# MAIN
# ---------------------------
Run-Backup -SiteUrl $SiteUrl -RootFolder $RootFolder