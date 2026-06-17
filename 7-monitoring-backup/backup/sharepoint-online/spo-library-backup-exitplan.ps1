[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$SiteUrl,

    [Parameter(Mandatory=$true)]
    [string]$LibraryName,

    [Parameter(Mandatory=$true)]
    [string]$FolderPath,

    [Parameter(Mandatory=$true)]
    [string]$RootFolder,

    # App auth
    [Parameter(Mandatory=$true)]
    [string]$TenantId,

    [Parameter(Mandatory=$true)]
    [string]$ClientId,

    [Parameter(Mandatory=$true)]
    [string]$Thumbprint,

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
# Retry helper
# ---------------------------
function Invoke-WithRetry {
    param(
        [scriptblock]$Operation,
        [string]$Activity,
        [int]$MaxRetry = 5
    )

    for ($i=0; $i -le $MaxRetry; $i++) {
        try {
            return & $Operation
        }
        catch {
            $msg = $_.Exception.Message

            if ($i -lt $MaxRetry -and $msg -match '429|thrott|timeout|5\d\d') {
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
# Safe name
# ---------------------------
function Convert-ToSafeName {
    param([string]$Name)
    ($Name -replace '[\\/:*?"<>|]', '_').Trim()
}

# ---------------------------
# FILE PROCESSOR (label cycle)
# ---------------------------
function Process-File {

    param(
        [string]$FileRef,
        [string]$FileName,
        [string]$LocalDir
    )

    $originalLabelId = $null

    try {

        # ---------------------------
        # 1. GET LABEL
        # ---------------------------
        try {
            $label = Get-PnPFileSensitivityLabel -Identity $FileRef
            $originalLabelId = $label.LabelId
        }
        catch {}

        Write-Info "Label: $originalLabelId"

        # ---------------------------
        # 2. TRY REMOVE LABEL (best effort)
        # ---------------------------
        if ($originalLabelId) {

            try {

                Add-PnPFileSensitivityLabel `
                    -Identity $FileRef `
                    -SensitivityLabelId "" `
                    -JustificationText "Backup temporary removal" `
                    -AssignmentMethod Privileged

                Start-Sleep -Seconds 2

                $check = Get-PnPFileSensitivityLabel -Identity $FileRef

                if (-not $check -or -not $check.LabelId) {
                    Write-Info "Label removed"
                }
                else {
                    Write-Warn "Label removal blocked by policy"
                }
            }
            catch {
                Write-Warn "Label removal failed: $($_.Exception.Message)"
            }
        }

        # ---------------------------
        # 3. DOWNLOAD FILE
        # ---------------------------
        Invoke-WithRetry -Activity "Download file" -MaxRetry $MaxRetry -Operation {

            Get-PnPFile `
                -Url $FileRef `
                -Path $LocalDir `
                -FileName $FileName `
                -AsFile `
                -Force
        }

        # ---------------------------
        # 4. RESTORE LABEL
        # ---------------------------
        if ($originalLabelId) {

            try {

                Add-PnPFileSensitivityLabel `
                    -Identity $FileRef `
                    -SensitivityLabelId $originalLabelId `
                    -JustificationText "Restore after backup" `
                    -AssignmentMethod Privileged

                Write-Info "Label restored"
            }
            catch {
                Write-Warn "Label restore failed: $($_.Exception.Message)"
            }
        }

        return "Success"
    }
    catch {
        return $_.Exception.Message
    }
}

# ---------------------------
# MAIN
# ---------------------------
Write-Info "Connecting..."

Connect-PnPOnline `
    -Url $SiteUrl `
    -Tenant $TenantId `
    -ClientId $ClientId `
    -Thumbprint $Thumbprint

$date = Get-Date -Format "yyyy-MM-dd"

$siteName = Convert-ToSafeName ($SiteUrl.Split('/') | Select-Object -Last 1)
$lib      = Convert-ToSafeName $LibraryName
$folder   = Convert-ToSafeName ($FolderPath -replace '/', '_')

$targetRoot = Join-Path $RootFolder "$siteName\$lib\$folder\$date"
New-Item -ItemType Directory -Force -Path $targetRoot | Out-Null

# ---------------------------
# Get files
# ---------------------------
$folderUrl = "$LibraryName/$FolderPath"

Write-Info "Scanning $folderUrl"

$items = Get-PnPFolderItem `
    -FolderSiteRelativeUrl $folderUrl `
    -Recursive `
    -ItemType File

Write-Info "Files: $($items.Count)"

$log = @()

foreach ($item in $items) {

    $fileRef  = $item.ServerRelativeUrl
    $fileName = $item.Name

    Write-Host "`n$fileRef" -ForegroundColor Green

    try {

        $relative = $fileRef -replace '^.+?/sites/[^/]+/', ''
        $localDir = Join-Path $targetRoot (Split-Path $relative -Parent)

        New-Item -ItemType Directory -Force -Path $localDir | Out-Null

        $result = Process-File `
            -FileRef $fileRef `
            -FileName $fileName `
            -LocalDir $localDir

        $log += [pscustomobject]@{
            File   = $fileRef
            Result = $result
        }

        if ($result -eq "Success") {
            Write-Info "OK"
        }
        else {
            Write-Warn $result
        }
    }
    catch {
        Write-Err "FAILED: $fileRef"

        $log += [pscustomobject]@{
            File   = $fileRef
            Result = $_.Exception.Message
        }
    }
}

# ---------------------------
# EXPORT LOG
# ---------------------------
$logPath = Join-Path $RootFolder "_logs"
New-Item -ItemType Directory -Force -Path $logPath | Out-Null

$csv = Join-Path $logPath ("backup_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")

$log | Export-Csv -NoTypeInformation -Path $csv

Write-Info "`nDONE"
Write-Info "Log: $csv"
Write-Info "Backup: $targetRoot"