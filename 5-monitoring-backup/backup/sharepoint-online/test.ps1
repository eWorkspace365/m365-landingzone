[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SiteUrl = "https://klieka.sharepoint.com/sites/External",

    [Parameter(Mandatory=$true)]
    [string]$RootFolder = "Gedeelde documenten/General",

    [Parameter(Mandatory=$false)]
    [string]$TenantId,

    [Parameter(Mandatory=$false)]
    [string]$ClientId,

    [Parameter(Mandatory=$false)]
    [string]$Thumbprint,

    [Parameter(Mandatory=$false)]
    [string]$TargetLabelId = "e37197a7-8e98-40e3-8e28-83c3915754f1",

    [Parameter(Mandatory=$false)]
    [string]$LogPath = ".\label-update-log.csv"
)

# =========================
# CONNECT
# =========================
if ($TenantId -and $ClientId -and $Thumbprint) {
    Connect-PnPOnline `
        -Url $SiteUrl `
        -Tenant $TenantId `
        -ClientId $ClientId `
        -Thumbprint $Thumbprint
}
else {
    Connect-PnPOnline -Url $SiteUrl -DeviceLogin
}

"File;OldLabel;NewLabel;Status;Message" | Out-File $LogPath -Encoding UTF8

function Log {
    param($file,$old,$new,$status,$msg)
    "$file;$old;$new;$status;$msg" | Add-Content $LogPath
}

function Process-Folder {

    param([string]$FolderUrl)

    Write-Host "Scanning: $FolderUrl" -ForegroundColor Cyan

    try {
        $items = Get-PnPFolderItem -FolderSiteRelativeUrl $FolderUrl -ItemType All
    }
    catch {
        Write-Warning "Cannot access folder: $FolderUrl"
        return
    }

    foreach ($item in $items) {

        # Folder recursion
        if ($item.FileSystemObjectType -eq "Folder") {
            Process-Folder -FolderUrl $item.ServerRelativeUrl
            continue
        }

        $fileUrl = $item.ServerRelativeUrl

        try {
            $label = Get-PnPFileSensitivityLabel -Url $fileUrl -ErrorAction SilentlyContinue

            if ($label -and $label.SensitivityLabelId -eq $TargetLabelId) {
                Write-Host "Already correct: $fileUrl" -ForegroundColor Green
                Log $fileUrl $label.SensitivityLabelId $TargetLabelId "Skipped" "Already correct"
                continue
            }

            Write-Host "Updating: $fileUrl" -ForegroundColor Yellow

            Add-PnPFileSensitivityLabel `
                -Identity $fileUrl `
                -SensitivityLabelId $TargetLabelId `
                -JustificationText "Bulk normalization to Everyone"

            Write-Host "Success: $fileUrl" -ForegroundColor Green

            $oldLabel = if ($label) { $label.SensitivityLabelId } else { "None" }

            Log $fileUrl $oldLabel $TargetLabelId "Updated" "OK"
        }
        catch {
            Write-Warning "FAILED: $fileUrl"
            Write-Warning $_.Exception.Message

            Log $fileUrl "N/A" $TargetLabelId "Failed" $_.Exception.Message
        }
    }
}

# =========================
# START
# =========================
Process-Folder -FolderUrl $RootFolder

Disconnect-PnPOnline

Write-Host "DONE - log saved to $LogPath" -ForegroundColor Green