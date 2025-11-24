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

###############################
# Operation → Friendly name map
###############################
$OperationFriendlyNames = @{
    'AccessRequestAccepted'    = 'Accepted access request'
    'SharingInvitationAccepted'= 'Accepted sharing invitation'
    'PermissionLevelAdded'     = 'Added permission level to site collection'
    'SharingInvitationBlocked' = 'Blocked sharing invitation'
    'CompanyLinkCreated'       = 'Created a company shareable link'
    'AccessRequestCreated'     = 'Created access request'
    'AnonymousLinkCreated'     = 'Created an anonymous link'
    'SecureLinkCreated'        = 'Created secure link'
    'SharingInvitationCreated' = 'Created sharing invitation'
    'SecureLinkDeleted'        = 'Deleted secure link'
    'AccessRequestDenied'      = 'Denied access request'
    'CompanyLinkRemoved'       = 'Removed a company shareable link'
    'AnonymousLinkRemoved'     = 'Removed an anonymous link'
    'SharingSet'               = 'Shared file, folder, or site'
    'SharingRevoked'           = 'Unshared file, folder, or site'
    'AccessRequestUpdated'     = 'Updated access request'
    'AnonymousLinkUpdated'     = 'Updated an anonymous link'
    'SharingInvitationUpdated' = 'Updated sharing invitation'
    'CompanyLinkUsed'          = 'Used a company shareable link'
    'AnonymousLinkUsed'        = 'Used an anonymous link'
    'SecureLinkUsed'           = 'Used secure link'
    'AddedToSecureLink'        = 'User added to secure link'
    'RemovedFromSecureLink'    = 'User removed from secure link'
    'SharingInvitationRevoked' = 'Withdrew sharing invitation'
}

#######################################################
# Region 1: Sensitivity labels (via Get-Label / IPPS)
#######################################################
Write-Host "=== Region: Sensitivity labels ===" -ForegroundColor Cyan

if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
    Write-Host "ExchangeOnlineManagement module not found. Install-Module ExchangeOnlineManagement" -ForegroundColor Red
    return
}

if (-not (Get-Module ExchangeOnlineManagement)) {
    Import-Module ExchangeOnlineManagement
}

try {
    Write-Host "Connecting to Compliance (IPPS) to retrieve sensitivity labels..." -ForegroundColor Yellow
    Connect-IPPSSession -AppId $AADClientId -CertificateThumbprint $AADThumbprint -Organization $OrganizationDomain -ShowBanner:$false -ErrorAction Stop | Out-Null

    $sensitiveLabels = Get-Label -ErrorAction Stop | Select-Object DisplayName, Guid
    if ($sensitiveLabels) {
        Save-ObjectToJsonFile -FileName "sharepointonline-sensitivity-labels.json" -ItemToSave $sensitiveLabels
    }
    else {
        Write-Host "No sensitivity labels returned by Get-Label." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "Failed to retrieve sensitivity labels (Get-Label). Continuing script without this JSON..." -ForegroundColor Yellow
    Write-Host $_.Exception.Message -ForegroundColor Yellow
}


#################################################################
# Region 3: SharePoint Online File Sharing Activity (EXO UAL)
#################################################################
Write-Host "=== Region: SharePoint sharing audit (Unified Audit Log) ===" -ForegroundColor Cyan

# Connect to EXO app-only (if not already for IPPS)
try {
    Write-Host "Connecting to Exchange Online (app-only)..." -ForegroundColor Yellow
    Connect-ExchangeOnline -AppId $AADClientId -CertificateThumbPrint $AADThumbprint -Organization $OrganizationDomain -ShowBanner:$false -ErrorAction Stop
}
catch {
    Write-Host "Failed to connect to Exchange Online:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    return
}

# Date range: last month + current month
$today               = Get-Date
$startOfCurrentMonth = Get-Date -Year $today.Year -Month $today.Month -Day 1 -Hour 0 -Minute 0 -Second 0
$startOfLastMonth    = $startOfCurrentMonth.AddMonths(-1)

$StartDate = $startOfLastMonth
$EndDate   = $startOfCurrentMonth.AddMonths(1).AddSeconds(-1)  # end of current month

Write-Host "Retrieving SharePointSharingOperation events from $StartDate to $EndDate..." -ForegroundColor Cyan

# Output CSV path in script folder
$basePath = $PSScriptRoot
if (-not $basePath) {
    $basePath = (Get-Location).Path
}
$csvFile = Join-Path $basePath ("exchangeonline-sharingreport_{0}.csv" -f (Get-Date -format "yyyy-MMM-dd-ddd HH-mm tt"))

if (Test-Path $csvFile) {
    Remove-Item $csvFile -Force -ErrorAction SilentlyContinue
}

# Collect audit data (chunk per day)
$AuditReport  = [System.Collections.Generic.List[Object]]::new()
$CurrentStart = $StartDate

while ($CurrentStart -lt $EndDate) {
    $CurrentEnd = $CurrentStart.AddDays(1)
    if ($CurrentEnd -gt $EndDate) {
        $CurrentEnd = $EndDate
    }

    Write-Host "  -> Querying $CurrentStart to $CurrentEnd" -ForegroundColor DarkGray

    $results = Search-UnifiedAuditLog `
        -StartDate $CurrentStart `
        -EndDate   $CurrentEnd `
        -RecordType SharePointSharingOperation `
        -Formatted `
        -ResultSize 5000

    if ($results.Count -eq 5000) {
        Write-Host "    WARNING: 5000 events in this day; results might be truncated. Consider smaller chunks." -ForegroundColor Yellow
    }

    foreach ($rec in $results) {

        # Parse audit data JSON
        try {
            $ad = $rec.AuditData | ConvertFrom-Json
        }
        catch {
            Write-Host "    Failed to parse AuditData for entry at $($rec.CreationDate)" -ForegroundColor Yellow
            continue
        }

        $operation = $ad.Operation

        # Only known sharing-related operations
        if ($OperationFriendlyNames.ContainsKey($operation) -eq $false) {
            continue
        }

        # Only SharePoint / OneDrive workloads
        if ($ad.Workload -notin @('SharePoint','OneDrive')) {
            continue
        }

        # Exclude SharePoint Embedded / contentstorage
        if ($ad.ObjectId -like "*CSP_*" -or $ad.ObjectId -like "*contentstorage*") {
            continue
        }

        # Exclude app@sharepoint (system actions)
        if ($ad.UserId -eq 'app@sharepoint') {
            continue
        }

        # Exclude Limited Access System Group
        if ($ad.TargetUserOrGroupName -like 'Limited Access System Group*') {
            continue
        }

        # ---- Sender & recipient ----
        $userId     = $ad.UserId
        $rawTarget  = $ad.TargetUserOrGroupName
        $targetType = $ad.TargetUserOrGroupType

        # Anonymous link special name
        if ($operation -eq 'AnonymousLinkCreated' -and [string]::IsNullOrWhiteSpace($rawTarget)) {
            $targetName = 'Anyone with the link'
        }
        else {
            $targetName = $rawTarget
        }

        # Only count activities where TargetUserOrGroup is NOT empty
        if ([string]::IsNullOrWhiteSpace($targetName)) {
            continue
        }

        # B2B guest → extract external domain
        if ($targetName -like '*#EXT#*') {
            # something_like tenant#EXT#_externaldomain#...
            $parts = $targetName.Split("_")
            if ($parts.Count -gt 1) {
                $TargetDomain = $parts[1].Split("#")[0].ToLower()
            }
            else {
                $TargetDomain = Get-DomainFromPrincipal -Principal $targetName
            }
        }
        else {
            $TargetDomain = Get-DomainFromPrincipal -Principal $targetName
        }

        if (-not $TargetDomain) {
            if ($targetName -eq 'Anyone with the link') {
                $TargetDomain = 'anonymous'
            }
            else {
                $TargetDomain = 'unknown'
            }
        }

        # >>> NEW: exclude events where TargetDomain = 'unknown' <<<
        if ($TargetDomain -eq 'unknown') {
            continue
        }

        $UserDomain = Get-DomainFromPrincipal -Principal $userId

        # ---- Internal vs External (domain rule) ----
        # If sender and recipient have the same domainname then it is internal. All other is external.
        $SharingType = 'External'
        if ($UserDomain -and $TargetDomain -and ($UserDomain -eq $TargetDomain)) {
            $SharingType = 'Internal'
        }

        # ---- Friendly operation name ----
        $FriendlyOperation = $OperationFriendlyNames[$operation]

        # ---- Build record ----
        $record = [PSCustomObject][Ordered]@{
            CreatedDateTime     = Get-Date $rec.CreationDate -Format 'dd-MMM-yyyy HH:mm:ss'
            Operation           = $operation
            FriendlyOperation   = $FriendlyOperation
            Workload            = $ad.Workload
            UserId              = $userId
            UserDomain          = $UserDomain
            TargetUserOrGroup   = $targetName
            TargetType          = $targetType
            TargetDomain        = $TargetDomain
            SharingType         = $SharingType     # Internal / External
            ObjectId            = $ad.ObjectId
            SiteUrl             = $ad.SiteURL
            ItemType            = $ad.ItemType
            SourceFileName      = $ad.SourceFileName
            SourceRelativeUrl   = $ad.SourceRelativeUrl
        }

        # Add to in-memory report
        $AuditReport.Add($record)

        # Append to CSV
        $record |
            Select-Object CreatedDateTime, Operation, FriendlyOperation, Workload,
                          UserId, UserDomain, TargetUserOrGroup, TargetType,
                          TargetDomain, SharingType, ObjectId, SiteUrl,
                          ItemType, SourceFileName, SourceRelativeUrl |
            Export-Csv -Path $csvFile -NoTypeInformation -Append
    }

    $CurrentStart = $CurrentEnd
}

Disconnect-ExchangeOnline -Confirm:$false

if (-not $AuditReport -or $AuditReport.Count -eq 0) {
    Write-Host "No relevant sharing events found for the selected period." -ForegroundColor Yellow
    return
}

###############################
# Summary
###############################
$internalCount = ($AuditReport | Where-Object { $_.SharingType -eq 'Internal' }).Count
$externalCount = ($AuditReport | Where-Object { $_.SharingType -eq 'External' }).Count
$totalCount    = $AuditReport.Count

Write-Host ""
Write-Host "=== Sharing Summary ($($StartDate.ToShortDateString()) - $($EndDate.ToShortDateString())) ===" -ForegroundColor Cyan
Write-Host "Total sharing events : $totalCount"
Write-Host "Internal sharing     : $internalCount"
Write-Host "External sharing     : $externalCount"

Write-Host "`nTop target domains (by share count):" -ForegroundColor Cyan
$AuditReport |
    Group-Object TargetDomain -NoElement |
    Sort-Object Count -Descending |
    Format-Table Name, Count

###############################
# JSON export (for automation / HC)
###############################
Save-ObjectToJsonFile -FileName "sharepointonline-sites-sharingactivity.json" -ItemToSave $AuditReport
