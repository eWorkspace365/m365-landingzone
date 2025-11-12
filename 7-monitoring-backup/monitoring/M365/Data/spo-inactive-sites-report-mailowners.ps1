[CmdletBinding()]
param( 
    [Parameter(Mandatory=$true)]
    [String]$TenantID,

    [Parameter(Mandatory=$false)]
    [String]$SPOAdminURL,  
	
    [Parameter(Mandatory=$false)]
    [String]$SPOClientId,
    
    [Parameter(Mandatory=$true)]
    [String]$SPOThumbprint,
    
    [Parameter(Mandatory=$true)]
    [String]$EXOMailFrom,
    
    [Parameter(Mandatory=$true)]
    [String]$EXOMailTo,
    
    [Parameter(Mandatory=$true)]
    [String]$EXOClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOThumbprint
)


# Define inactivity threshold (e.g., 90 days)
$thresholdDate = (Get-Date).AddDays(-2)


Connect-PnPOnline $SPOAdminURL -ClientId $SPOClientId -Thumbprint $SPOThumbprint -Tenant $TenantId -ErrorAction Stop



# Get all SharePoint Online sites and filter for inactivity and storage usage >= 0
Write-Host "Retrieving all sites and filtering for inactivity and storage usage >= 0..." -ForegroundColor Yellow
$sites = Get-PnPTenantSite -IncludeOneDriveSites:$false | Where-Object {
    $_.LastContentModifiedDate -lt $thresholdDate -and $_.StorageUsageCurrent -ge 0
}

# Debug: Display all matching sites in the console
Write-Host "Matching sites (inactive for 90+ days and with storage usage >= 0):" -ForegroundColor Cyan
foreach ($site in $sites) {
    Write-Host "Site Title: $($site.Title)" -ForegroundColor Green
    Write-Host "Site URL: $($site.Url)" -ForegroundColor Green
    Write-Host "Last Activity Date: $($site.LastContentModifiedDate)" -ForegroundColor Green
    Write-Host "Storage Usage Current (MB): $($site.StorageUsageCurrent)" -ForegroundColor Yellow
    Write-Host "---------------------------------------------"
}

# Initialize an array to store inactive sites
$inactiveSites = @()

foreach ($site in $sites) {
    Write-Host "Processing site: $($site.Url)"

    try {
        # Get site storage size (in MB)
        $siteStorageSize = $site.StorageUsageCurrent # Directly use StorageUsageCurrent

        # Calculate the number of inactivity days
        $inactivityDays = (Get-Date) - $site.LastContentModifiedDate
        $inactivityDays = [math]::Floor($inactivityDays.TotalDays) # Round down to the nearest whole number

        # Retrieve the group owners using Get-PnPMicrosoft365GroupOwners
        $owners = @()
        $members = @()
        if ($site.GroupId -ne $null -and $site.GroupId -ne "" -and $site.GroupId -ne "00000000-0000-0000-0000-000000000000") {
            # Get group owners
            $owners = Get-PnPMicrosoft365GroupOwners -Identity $site.GroupId | Select-Object -ExpandProperty UserPrincipalName
            # Get group members
            $members = Get-PnPMicrosoft365GroupMembers -Identity $site.GroupId | Select-Object -ExpandProperty UserPrincipalName
        }
        $siteOwner = $owners -join ", " # Combine multiple owners into a single string
        $siteMembers = $members -join ", " # Combine multiple members into a single string

        # Add inactive site to the list
        $inactiveSites += [PSCustomObject]@{
            SiteName         = $site.Title
            SiteUrl          = $site.Url
            SiteOwner        = $siteOwner
            SiteMembers      = $siteMembers
            LastActivityDate = $site.LastContentModifiedDate
            StorageSizeMB    = $siteStorageSize
            InactivityDays   = $inactivityDays
        }
    } catch {
        Write-Host "Error processing site: $($site.Url) - $_" -ForegroundColor Red
    }
}

# Sort the list of inactive sites by storage size (descending order)
$inactiveSites = $inactiveSites | Sort-Object -Property StorageSizeMB -Descending

# Generate HTML report
Write-Host "Generating HTML report..." -ForegroundColor Yellow
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Inactive SharePoint Sites Report</title>
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #F39C12;
        }
    </style>
</head>
<body>
    <h1>Inactive SharePoint Sites Report</h1>
    <h2>Sites inactive for the last 90 days</h2>
    <table>
        <tr>
            <th>Site Name</th>
            <th>Site URL</th>
            <th>Site Owner(s)</th>
            <th>Site Members</th>
            <th>Last Activity Date</th>
            <th>Storage Size (MB)</th>
            <th>Inactivity Days</th>
        </tr>
"@

foreach ($site in $inactiveSites) {
    $htmlContent += @"
        <tr>
            <td>$($site.SiteName)</td>
            <td><a href='$($site.SiteUrl)' target='_blank'>$($site.SiteUrl)</a></td>
            <td>$($site.SiteOwner)</td>
            <td>$($site.SiteMembers)</td>
            <td>$($site.LastActivityDate)</td>
            <td>$($site.StorageSizeMB)</td>
            <td>$($site.InactivityDays)</td>
        </tr>
"@
}

$htmlContent += @"
    </table>
</body>
</html>
"@

# EMAIL PART VIA GRAPH

# Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantID -CertificateThumbprint $EXOThumbprint

# 1) Send summary report to central mailbox / admin
$summaryMessage = @{
    subject = "Inactive SharePoint Sites Report"
    body    = @{
        contentType = "HTML"
        content     = $htmlContent
    }
    toRecipients = @(
        @{
            emailAddress = @{
                address = $EXOMailTo
            }
        }
    )
}

Write-Host "Sending summary report email to $EXOMailTo..." -ForegroundColor Yellow
Send-MgUserMail -UserId $EXOMailFrom -Message $summaryMessage
Write-Host "Summary report email sent." -ForegroundColor Green

# Helper: resolve email(s) from owner user objects
function Get-EmailsFromOwnerObjects {
    param(
        [Parameter(Mandatory)]
        [array]$Owners
    )
    $emails = @()

    foreach ($o in $Owners) {
        $addr = $null

        # 1) Prefer Mail
        if ($o.PSObject.Properties.Match('Mail').Count -gt 0 -and $o.Mail) {
            $addr = $o.Mail
        }
        # 2) Fallback: UPN
        elseif ($o.PSObject.Properties.Match('UserPrincipalName').Count -gt 0 -and $o.UserPrincipalName) {
            $addr = $o.UserPrincipalName
        }
        # 3) Last resort: query Graph by Id (if available)
        elseif ($o.PSObject.Properties.Match('Id').Count -gt 0 -and $o.Id) {
            try {
                $gu = Get-MgUser -UserId $o.Id -Property Mail,UserPrincipalName -ErrorAction Stop
                if ($gu -and $gu.Mail) { $addr = $gu.Mail }
                elseif ($gu -and $gu.UserPrincipalName) { $addr = $gu.UserPrincipalName }
            } catch {
                Write-Verbose "Get-MgUser lookup failed for owner Id $($o.Id): $($_.Exception.Message)"
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($addr)) {
            $emails += $addr
        }
    }

    $emails | Sort-Object -Unique
}

# 2) Send per-site notification to site owners (extracting email from user objects)
foreach ($site in $inactiveSites) {
    try {
        Write-Host "Preparing recipients for site: $($site.SiteUrl)" -ForegroundColor Cyan

        # Start with any pre-filled addresses on the object (optional)
        $emails = @()
        if ($site.PSObject.Properties.Match('SiteOwnerEmails').Count -gt 0 -and
            -not [string]::IsNullOrWhiteSpace($site.SiteOwnerEmails)) {
            $emails = ($site.SiteOwnerEmails -split ',').ForEach({ $_.Trim() }) | Where-Object { $_ }
        }

        # If still nothing, resolve via the Group owners and extract emails from the *user objects*
        if ($emails.Count -eq 0) {
            # Find the matching tenant site to get GroupId
            $tenantSite = $sites | Where-Object { $_.Url -eq $site.SiteUrl }
            $groupId = $tenantSite.GroupId

            if ($groupId -and $groupId -notmatch '^0{8}-0{4}-0{4}-0{4}-0{12}$') {
                try {
                    # Get owner *objects* with Id/Mail/UPN (avoid -ExpandProperty)
                    $ownerObjs = Get-PnPMicrosoft365GroupOwners -Identity $groupId |
                                 Select-Object Id, DisplayName, Mail, UserPrincipalName

                    $emails = Get-EmailsFromOwnerObjects -Owners $ownerObjs
                } catch {
                    Write-Warning "Failed to resolve owners for '$($site.SiteName)' (GroupId: $groupId): $($_.Exception.Message)"
                }
            }
        }

        # Fallback to central mailbox if still no addresses
        $usingFallback = $false
        if ($emails.Count -eq 0) {
            $usingFallback = $true
            $emails = @($EXOMailTo)
            Write-Host "No owner emails found for '$($site.SiteName)'. Using fallback: $EXOMailTo" -ForegroundColor DarkYellow
        }

        # Build Graph recipients
        $toRecipients = @()
        foreach ($addr in $emails) {
            if (-not [string]::IsNullOrWhiteSpace($addr)) {
                $toRecipients += @{ emailAddress = @{ address = $addr.Trim() } }
            }
        }

        if ($toRecipients.Count -eq 0) {
            Write-Host "Skipping '$($site.SiteName)' — no valid recipient addresses." -ForegroundColor DarkGray
            continue
        }

        # Owner email body
        $ownerMailBody = @"
<p>Beste site-eigenaar,</p>
<p>De volgende SharePoint-site is al geruime tijd niet actief geweest:</p>
<ul>
    <li><strong>Site naam:</strong> $($site.SiteName)</li>
    <li><strong>URL:</strong> <a href='$($site.SiteUrl)'>$($site.SiteUrl)</a></li>
    <li><strong>Laatste activiteit:</strong> $($site.LastActivityDate)</li>
    <li><strong>Opslaggebruik (MB):</strong> $($site.StorageSizeMB)</li>
    <li><strong>Inactiviteitsdagen:</strong> $($site.InactivityDays)</li>
</ul>
<p>Controleer of deze site nog nodig is. Als dat niet het geval is, kun je de inhoud archiveren of de site laten verwijderen volgens het beleid van de organisatie.</p>
<p>Met vriendelijke groet,<br/>Functioneel Beheer</p>
"@

        $ownerMessage = @{
            subject = "Inactive SharePoint site: $($site.SiteName)"
            body    = @{
                contentType = "HTML"
                content     = $ownerMailBody
            }
            toRecipients = $toRecipients
        }

        $recipStr = ($emails -join '; ')
        if ($usingFallback) {
            Write-Host "Sending (FALLBACK) notification for '$($site.SiteName)' to $recipStr" -ForegroundColor Yellow
        } else {
            Write-Host "Sending owner notification for '$($site.SiteName)' to $recipStr" -ForegroundColor Green
        }

        Send-MgUserMail -UserId $EXOMailFrom -Message $ownerMessage -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to send for '$($site.SiteName)' ($($site.SiteUrl)): $($_.Exception.Message)"
        continue
    }
}
