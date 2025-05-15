# Define inactivity threshold (e.g., 90 days)
$thresholdDate = (Get-Date).AddDays(-0)

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
            $owners = Get-PnPMicrosoft365GroupOwners -Identity $site.GroupId | Select-Object -ExpandProperty DisplayName
            # Get group members
            $members = Get-PnPMicrosoft365GroupMembers -Identity $site.GroupId | Select-Object -ExpandProperty DisplayName
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

# Save the HTML content to a file (optional)
$outputFile = "InactiveSitesReport.html"
$htmlContent | Out-File -FilePath $outputFile -Encoding utf8
Write-Host "HTML report created: $outputFile" -ForegroundColor Green

