# Define inactivity threshold (e.g., 90 days)
$thresholdDate = (Get-Date).AddDays(-90)

# Get all SharePoint Online sites and filter for inactivity and storage usage >= 0
Write-Host "Retrieving all sites and filtering for inactivity and storage usage >= 0..." -ForegroundColor Yellow
$sites = Get-PnPTenantSite -IncludeOneDriveSites:$false | Where-Object {
    $_.LastContentModifiedDate -lt $thresholdDate -and $_.StorageUsage -ge 0
}

# Debug: Display all matching sites in the console
Write-Host "Matching sites (inactive for 90+ days and with storage usage >= 0):" -ForegroundColor Cyan
foreach ($site in $sites) {
    Write-Host "Site Title: $($site.Title)" -ForegroundColor Green
    Write-Host "Site URL: $($site.Url)" -ForegroundColor Green
    Write-Host "Last Activity Date: $($site.LastContentModifiedDate)" -ForegroundColor Green
    Write-Host "Storage Usage (KB): $($site.StorageUsage)" -ForegroundColor Green
    Write-Host "---------------------------------------------"
}

# Initialize an array to store inactive sites
$inactiveSites = @()

foreach ($site in $sites) {
    Write-Host "Processing site: $($site.Url)"

    try {
        # Get site storage size (in MB)
        $siteStorageSize = $site.StorageUsage / 1024 # Convert from KB to MB

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

        # Write the owner(s), member(s), and storage size to the console
        Write-Host "Owner(s): $siteOwner" -ForegroundColor Cyan
        Write-Host "Member(s): $siteMembers" -ForegroundColor Magenta
        Write-Host "Storage Size (MB): $siteStorageSize" -ForegroundColor Blue

        # Add inactive site to the list
        $inactiveSites += [PSCustomObject]@{
            SiteName         = $site.Title
            SiteUrl          = $site.Url
            SiteOwner        = $siteOwner
            SiteMembers      = $siteMembers
            LastActivityDate = $site.LastContentModifiedDate
            StorageSizeMB    = $siteStorageSize
        }
    } catch {
        Write-Host "Error processing site: $($site.Url) - $_" -ForegroundColor Red
    }
}

# Sort the list of inactive sites by storage size (descending order)
$inactiveSites = $inactiveSites | Sort-Object -Property StorageSizeMB -Descending

# Export the list of inactive sites to a CSV file
$inactiveSites | Export-Csv -Path "InactiveSitesReport.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Export completed. File saved as InactiveSitesReport.csv"
