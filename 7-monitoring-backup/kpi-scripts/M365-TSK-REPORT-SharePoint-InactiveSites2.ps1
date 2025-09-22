

# Define inactivity threshold (e.g., 90 days)
$thresholdDate = (Get-Date).AddDays(-90)

# Get all SharePoint Online sites
$sites = Get-PnPTenantSite -IncludeOneDriveSites:$false

# Initialize an array to store inactive sites
$inactiveSites = @()

foreach ($site in $sites) {
    # Exclude OneDrive sites (my.sharepoint.com)
    if ($site.Url -like "*-my.sharepoint.com*") {
        Write-Host "Skipping OneDrive site: $($site.Url)" -ForegroundColor Yellow
        continue
    }

    Write-Host "Processing site: $($site.Url)"

    try {
        # Get site usage details
        $siteDetails = Get-PnPTenantSite -Url $site.Url

        # Get the last activity date
        $lastActivityDate = $siteDetails.LastContentModifiedDate

        # Retrieve the group owners using Get-PnPMicrosoft365GroupOwners
        $owners = @()
        if ($site.GroupId -ne $null -and $site.GroupId -ne "" -and $site.GroupId -ne "00000000-0000-0000-0000-000000000000") {
            $owners = Get-PnPMicrosoft365GroupOwners -Identity $site.GroupId | Select-Object -ExpandProperty DisplayName
        }
        $siteOwner = $owners -join ", " # Combine multiple owners into a single string

        # Write the owner(s) to the console
        Write-Host "Owner(s): $siteOwner" -ForegroundColor Cyan

        # Check if the site is inactive
        if ($lastActivityDate -lt $thresholdDate) {
            # Add inactive site to the list
            $inactiveSites += [PSCustomObject]@{
                SiteName         = $site.Title
                SiteUrl          = $site.Url
                SiteOwner        = $siteOwner
                LastActivityDate = $lastActivityDate
            }
        } else {
            Write-Host "Site is active: $($site.Url)" -ForegroundColor Green
        }
    } catch {
        Write-Host "Error processing site: $($site.Url) - $_" -ForegroundColor Red
    }
}

# Export the list of inactive sites to a CSV file
$inactiveSites | Export-Csv -Path "InactiveSitesReport.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Export completed. File saved as InactiveSitesReport.csv"
