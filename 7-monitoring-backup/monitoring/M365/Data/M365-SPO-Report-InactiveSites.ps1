[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [String]$SPOAdminURL,
    
    [Parameter(Mandatory=$false)]
    [String]$SPOClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$SPOThumbprint,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOMailFrom,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOMailTo,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOThumbprint,
    
    [Parameter(Mandatory=$false)]
    [String]$Organization
)

# Define inactivity threshold (e.g., 90 days)
$thresholdDate = (Get-Date).AddDays(-90)

# Connect to SharePoint Online
Write-Host "Connecting to SharePoint Online..." -ForegroundColor Yellow
Connect-PnPOnline -Url $SPOAdminURL -ClientId $SPOClientId -Thumbprint $SPOThumbprint -Tenant $Organization

# Get all SharePoint Online sites and filter for inactivity and storage usage >= 0
Write-Host "Retrieving all sites and filtering for inactivity and storage usage >= 0..." -ForegroundColor Yellow
$sites = Get-PnPTenantSite -IncludeOneDriveSites:$false | Where-Object {
    $_.LastContentModifiedDate -lt $thresholdDate -and $_.StorageUsageCurrent -ge 0
}

# Initialize arrays to store inactive Teams and SharePoint sites
$teamsSites = @()
$sharePointSites = @()

foreach ($site in $sites) {
    # Exclude OneDrive sites (my.sharepoint.com)
    if ($site.Url -like "*-my.sharepoint.com*") {
        Write-Host "Skipping OneDrive site: $($site.Url)" -ForegroundColor Yellow
        continue
    }

    Write-Host "Processing site: $($site.Url)"

    try {
        # Get site storage size (in MB)
        $siteStorageSize = $site.StorageUsageCurrent # Directly use StorageUsageCurrent

        # Calculate the number of inactivity days
        $inactivityDays = (Get-Date) - $site.LastContentModifiedDate
        $inactivityDays = [math]::Floor($inactivityDays.TotalDays) # Round down to the nearest whole number

        # Initialize owners and members
        $owners = @()
        $members = @()

        # Check if the site has an associated group
        if ($site.GroupId -ne $null -and $site.GroupId -ne "" -and $site.GroupId -ne "00000000-0000-0000-0000-000000000000") {
            try {
                # Attempt to retrieve group owners
                $owners = Get-PnPMicrosoft365GroupOwners -Identity $site.GroupId | Select-Object -ExpandProperty DisplayName
                # Attempt to retrieve group members
                $members = Get-PnPMicrosoft365GroupMembers -Identity $site.GroupId | Select-Object -ExpandProperty DisplayName
            } catch {
                Write-Host "Error retrieving group information for site: $($site.Url) - $_" -ForegroundColor Red
                $owners = @("Unknown")
                $members = @("Unknown")
            }
        } else {
            Write-Host "No associated group found for site: $($site.Url)" -ForegroundColor Yellow
            $owners = @("None")
            $members = @("None")
        }

        $siteOwner = $owners -join ", " # Combine multiple owners into a single string
        $siteMembers = $members -join ", " # Combine multiple members into a single string

        # Determine if the site is a Teams site or a regular SharePoint site
        if ($site.Template -eq "GROUP#0") {
            # Teams site
            $teamsSites += [PSCustomObject]@{
                SiteName         = $site.Title
                SiteUrl          = $site.Url
                SiteOwner        = $siteOwner
                SiteMembers      = $siteMembers
                LastActivityDate = $site.LastContentModifiedDate
                StorageSizeMB    = $siteStorageSize
                InactivityDays   = $inactivityDays
            }
        } else {
            # SharePoint site
            $sharePointSites += [PSCustomObject]@{
                SiteName         = $site.Title
                SiteUrl          = $site.Url
                SiteOwner        = $siteOwner
                SiteMembers      = $siteMembers
                LastActivityDate = $site.LastContentModifiedDate
                StorageSizeMB    = $siteStorageSize
                InactivityDays   = $inactivityDays
            }
        }
    } catch {
        Write-Host "Error processing site: $($site.Url) - $_" -ForegroundColor Red
        # Include the site with "Unknown" values for owners and members
        $siteOwner = "Unknown"
        $siteMembers = "Unknown"

        # Determine if the site is a Teams site or a regular SharePoint site
        if ($site.Template -eq "GROUP#0") {
            # Teams site
            $teamsSites += [PSCustomObject]@{
                SiteName         = $site.Title
                SiteUrl          = $site.Url
                SiteOwner        = $siteOwner
                SiteMembers      = $siteMembers
                LastActivityDate = $site.LastContentModifiedDate
                StorageSizeMB    = $site.StorageUsageCurrent
                InactivityDays   = $inactivityDays
            }
        } else {
            # SharePoint site
            $sharePointSites += [PSCustomObject]@{
                SiteName         = $site.Title
                SiteUrl          = $site.Url
                SiteOwner        = $siteOwner
                SiteMembers      = $siteMembers
                LastActivityDate = $site.LastContentModifiedDate
                StorageSizeMB    = $site.StorageUsageCurrent
                InactivityDays   = $inactivityDays
            }
        }
    }
}



# Sort the lists by storage size (descending order)
$teamsSites = $teamsSites | Sort-Object -Property StorageSizeMB -Descending
$sharePointSites = $sharePointSites | Sort-Object -Property StorageSizeMB -Descending

# Generate HTML report
Write-Host "Generating HTML report..." -ForegroundColor Yellow
$htmlContent = @"
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
	<h2>Inactive Site Report from Rubicon Cloud Advisor</h2>
	<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" height="10%" alt="Banner Image" class="banner">
	<p>This email contains inactive SharePoint and Teams Sites.</p>
    <h3>Teams Sites inactive for the last 90 days</h3>
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

foreach ($site in $teamsSites) {
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
    <h3>SharePoint Sites inactive for the last 90 days</h3>
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

foreach ($site in $sharePointSites) {
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

# Connect to Microsoft Graph for email operations
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
$params = @{
    message = @{
        subject = "Inactive SharePoint Sites Report"
        body = @{
            contentType = "HTML"
            content = $htmlContent
        }
        toRecipients = @(
            @{
                emailAddress = @{
                    address = $EXOMailTo
                }
            }
        )
    }
}

# Send the email
Write-Verbose "Sending email with the report"
Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

# Disconnect from Microsoft Graph for email operations
Disconnect-MgGraph

Write-Host "Email sent successfully. Report completed."
