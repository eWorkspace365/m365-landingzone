[CmdletBinding()]
param( 
    [Parameter(Mandatory = $true)]
    [string]$TenantID,

    [Parameter(Mandatory = $true)]
    [string]$SPOAdminURL,  

    [Parameter(Mandatory = $true)]
    [string]$SPOClientId,
    
    [Parameter(Mandatory = $true)]
    [string]$SPOThumbprint
)

# For HTML encoding
Add-Type -AssemblyName System.Web

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

$thresholdDate = (Get-Date).AddDays(-270)
$generated     = Get-Date
$reportPath    = ".\Inactive_SharePoint_Sites_By_Owner.html"
$Title         = "Inactive SharePoint Sites – Grouped by Owner"

# ------------------------------------------------------------
# Connect to SharePoint Online
# ------------------------------------------------------------

Write-Host "Connecting to SharePoint Online..." -ForegroundColor Yellow

Connect-PnPOnline `
    -Url $SPOAdminURL `
    -ClientId $SPOClientId `
    -Thumbprint $SPOThumbprint `
    -Tenant $TenantID `
    -ErrorAction Stop

# ------------------------------------------------------------
# Retrieve inactive sites
# ------------------------------------------------------------

Write-Host "Retrieving SharePoint sites..." -ForegroundColor Yellow

$sites = Get-PnPTenantSite -IncludeOneDriveSites:$false |
Where-Object {
    $_.LastContentModifiedDate -lt $thresholdDate -and
    $_.StorageUsageCurrent -ge 0
}

# ------------------------------------------------------------
# Build site objects
# ------------------------------------------------------------

$inactiveSites = @()

foreach ($site in $sites) {
    try {
        $owners  = @()
        $members = @()

        if ($site.GroupId -and $site.GroupId -notmatch '^0{8}-0{4}-0{4}-0{4}-0{12}$') {
            $owners  = Get-PnPMicrosoft365GroupOwners  -Identity $site.GroupId |
                       Select-Object -ExpandProperty UserPrincipalName

            $members = Get-PnPMicrosoft365GroupMembers -Identity $site.GroupId |
                       Select-Object -ExpandProperty UserPrincipalName
        }

        $inactiveSites += [PSCustomObject]@{
            SiteName         = $site.Title
            SiteUrl          = $site.Url
            Owners           = $owners
            Members          = ($members -join ", ")
            LastActivityDate = $site.LastContentModifiedDate
            StorageMB        = $site.StorageUsageCurrent
            InactiveDays     = [math]::Floor(((Get-Date) - $site.LastContentModifiedDate).TotalDays)
        }
    }
    catch {
        Write-Warning "Failed processing $($site.Url): $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------
# Group by owner
# ------------------------------------------------------------

$sitesByOwner = @{}

foreach ($site in $inactiveSites) {

    $owners = if ($site.Owners.Count -gt 0) {
        $site.Owners
    } else {
        @("⚠ No Owner Assigned")
    }

    foreach ($owner in $owners) {
        if (-not $sitesByOwner.ContainsKey($owner)) {
            $sitesByOwner[$owner] = @()
        }
        $sitesByOwner[$owner] += $site
    }
}

$totalSites = $inactiveSites.Count

# ------------------------------------------------------------
# Build HTML
# ------------------------------------------------------------

$htmlSections = foreach ($owner in ($sitesByOwner.Keys | Sort-Object)) {

    $ownerEnc = [System.Web.HttpUtility]::HtmlEncode($owner)

@"
<h2 class='owner-header'>Owner: $ownerEnc</h2>
<table>
    <thead>
        <tr>
            <th>Site Name</th>
            <th>URL</th>
            <th>Last Activity</th>
            <th>Inactive Days</th>
            <th>Storage (MB)</th>
            <th>Members</th>
        </tr>
    </thead>
    <tbody>
"@

    foreach ($site in $sitesByOwner[$owner] | Sort-Object StorageMB -Descending) {

        $nameEnc    = [System.Web.HttpUtility]::HtmlEncode($site.SiteName)
        $urlEnc     = [System.Web.HttpUtility]::HtmlEncode($site.SiteUrl)
        $membersEnc = [System.Web.HttpUtility]::HtmlEncode($site.Members)

@"
<tr>
    <td>$nameEnc</td>
    <td><a href="$urlEnc" target="_blank">$urlEnc</a></td>
    <td>$($site.LastActivityDate)</td>
    <td>$($site.InactiveDays)</td>
    <td>$($site.StorageMB)</td>
    <td>$membersEnc</td>
</tr>
"@
    }

"</tbody></table>"
}

$html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='utf-8' />
    <title>$Title</title>
    <style>
        body {
            font-family: Consolas, 'Fira Code', 'Segoe UI', monospace;
            background-color: #0b1120;
            color: #e5e7eb;
            margin: 0;
            padding: 2rem;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
        }

        .banner {
            display: flex;
            align-items: center;
            gap: 1.25rem;
            padding: 1rem 1.25rem;
            border-radius: 1rem;
            background: linear-gradient(90deg, #1d4ed8, #38bdf8);
            box-shadow: 0 18px 60px rgba(0,0,0,.65);
            margin-bottom: 2rem;
        }

        .banner-img {
            height: 52px;
            border-radius: .75rem;
            background: white;
            padding: 10px;
        }

        h1 { margin: 0; font-size: 1.6rem; }
        .subtitle { font-size: .9rem; opacity: .95; }

        .owner-header {
            margin-top: 2.5rem;
            margin-bottom: .5rem;
            font-size: 1.1rem;
            color: #38bdf8;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: .85rem;
            background-color: #020617;
            border-radius: .75rem;
            overflow: hidden;
            margin-bottom: 1.5rem;
        }

        th, td {
            padding: .55rem .7rem;
            border-bottom: 1px solid #1f2937;
            vertical-align: top;
        }

        th {
            background-color: #020617;
            text-align: left;
            white-space: nowrap;
        }

        a {
            color: #38bdf8;
            text-decoration: none;
        }

        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class='container'>
        <div class='banner'>
            <img class='banner-img'
                 src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" />
            <div>
                <h1>$Title</h1>
                <div class='subtitle'>
                    Generated on $generated | Total inactive sites: $totalSites
                </div>
            </div>
        </div>

        $($htmlSections -join "`r`n")

    </div>
</body>
</html>
"@

# ------------------------------------------------------------
# Write report
# ------------------------------------------------------------

$html | Set-Content -Path $reportPath -Encoding UTF8

Write-Host "Report generated successfully:" -ForegroundColor Green
Write-Host " $reportPath" -ForegroundColor Cyan
