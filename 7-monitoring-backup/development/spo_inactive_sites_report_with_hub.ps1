<#
.SYNOPSIS
    Find inactive SharePoint Online sites and restrict results to sites associated with a specific HubSite.

.DESCRIPTION
    This script follows the same structure and format as the previously provided "inactive sites" script
    but adds a single new filter option: HubSite association. You may provide either a HubSiteId (GUID)
    or a HubSiteUrl; the script will attempt to resolve the hub site's GUID and then return only sites
    whose HubSiteId property matches that GUID.

    Connection methods supported:
      - SPO Management Shell (Connect-SPOService + Get-SPOSite)
      - PnP.PowerShell (Connect-PnPOnline + Get-PnPTenantSite)

.NOTES
    - Requires either Microsoft.Online.SharePoint.PowerShell or PnP.PowerShell modules.
    - Designed to drop-in replace the site-collection-query section of the earlier script while keeping
      the rest of the logic (inactivity calculation, CSV/HTML export, etc.) identical.
#>

[CmdletBinding()]
param(
    # Choose one: "SPO" or "PnP"
    [Parameter(Mandatory=$false)]
    [ValidateSet("SPO","PnP")]
    [string]$ConnectionMethod = "PnP",

    # SPO admin URL for Connect-SPOService (e.g. https://contoso-admin.sharepoint.com)
    [Parameter(Mandatory=$false)]
    [string]$SPOAdminUrl = "https://YOURTENANT-admin.sharepoint.com",

    # Provide either HubSiteId (GUID) OR HubSiteUrl (the script will resolve the ID if you provide a URL)
    # If both are provided, HubSiteId takes precedence.
    [Parameter(Mandatory=$false)]
    [string]$HubSiteId = "",

    [Parameter(Mandatory=$false)]
    [string]$HubSiteUrl = "",

    # Number of days of inactivity threshold (default 90 days)
    [Parameter(Mandatory=$false)]
    [int]$InactivityDays = 90,

    # Output CSV path
    [Parameter(Mandatory=$false)]
    [string]$OutputCsv = ".\inactive-sites-by-hub.csv",

    # Output HTML report (optional)
    [Parameter(Mandatory=$false)]
    [string]$OutputHtml = ".\inactive-sites-by-hub.html",

    # PnP certificate-based auth parameters (used when ConnectionMethod = "PnP")
    [Parameter(Mandatory=$false)]
    [string]$TenantId = "",

    [Parameter(Mandatory=$false)]
    [string]$ClientId = "",

    [Parameter(Mandatory=$false)]
    [string]$CertificateThumbprint = "",

    # If you prefer interactive PnP sign-in (set to $true to use interactive)
    [Parameter(Mandatory=$false)]
    [bool]$PnPInteractive = $false
)

function Ensure-Module {
    param(
        [string]$Name
    )
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Verbose "Module $Name not found. Attempting to install..."
        try {
            Install-Module -Name $Name -Force -Scope CurrentUser -Confirm:$false -ErrorAction Stop
        } catch {
            throw "Could not install module $Name. Run PowerShell as Admin or install the module manually. Error: $_"
        }
    }
}

# Validate hub input
if (-not $HubSiteId -and -not $HubSiteUrl) {
    throw "Provide either -HubSiteId (GUID) or -HubSiteUrl. Example: -HubSiteUrl 'https://contoso.sharepoint.com/sites/ContosoHub'"
}

# Calculate threshold date
$thresholdDate = (Get-Date).AddDays(-1 * $InactivityDays)
Write-Host "Searching for sites associated with hub (HubSiteId or HubSiteUrl) and last modified before $($thresholdDate.ToString('u'))" -ForegroundColor Cyan

$resolvedHubId = $null
$results = @()

if ($ConnectionMethod -eq "SPO") {
    Ensure-Module -Name "Microsoft.Online.SharePoint.PowerShell"

    Write-Host "Connecting using Connect-SPOService to $SPOAdminUrl..." -ForegroundColor Yellow
    try {
        Connect-SPOService -Url $SPOAdminUrl -ErrorAction Stop
    } catch {
        throw "Failed to connect with Connect-SPOService. Ensure you're an SPO administrator and have the module installed. Error: $_"
    }

    # If HubSiteId provided, use it; otherwise try to resolve from URL
    if ($HubSiteId) {
        $resolvedHubId = $HubSiteId
    } elseif ($HubSiteUrl) {
        Write-Host "Resolving HubSiteId from HubSiteUrl (SPO)..." -ForegroundColor Yellow
        try {
            $hubSite = Get-SPOSite -Identity $HubSiteUrl -ErrorAction Stop
            if ($hubSite -and $hubSite.HubSiteId) {
                $resolvedHubId = $hubSite.HubSiteId.ToString()
                Write-Host "Resolved HubSiteId: $resolvedHubId" -ForegroundColor Green
            } else {
                Write-Warning "Could not resolve HubSiteId from Get-SPOSite. Will attempt to resolve from full site list later."
            }
        } catch {
            Write-Warning "Get-SPOSite -Identity failed: $_. Will attempt to resolve from full site list later."
        }
    }

    Write-Host "Retrieving all tenant sites (Get-SPOSite -Limit ALL)..." -ForegroundColor Yellow
    try {
        $allSites = Get-SPOSite -Limit ALL -ErrorAction Stop
    } catch {
        throw "Failed to retrieve sites using Get-SPOSite: $_"
    }

    # If we still don't have resolvedHubId but HubSiteUrl was provided, try to find the hub in the list
    if (-not $resolvedHubId -and $HubSiteUrl) {
        $candidate = $allSites | Where-Object { $_.Url -eq $HubSiteUrl -or $_.Url -like "$HubSiteUrl/*" } | Select-Object -First 1
        if ($candidate -and $candidate.HubSiteId) {
            $resolvedHubId = $candidate.HubSiteId.ToString()
            Write-Host "Resolved HubSiteId from site list: $resolvedHubId" -ForegroundColor Green
        }
    }

    # Filter sites by HubSiteId (property name HubSiteId is expected)
    if ($resolvedHubId) {
        $filtered = $allSites | Where-Object { $_.PSObject.Properties.Match('HubSiteId') -and ($_.HubSiteId -and ($_.HubSiteId.ToString().Trim() -ieq $resolvedHubId.Trim())) }
    } else {
        # Fallback: try to match on other hub-related properties if present (HubSiteUrl/HubSite)
        $filtered = $allSites | Where-Object {
            ( $_.PSObject.Properties.Match('HubSiteUrl') -and ($_.HubSiteUrl -and ($_.HubSiteUrl -ieq $HubSiteUrl))) -or
            ( $_.PSObject.Properties.Match('HubSite') -and ($_.HubSite -and ($_.HubSite -ieq $HubSiteUrl)))
        }
    }

    foreach ($s in $filtered) {
        $results += [PSCustomObject]@{
            Url = $s.Url
            Title = $s.Title
            HubSiteId = if ($s.PSObject.Properties.Match('HubSiteId')) { $s.HubSiteId } else { $null }
            Owner = $s.Owner
            StorageMB = $s.StorageUsageCurrent
            LastContentModifiedDate = $s.LastContentModifiedDate
            Created = if ($s.PSObject.Properties.Match('CreationTime')) { $s.CreationTime } elseif ($s.PSObject.Properties.Match('Created')) { $s.Created } else { $null }
            Source = "SPO"
        }
    }
}
else {
    # PnP path
    Ensure-Module -Name "PnP.PowerShell"
    Import-Module PnP.PowerShell -Force

    if ($PnPInteractive) {
        Write-Host "Connecting interactively with Connect-PnPOnline (browser popup)..." -ForegroundColor Yellow
        try {
            Connect-PnPOnline -Interactive -Scopes "Sites.Read.All","Sites.FullControl.All" -ErrorAction Stop
        } catch {
            throw "Interactive PnP connect failed: $_"
        }
    } else {
        if (-not ($TenantId -and $ClientId -and $CertificateThumbprint)) {
            throw "PnP certificate auth selected but TenantId, ClientId and CertificateThumbprint were not provided. Provide them or set -PnPInteractive to `$true."
        }
        Write-Host "Connecting PnP app-only using certificate (ClientId: $ClientId)..." -ForegroundColor Yellow
        try {
            $tenantRoot = if ($TenantId -match '\.') { $TenantId.Split('\.')[0] } else { $TenantId }
            $tenantRootUrl = "https://$tenantRoot.sharepoint.com"
            Connect-PnPOnline -Tenant $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -Url $tenantRootUrl -ErrorAction Stop
        } catch {
            throw "PnP certificate-based Connect-PnPOnline failed. Ensure the app registration exists and certificate thumbprint is in the current user store. Error: $_"
        }
    }

    # Resolve HubSiteId if needed
    if ($HubSiteId) {
        $resolvedHubId = $HubSiteId
    } elseif ($HubSiteUrl) {
        Write-Host "Resolving HubSiteId from URL using Get-PnPHubSite..." -ForegroundColor Yellow
        try {
            $hub = Get-PnPHubSite -Identity $HubSiteUrl -ErrorAction Stop
            if ($hub -and $hub.SiteId) { $resolvedHubId = $hub.SiteId.ToString() }
            elseif ($hub -and ($hub.Id -or $hub.ID)) { $resolvedHubId = ($hub.Id -or $hub.ID).ToString() }
            if ($resolvedHubId) { Write-Host "Resolved HubSiteId: $resolvedHubId" -ForegroundColor Green }
            else { Write-Warning "Get-PnPHubSite returned no SiteId. Will attempt to find hub from tenant site list." }
        } catch {
            Write-Warning "Get-PnPHubSite failed: $_. Will attempt to find hub from tenant site list." }
    }

    Write-Host "Retrieving tenant sites with Get-PnPTenantSite -Detailed..." -ForegroundColor Yellow
    try {
        $pnpsites = Get-PnPTenantSite -Detailed -IncludeOneDriveSites:$false -ErrorAction Stop
    } catch {
        throw "Failed to retrieve tenant sites via Get-PnPTenantSite: $_"
    }

    if (-not $resolvedHubId -and $HubSiteUrl) {
        $hubCandidate = $pnpsites | Where-Object { $_.Url -eq $HubSiteUrl -or $_.Url -like "$HubSiteUrl/*" } | Select-Object -First 1
        if ($hubCandidate -and $hubCandidate.HubSiteId) {
            $resolvedHubId = $hubCandidate.HubSiteId.ToString()
            Write-Host "Resolved HubSiteId from tenant site list: $resolvedHubId" -ForegroundColor Green
        }
    }

    if ($resolvedHubId) {
        $filtered = $pnpsites | Where-Object { $_.HubSiteId -and ($_.HubSiteId.ToString().Trim() -ieq $resolvedHubId.Trim()) }
    } else {
        # fallback: match by HubSiteUrl property if present
        $filtered = $pnpsites | Where-Object {
            ($_.PSObject.Properties.Match('HubSiteUrl') -and ($_.HubSiteUrl -and ($_.HubSiteUrl -ieq $HubSiteUrl))) -or
            ($_.PSObject.Properties.Match('HubSite') -and ($_.HubSite -and ($_.HubSite -ieq $HubSiteUrl)))
        }
    }

    foreach ($s in $filtered) {
        $results += [PSCustomObject]@{
            Url = $s.Url
            Title = $s.Title
            HubSiteId = if ($s.HubSiteId) { $s.HubSiteId } else { $null }
            Owner = $s.Owner
            StorageMB = if ($s.StorageUsageCurrent) { $s.StorageUsageCurrent } else { $s.Storage }
            LastContentModifiedDate = $s.LastContentModifiedDate
            Created = $s.Created
            Source = "PnP"
        }
    }
}

# If no results
if (-not $results -or $results.Count -eq 0) {
    Write-Warning "No sites found associated with the provided hub. Check HubSiteId/HubSiteUrl and permissions."
    return
}

# Normalize dates
$results = $results | ForEach-Object {
    if (-not $_.LastContentModifiedDate) { $_.LastContentModifiedDate = $_.Created }
    try { $_.LastContentModifiedDate = [datetime]$_.LastContentModifiedDate } catch { $_.LastContentModifiedDate = $null }
    try { $_.Created = [datetime]$_.Created } catch {}
    $_
}

# Filter by inactivity threshold
$inactiveSites = $results | Where-Object { $_.LastContentModifiedDate -and ($_.LastContentModifiedDate -lt $thresholdDate) } |
    Select-Object Url, Title, HubSiteId, Owner, StorageMB, @{Name='LastContentModifiedDate';Expression={[datetime]$_.LastContentModifiedDate}}, @{Name='Created';Expression={[datetime]$_.Created}}, Source

$inactiveCount = $inactiveSites.Count
Write-Host "Found $inactiveCount inactive site(s) associated with hub." -ForegroundColor Green

# Export CSV
try {
    $inactiveSites | Sort-Object LastContentModifiedDate | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -Force
    Write-Host "Exported CSV to: $OutputCsv" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export CSV: $_"
}

# Optional HTML report (keeps same format as original script)
try {
    $html = @"
<html>
<head>
    <meta charset='utf-8' />
    <title>Inactive SharePoint Sites by Hub</title>
    <style>
        body{font-family:Segoe UI, Arial; font-size:12px; padding:12px}
        table{border-collapse:collapse; width:100%}
        th,td{border:1px solid #ddd; padding:6px; text-align:left}
        th{background:#f3f3f3}
    </style>
</head>
<body>
    <h2>Inactive SharePoint Sites Associated to Hub</h2>
    <p>Hub identifier: $([System.Web.HttpUtility]::HtmlEncode( ($HubSiteId) ? $HubSiteId : $HubSiteUrl ))</p>
    <p>Inactivity threshold: last modified before $($thresholdDate.ToString('yyyy-MM-dd HH:mm')) (UTC)</p>
    <table>
        <thead>
            <tr><th>Url</th><th>Title</th><th>HubSiteId</th><th>Owner</th><th>StorageMB</th><th>LastModified</th><th>Created</th><th>Source</th></tr>
        </thead>
        <tbody>
"@

    foreach ($row in $inactiveSites | Sort-Object LastContentModifiedDate) {
        $html += "<tr>"
        $html += "<td><a href='$($row.Url)'>$([System.Web.HttpUtility]::HtmlEncode($row.Url))</a></td>"
        $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($row.Title))</td>"
        $html += "<td>$($row.HubSiteId)</td>"
        $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($row.Owner))</td>"
        $html += "<td>$([string]$row.StorageMB)</td>"
        $html += "<td>$([datetime]$row.LastContentModifiedDate -as [string])</td>"
        $html += "<td>$([datetime]$row.Created -as [string])</td>"
        $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($row.Source))</td>"
        $html += "</tr>`n"
    }

    $html += @"
        </tbody>
    </table>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputHtml -Encoding UTF8 -Force
    Write-Host "Exported HTML report to: $OutputHtml" -ForegroundColor Green
} catch {
    Write-Warning "Failed to build/export HTML report: $_"
}

# Sample
Write-Host "`nSample (oldest 10):" -ForegroundColor Cyan
$inactiveSites | Sort-Object LastContentModifiedDate | Select-Object -First 10 | Format-Table -AutoSize

Write-Host "`nDone." -ForegroundColor Cyan
