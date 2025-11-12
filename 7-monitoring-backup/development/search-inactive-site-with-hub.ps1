<#
.SYNOPSIS
    Find inactive SharePoint Online sites that are associated with a specific HubSite and export results.

.DESCRIPTION
    Connects to SharePoint Online using SPO module or PnP.PowerShell
    and returns sites whose HubSiteId matches the provided hub site (by ID or URL),
    then filters those sites by LastContentModifiedDate older than the inactivity threshold.

.NOTES
    - Requires PnP.PowerShell module for PnP path, or Microsoft.Online.SharePoint.PowerShell for SPO path.
    - For automation, PnP certificate-based auth is supported.
#>

[CmdletBinding()]
param(
    # Choose connection method: "SPO" (Connect-SPOService) or "PnP" (Connect-PnPOnline)
    [Parameter(Mandatory=$false)]
    [ValidateSet("SPO","PnP")]
    [string]$ConnectionMethod = "PnP",

    # SPO admin URL (when using SPO method)
    [Parameter(Mandatory=$false)]
    [string]$SPOAdminUrl = "https://YOURTENANT-admin.sharepoint.com",

    # Provide either HubSiteId (GUID) OR HubSiteUrl (e.g. https://contoso.sharepoint.com/sites/ContosoHub)
    # If both are provided, HubSiteId takes precedence.
    [Parameter(Mandatory=$false)]
    [string]$HubSiteId = "",

    [Parameter(Mandatory=$false)]
    [string]$HubSiteUrl = "",

    # Number of days of inactivity (default 90)
    [Parameter(Mandatory=$false)]
    [int]$InactivityDays = 90,

    # Output paths
    [Parameter(Mandatory=$false)]
    [string]$OutputCsv = ".\inactive-sites-by-hub.csv",

    [Parameter(Mandatory=$false)]
    [string]$OutputHtml = ".\inactive-sites-by-hub.html",

    # PnP certificate-based auth parameters (if using PnP non-interactive)
    [Parameter(Mandatory=$false)]
    [string]$TenantId = "",

    [Parameter(Mandatory=$false)]
    [string]$ClientId = "",

    [Parameter(Mandatory=$false)]
    [string]$CertificateThumbprint = "",

    # Use interactive PnP sign-in if set to $true
    [Parameter(Mandatory=$false)]
    [bool]$PnPInteractive = $false
)

function Ensure-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Verbose "Module $Name not found. Attempting to install..."
        try {
            Install-Module -Name $Name -Force -Scope CurrentUser -Confirm:$false -ErrorAction Stop
        } catch {
            throw "Could not install module $Name. Run PowerShell as Admin or install the module manually. Error: $_"
        }
    }
}

# Validate inputs
if (-not $HubSiteId -and -not $HubSiteUrl) {
    throw "Provide either -HubSiteId (GUID) or -HubSiteUrl. Example: -HubSiteUrl 'https://contoso.sharepoint.com/sites/ContosoHub'"
}

# Compute inactivity threshold
$thresholdDate = (Get-Date).AddDays(-1 * $InactivityDays)
Write-Host "Inactivity threshold: sites last modified before $($thresholdDate.ToString('u'))" -ForegroundColor Cyan

# Helper: try to convert HubSiteId to GUID, otherwise leave as string
$resolvedHubId = $null

# Results accumulator
$results = @()

if ($ConnectionMethod -eq "SPO") {
    Ensure-Module -Name "Microsoft.Online.SharePoint.PowerShell"
    Write-Host "Connecting using Connect-SPOService to $SPOAdminUrl..." -ForegroundColor Yellow
    try {
        Connect-SPOService -Url $SPOAdminUrl -ErrorAction Stop
    } catch {
        throw "Failed to connect with Connect-SPOService. Ensure you're an SPO administrator and have the module installed. Error: $_"
    }

    # If user supplied HubSiteUrl, attempt to resolve HubSiteId by getting that single site
    if ($HubSiteUrl -and -not $HubSiteId) {
        Write-Host "Resolving HubSiteId from HubSiteUrl (SPO)..." -ForegroundColor Yellow
        try {
            $hubSite = Get-SPOSite -Identity $HubSiteUrl -ErrorAction Stop
            if ($hubSite -and $hubSite.HubSiteId) {
                $resolvedHubId = $hubSite.HubSiteId.ToString()
                Write-Host "Resolved HubSiteId: $resolvedHubId" -ForegroundColor Green
            } else {
                Write-Warning "Could not resolve hub site or HubSiteId property is empty. Proceeding to client-side resolution later."
            }
        } catch {
            Write-Warning "Error resolving hub site: $_. Proceeding to fetch all sites and resolve client-side."
        }
    } elseif ($HubSiteId) {
        $resolvedHubId = $HubSiteId
    }

    Write-Host "Retrieving all tenant sites (SPO)..." -ForegroundColor Yellow
    try {
        # Get-SPOSite does not reliably provide all extended properties in some tenants; get all and filter client-side
        $allSites = Get-SPOSite -Limit ALL -ErrorAction Stop
    } catch {
        throw "Failed to retrieve sites using Get-SPOSite: $_"
    }

    # If resolvedHubId is still null but HubSiteUrl was provided, try to find the site matching that URL and get its HubSiteId property
    if (-not $resolvedHubId -and $HubSiteUrl) {
        $candidate = $allSites | Where-Object { $_.Url -eq $HubSiteUrl -or $_.Url -like "$HubSiteUrl/*" } | Select-Object -First 1
        if ($candidate -and $candidate.HubSiteId) {
            $resolvedHubId = $candidate.HubSiteId.ToString()
            Write-Host "Resolved HubSiteId from site list: $resolvedHubId" -ForegroundColor Green
        }
    }

    if (-not $resolvedHubId) {
        Write-Warning "HubSiteId could not be resolved explicitly. If the hub site exists, we'll try to filter by the HubSiteId property on retrieved sites (if present)."
    } else {
        Write-Host "Filtering sites where HubSiteId equals $resolvedHubId" -ForegroundColor Cyan
    }

    # Filter sites that are associated with the hub (HubSiteId matches) or have HubSiteUrl (some versions)
    $filtered = @()
    foreach ($s in $allSites) {
        # Normalize hub id property if present
        $siteHubId = $null
        if ($s.PSObject.Properties.Match('HubSiteId')) {
            $siteHubId = $s.HubSiteId
        } elseif ($s.PSObject.Properties.Match('HubSite')) {
            # older or different property name fallback
            $siteHubId = $s.HubSite
        }

        $siteHubIdString = if ($siteHubId) { $siteHubId.ToString().Trim() } else { "" }

        $isMatch = $false
        if ($resolvedHubId) {
            # compare GUIDs/strings case-insensitively
            if ($siteHubIdString -and ($siteHubIdString -ieq $resolvedHubId)) {
                $isMatch = $true
            }
        } else {
            # If user provided HubSiteUrl but couldn't resolve ID, try to match on a property containing the URL or match by recognized pattern
            if ($HubSiteUrl) {
                # Some site objects expose 'HubSiteUrl' or 'HubSite' or similar; check them
                if ($s.PSObject.Properties.Match('HubSiteUrl')) {
                    if ($s.HubSiteUrl -and ($s.HubSiteUrl -ieq $HubSiteUrl)) { $isMatch = $true }
                }
                # Also match if a site has the hub site URL as part of a property e.g. s.HubSite
                if (-not $isMatch -and $s.PSObject.Properties.Match('HubSite')) {
                    if ($s.HubSite -and $s.HubSite -ieq $HubSiteUrl) { $isMatch = $true }
                }
            }
        }

        if ($isMatch) {
            $filtered += $s
        }
    }

    # Build normalized results
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
        Write-Host "Connecting interactively with Connect-PnPOnline..." -ForegroundColor Yellow
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
            # Note: use the tenant root url as Connect-PnPOnline -Url param
            $tenantRootUrl = "https://$($TenantId -replace '\.onmicrosoft\.com$','').sharepoint.com"
            Connect-PnPOnline -Tenant $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -Url $tenantRootUrl -ErrorAction Stop
        } catch {
            throw "PnP certificate-based Connect-PnPOnline failed. Ensure the app registration exists and certificate thumbprint is in the current user store. Error: $_"
        }
    }

    # Resolve HubSiteId if user provided HubSiteUrl
    if ($HubSiteId) {
        $resolvedHubId = $HubSiteId
    } elseif ($HubSiteUrl) {
        Write-Host "Resolving HubSiteId from URL using PnP..." -ForegroundColor Yellow
        try {
            # Use Get-PnPHubSite to resolve; it accepts identity of url or id
            $hub = Get-PnPHubSite -Identity $HubSiteUrl -ErrorAction Stop
            if ($hub -and $hub.SiteId) {
                # Get-PnPHubSite returns SiteId (GUID) in SiteId property; some returns Id or ID - normalize
                $resolvedHubId = $hub.SiteId.ToString()
            } elseif ($hub -and ($hub.ID -or $hub.Id)) {
                $resolvedHubId = if ($hub.SiteId) { $hub.SiteId.ToString() } elseif ($hub.Id) { $hub.Id.ToString() } else { $null }
            }
            if ($resolvedHubId) {
                Write-Host "Resolved HubSiteId: $resolvedHubId" -ForegroundColor Green
            } else {
                Write-Warning "Could not resolve HubSiteId from Get-PnPHubSite result; will attempt to find by URL from full site list."
            }
        } catch {
            Write-Warning "Get-PnPHubSite failed to resolve: $_. Will fallback to scanning tenant sites."
        }
    }

    Write-Host "Retrieving tenant sites with Get-PnPTenantSite (detailed)..." -ForegroundColor Yellow
    try {
        # Get all tenant sites (Detailed returns HubSiteId and LastContentModifiedDate)
        $pnpsites = Get-PnPTenantSite -Detailed -IncludeOneDriveSites:$false -ErrorAction Stop
    } catch {
        throw "Failed to retrieve tenant sites via Get-PnPTenantSite: $_"
    }

    # If resolvedHubId is still null but HubSiteUrl provided, try to resolve by matching Url
    if (-not $resolvedHubId -and $HubSiteUrl) {
        $hubCandidate = $pnpsites | Where-Object { $_.Url -eq $HubSiteUrl -or $_.Url -like "$HubSiteUrl/*" } | Select-Object -First 1
        if ($hubCandidate -and $hubCandidate.HubSiteId) {
            $resolvedHubId = $hubCandidate.HubSiteId.ToString()
            Write-Host "Resolved HubSiteId from tenant site list: $resolvedHubId" -ForegroundColor Green
        }
    }

    # Filter tenant sites where HubSiteId equals resolvedHubId (or where HubSiteId property matches)
    if ($resolvedHubId) {
        $filtered = $pnpsites | Where-Object { $_.HubSiteId -and ($_.HubSiteId.ToString().Trim() -ieq $resolvedHubId.Trim()) }
    } else {
        # fallback: if user provided HubSiteUrl and we couldn't find ID, try to match HubSiteUrl property if present
        if ($HubSiteUrl) {
            $filtered = $pnpsites | Where-Object {
                ($_.PSObject.Properties.Match('HubSiteUrl') -and ($_.HubSiteUrl -and ($_.HubSiteUrl -ieq $HubSiteUrl)))
                -or
                ($_.PSObject.Properties.Match('HubSite') -and ($_.HubSite -and ($_.HubSite -ieq $HubSiteUrl)))
            }
        } else {
            $filtered = @()
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

# If none found
if (-not $results -or $results.Count -eq 0) {
    Write-Warning "No sites found associated with the provided hub. Check HubSiteId/HubSiteUrl and permissions."
    return
}

# Normalize dates: if LastContentModifiedDate null -> use Created
$results = $results | ForEach-Object {
    if (-not $_.LastContentModifiedDate) { $_.LastContentModifiedDate = $_.Created }
    # Ensure DateTime type
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

# Optional HTML report
try {
    $htmlHeader = @"
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

    $htmlBody = ""
    foreach ($row in $inactiveSites | Sort-Object LastContentModifiedDate) {
        $htmlBody += "<tr>"
        $htmlBody += "<td><a href='$($row.Url)'>$([System.Web.HttpUtility]::HtmlEncode($row.Url))</a></td>"
        $htmlBody += "<td>$([System.Web.HttpUtility]::HtmlEncode($row.Title))</td>"
        $htmlBody += "<td>$($row.HubSiteId)</td>"
        $htmlBody += "<td>$([System.Web.HttpUtility]::HtmlEncode($row.Owner))</td>"
        $htmlBody += "<td>$([string]$row.StorageMB)</td>"
        $htmlBody += "<td>$([datetime]$row.LastContentModifiedDate -as [string])</td>"
        $htmlBody += "<td>$([datetime]$row.Created -as [string])</td>"
        $htmlBody += "<td>$([System.Web.HttpUtility]::HtmlEncode($row.Source))</td>"
        $htmlBody += "</tr>`n"
    }

    $htmlFooter = @"
        </tbody>
    </table>
</body>
</html>
"@

    $fullHtml = $htmlHeader + $htmlBody + $htmlFooter
    $fullHtml | Out-File -FilePath $OutputHtml -Encoding UTF8 -Force
    Write-Host "Exported HTML report to: $OutputHtml" -ForegroundColor Green
} catch {
    Write-Warning "Failed to build/export HTML report: $_"
}

# Show sample
Write-Host "`nSample (oldest 10):" -ForegroundColor Cyan
$inactiveSites | Sort-Object LastContentModifiedDate | Select-Object -First 10 | Format-Table -AutoSize

Write-Host "`nDone." -ForegroundColor Cyan
