param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath,

    [string]$OutputPath,

    [string]$Title = "Microsoft 365 drift report from Rubicon Cloud Advisor",

    [switch]$OpenReport
)

# $JsonPath = "$PathReport\$TenantName-DriftReport-M365-$Workload.json"
# $OutputPath = "$PathReport\$TenantName-DriftReport-M365-$Workload.html"
# $Title = "Microsoft 365 drift detection report from Rubicon Cloud Advisor"

# ----------------- Validatie & setup -----------------

if (-not (Test-Path -Path $JsonPath)) {
    throw "JSON file not found: $JsonPath"
}

if (-not $OutputPath) {
    $baseName   = [System.IO.Path]::GetFileNameWithoutExtension($JsonPath)
    $directory  = [System.IO.Path]::GetDirectoryName($JsonPath)
    $OutputPath = Join-Path $directory "$baseName-report.html"
}

# Voor HTML-encoding
Add-Type -AssemblyName System.Web

# ----------------- Helpers -----------------

function Get-DriftStatus {
    param(
        [array]$Properties
    )

    $status = "Modified"

    if ($Properties) {
        foreach ($p in $Properties) {
            $src = $p.ValueInSource
            $dst = $p.ValueInDestination

            $srcStr = [string]$src
            $dstStr = [string]$dst

            if ($srcStr -eq "Absent" -and $dstStr -ne "Absent") {
                return "Added"
            }
            elseif ($dstStr -eq "Absent" -and $srcStr -ne "Absent") {
                return "Removed"
            }
        }
    }

    return $status
}

function Get-CleanJsonText {
    param(
        $Value
    )

    if ($null -eq $Value) {
        return ""
    }

    $json = $Value | ConvertTo-Json -Depth 10

    # Strip { en } en lege regels weghalen
    $noBraces = $json -replace '[{}]', ''
    $lines = $noBraces -split "`r?`n" |
        ForEach-Object { $_.TrimEnd() } |
        Where-Object { $_.Trim() -ne '' }

    return ($lines -join "`r`n")
}

function Build-PropertiesHtml {
    param(
        [array]$Properties
    )

    if (-not $Properties -or $Properties.Count -eq 0) {
        return "<em>No property differences</em>"
    }

    $blocks = @()

    foreach ($prop in $Properties) {
        $paramName    = [string]$prop.ParameterName
        $paramNameEnc = [System.Web.HttpUtility]::HtmlEncode($paramName)

        $srcText = Get-CleanJsonText $prop.ValueInSource
        $dstText = Get-CleanJsonText $prop.ValueInDestination

        $srcHtml = [System.Web.HttpUtility]::HtmlEncode($srcText)
        $dstHtml = [System.Web.HttpUtility]::HtmlEncode($dstText)

        $blocks += @"
<div class='prop-block'>
  <table class='prop-table'>
    <tr>
      <th class='prop-title' colspan='2'>$paramNameEnc</th>
    </tr>
    <tr>
      <th class='prop-colhead'>ValueInSource</th>
      <th class='prop-colhead'>ValueInDestination</th>
    </tr>
    <tr>
      <td><pre class='json-block'>$srcHtml</pre></td>
      <td><pre class='json-block'>$dstHtml</pre></td>
    </tr>
  </table>
</div>
"@
    }

    return ($blocks -join "<hr class='prop-separator' />")
}

# ----------------- JSON inlezen -----------------

$jsonRaw = Get-Content -Path $JsonPath -Raw
$items   = $jsonRaw | ConvertFrom-Json

if ($items -isnot [System.Collections.IEnumerable] -or $items -is [string]) {
    $items = @($items)
}

$rows = foreach ($item in $items) {
    $status    = Get-DriftStatus -Properties $item.Properties
    $propsHtml = Build-PropertiesHtml -Properties $item.Properties

    [PSCustomObject]@{
        ResourceName         = [string]$item.ResourceName
        ResourceInstanceName = [string]$item.ResourceInstanceName
        Status               = $status
        PropertiesHtml       = $propsHtml
    }
}

$total     = $rows.Count
$added     = ($rows | Where-Object { $_.Status -eq "Added" }).Count
$removed   = ($rows | Where-Object { $_.Status -eq "Removed" }).Count
$modified  = ($rows | Where-Object { $_.Status -eq "Modified" }).Count
$generated = Get-Date

# ----------------- HTML opbouwen -----------------

$rowsHtml = foreach ($r in $rows) {
    $resName = [System.Web.HttpUtility]::HtmlEncode($r.ResourceName)
    $resInst = [System.Web.HttpUtility]::HtmlEncode($r.ResourceInstanceName)
    $status  = [System.Web.HttpUtility]::HtmlEncode($r.Status)

    $icon = switch ($r.Status) {
        "Added"    { "&#x2795;" }   # plus
        "Removed"  { "&#x2796;" }   # minus
        "Modified" { "&#x270E;" }   # pencil
        default    { "&#x270E;" }
    }

@"
<tr>
    <td>$resName</td>
    <td>$resInst</td>
    <td><span class='status-badge status-$($r.Status.ToLower())'>$icon $status</span></td>
    <td>$($r.PropertiesHtml)</td>
</tr>
"@
}

$rowsHtmlJoined = $rowsHtml -join "`r`n"

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
            margin-bottom: 1.5rem;
        }

        .banner-image-wrapper {
            flex: 0 0 auto;
        }

        .banner-img {
            height: 52px;
            width: auto;
            max-width: 120px;
            border-radius: 0.75rem;
            object-fit: contain;
            border: 2px solid rgba(15,23,42,.85);
            background-color: #ffffff;
            padding: 12px;
        }

        .banner-text {
            flex: 1 1 auto;
            min-width: 0;
        }

        .banner-text h1 {
            margin: 0;
            font-size: 1.6rem;
            line-height: 1.25;
        }

        .banner-subtitle {
            margin: .25rem 0 0;
            font-size: .9rem;
            color: #e5e7eb;
            opacity: .95;
        }

        /* Toolbar for ResourceName filter */
        .toolbar {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1rem;
            padding: 0.6rem 0.9rem;
            background-color: #020617;
            border-radius: 0.75rem;
            border: 1px solid #1f2937;
        }

        .toolbar-label {
            font-size: 0.85rem;
            color: #9ca3af;
            white-space: nowrap;
        }

        .toolbar-select {
            min-width: 260px;
            padding: 0.35rem 0.6rem;
            border-radius: 0.5rem;
            border: 1px solid #374151;
            background-color: #020617;
            color: #e5e7eb;
            font-size: 0.85rem;
        }

        .toolbar-select:focus {
            outline: none;
            border-color: #38bdf8;
            box-shadow: 0 0 0 1px #38bdf8;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: .85rem;
            background-color: #020617;
            border-radius: .75rem;
            overflow: hidden;
        }

        thead {
            background-color: #020617;
        }

        thead th {
            padding: .6rem .7rem;
            text-align: left;
            border-bottom: 1px solid #1f2937;
            white-space: nowrap;
        }

        tbody tr:nth-child(odd)  { background-color: #020617; }
        tbody tr:nth-child(even) { background-color: #020617; }

        tbody td {
            padding: .5rem .7rem;
            vertical-align: top;
            border-bottom: 1px solid #111827;
        }

        td:nth-child(1) { width: 15%; }
        td:nth-child(2) { width: 25%; }
        td:nth-child(3) { width: 10%; }
        td:nth-child(4) { width: 50%; }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: .25rem;
            padding: .1rem .45rem;
            border-radius: 999px;
            font-size: .7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: .06em;
            border: 1px solid transparent;
        }

        .status-added {
            color: #16a34a;
            border-color: rgba(34,197,94,.4);
            background: rgba(22,163,74,.15);
        }

        .status-removed {
            color: #b91c1c;
            border-color: rgba(248,113,113,.4);
            background: rgba(185,28,28,.15);
        }

        .status-modified {
            color: #d97706;
            border-color: rgba(245,158,11,.4);
            background: rgba(217,119,6,.15);
        }

        .prop-block {
            margin-bottom: .5rem;
        }

        .prop-table {
            width: 100%;
            border-collapse: collapse;
            border: 1px solid #1f2937;
            table-layout: fixed;
        }

        .prop-table th,
        .prop-table td {
            border: 1px solid #1f2937;
            padding: .25rem .35rem;
            vertical-align: top;
            word-wrap: break-word;
            overflow-wrap: anywhere;
        }

        .prop-title {
            background-color: #111827;
            text-align: left;
            font-weight: 700;
        }

        .prop-colhead {
            background-color: #020617;
            font-weight: 600;
            text-align: left;
        }

        .json-block {
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow-wrap: anywhere;
        }

        .prop-separator {
            border: 0;
            border-top: 1px dashed #1f2937;
            margin: .4rem 0;
        }
    </style>
</head>
<body>
    <div class='container'>
        <div class='banner'>
            <div class='banner-image-wrapper'>
                <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU"
                     alt="Microsoft 365 Drift Detection"
                     class="banner-img" />
            </div>
            <div class='banner-text'>
                <h1>$Title</h1>
                <p class='banner-subtitle'>
                    Generated on $generated | Total: $total | Added: $added | Removed: $removed | Modified: $modified
                </p>
            </div>
        </div>

        <!-- Toolbar with ResourceName filter -->
        <div class='toolbar'>
            <span class='toolbar-label'>Filter by ResourceName:</span>
            <select id='resourceFilter' class='toolbar-select'>
                <option value='__all'>All resources</option>
            </select>
        </div>

        <table id='driftTable'>
            <thead>
                <tr>
                    <th>ResourceName</th>
                    <th>ResourceInstanceName</th>
                    <th>Status</th>
                    <th>Properties (ParameterName / ValueInSource / ValueInDestination)</th>
                </tr>
            </thead>
            <tbody>
                $rowsHtmlJoined
            </tbody>
        </table>
    </div>

    <script>
        // Build dropdown options from unique ResourceName values and filter rows on change
        document.addEventListener('DOMContentLoaded', function () {
            var table = document.getElementById('driftTable');
            if (!table || !table.tBodies.length) {
                return;
            }

            var tbody = table.tBodies[0];
            var rows = Array.prototype.slice.call(tbody.rows);
            var select = document.getElementById('resourceFilter');
            if (!select) {
                return;
            }

            var namesMap = {};

            rows.forEach(function (row) {
                if (!row.cells.length) {
                    return;
                }
                var cell = row.cells[0]; // ResourceName column
                var text = (cell.textContent || cell.innerText || '').trim();
                if (text && !namesMap[text]) {
                    namesMap[text] = true;
                }
            });

            var names = Object.keys(namesMap).sort();
            names.forEach(function (name) {
                var opt = document.createElement('option');
                opt.value = name;
                opt.textContent = name;
                select.appendChild(opt);
            });

            select.addEventListener('change', function () {
                var selected = select.value;
                rows.forEach(function (row) {
                    var cell = row.cells[0];
                    var name = cell ? (cell.textContent || cell.innerText || '').trim() : '';
                    if (selected === '__all' || name === selected) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                });
            });
        });
    </script>
</body>
</html>
"@

# ----------------- Schrijven & openen -----------------

$html | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host "Drift report generated:" -ForegroundColor Green
Write-Host " $OutputPath"

if ($OpenReport) {
    Start-Process $OutputPath
}


# SharePoint Upload
# Connect to your SharePoint site
Connect-PnPOnline "https://contoso.sharepoint.com/sites/$customer" -ClientId $ApplicationID -Thumbprint $CertificateThumbprint -Tenant $TenantID

# Define the folder containing HTML files for category extraction and upload
$HtmlFolder = "C:\Users\Public\Downloads"

# Get all HTML files in the folder
$htmlFiles = Get-ChildItem -Path $HtmlFolder -Filter "*.html"

# Retrieve all terms from the "PageCategory" term set
$termSetName = "PageCategory"
$termGroupName = "Siteverzameling - cbgmeb.sharepoint.com-sites-InformationPortalTest"
$terms = Get-PnPTerm -TermSet $termSetName -TermGroup $termGroupName

# Loop through each HTML file
foreach ($file in $htmlFiles) {
    # Get the page name from the file name
    $pageName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)

    # Read the content of the HTML file
    $htmlContent = Get-Content -Path $file.FullName -Raw

    # Create a modern page in SharePoint
    Add-PnPPage -Name $pageName -LayoutType Article -Title $pageTitle

    # Add the HTML content to the page
    Add-PnPPageTextPart -Page $pageName -Text $normalizedHtmlContent
	
    Write-Host "Processed and uploaded page: $pageName with metadata categories set to $categoryIds"
}

Write-Host "All HTML files have been processed and uploaded to SharePoint."