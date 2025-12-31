param(
    [string]$JsonPath = ".\exclusions.json",
    [string]$OutputHtml = ".\CA-Exclusions-Rubicon.html"
)

# -----------------------------
# 1️⃣ Load JSON
# -----------------------------
if (-not (Test-Path $JsonPath)) { Write-Error "JSON file not found"; exit }
$groups = Get-Content $JsonPath -Raw | ConvertFrom-Json
if ($null -eq $groups) { Write-Error "JSON is empty"; exit }

if ($groups -isnot [System.Array]) { $groups = ,$groups }

# -----------------------------
# 2️⃣ Build table rows
# -----------------------------
function EscapeHtml([string]$s) {
    if (-not $s) { return "" }
    return $s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace('"','&quot;')
}

$rows = foreach ($g in $groups) {
    $membersHtml = if ($g.Members -and $g.Members.Count -gt 0) {
        ($g.Members | ForEach-Object { EscapeHtml($_.DisplayName + " <" + $_.UserPrincipalName + ">") }) -join "<br/>"
    } else { "No members" }

    $policiesHtml = if ($g.ExcludedByPolicies -and $g.ExcludedByPolicies.Count -gt 0) {
        ($g.ExcludedByPolicies | ForEach-Object { EscapeHtml($_) }) -join "<br/>"
    } else { "None" }

    "<tr>
        <td>$($g.GroupDisplayName)</td>
        <td><pre class='json-block'>$membersHtml</pre></td>
        <td><pre class='json-block'>$policiesHtml</pre></td>
    </tr>"
}

# -----------------------------
# 3️⃣ Build full HTML
# -----------------------------
$html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='utf-8' />
    <title>Conditional Access Exclusions Report</title>
    <style>
        body { font-family: Consolas, 'Fira Code', 'Segoe UI', monospace; background-color: #0b1120; color: #e5e7eb; margin: 0; padding: 2rem; }
        .container { max-width: 1600px; margin: 0 auto; }
        .banner { display: flex; align-items: center; gap: 1.25rem; padding: 1rem 1.25rem; border-radius: 1rem; background: linear-gradient(90deg, #1d4ed8, #38bdf8); box-shadow: 0 18px 60px rgba(0,0,0,.65); margin-bottom: 1.5rem; }
        .banner-img { height: 52px; width: auto; border-radius: .75rem; border: 2px solid rgba(15,23,42,.85); background-color: #ffffff; padding: 12px; }
        .banner-text h1 { margin:0; font-size:1.6rem; line-height:1.25; }
        .banner-subtitle { margin: .25rem 0 0; font-size:.9rem; color:#e5e7eb; opacity:.95; }
        table { width:100%; border-collapse:collapse; font-size:.85rem; background-color:#020617; border-radius:.75rem; overflow:hidden; margin-top:1rem; }
        thead th { padding:.6rem .7rem; text-align:left; border-bottom:1px solid #1f2937; white-space:nowrap; }
        tbody td { padding:.5rem .7rem; vertical-align:top; border-bottom:1px solid #111827; }
        .json-block { margin:0; white-space:pre-wrap; word-wrap:break-word; overflow-wrap:anywhere; }
    </style>
</head>
<body>
    <div class='container'>
        <div class='banner'>
            <img src='https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg' alt='M365 CA Report' class='banner-img' />
            <div class='banner-text'>
                <h1>Conditional Access Exclusions Report</h1>
                <p class='banner-subtitle'>Generated on $(Get-Date -Format "MM/dd/yyyy HH:mm:ss") | Total Groups: $($groups.Count)</p>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>GroupDisplayName</th>
                    <th>Members</th>
                    <th>ExcludedByPolicies</th>
                </tr>
            </thead>
            <tbody>
                $($rows -join "`n")
            </tbody>
        </table>
    </div>
</body>
</html>
"@

# -----------------------------
# 4️⃣ Save HTML
# -----------------------------
$html | Out-File -FilePath $OutputHtml -Encoding UTF8
Write-Host "Report generated at $OutputHtml"
