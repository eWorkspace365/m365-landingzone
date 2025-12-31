param(
    [string]$JsonPath = ".\mfa_status.json",
    [string]$OutputHtml = ".\MFA-Status-Rubicon.html"
)

# -----------------------------
# 1️⃣ Load JSON
# -----------------------------
if (-not (Test-Path $JsonPath)) { Write-Error "JSON file not found"; exit }
$users = Get-Content $JsonPath -Raw | ConvertFrom-Json
if ($null -eq $users) { Write-Error "JSON is empty"; exit }

if ($users -isnot [System.Array]) { $users = ,$users }

# -----------------------------
# 2️⃣ Build table rows
# -----------------------------
function EscapeHtml([string]$s) {
    if (-not $s) { return "" }
    return $s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace('"','&quot;')
}

$goodRows = foreach ($u in $users | Where-Object {$_.MFAStatus -eq "Good"}) {
    "<tr>
        <td>$($u.UPN)</td>
        <td>$($u.Methods)</td>
        <td>$($u.MFAStatus)</td>
    </tr>"
}

$checkRows = foreach ($u in $users | Where-Object {$_.MFAStatus -eq "Check!"}) {
    "<tr>
        <td>$($u.UPN)</td>
        <td>$($u.Methods)</td>
        <td>$($u.MFAStatus)</td>
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
    <title>MFA Status Report</title>
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
        .section-title { margin-top:2rem; font-size:1.2rem; font-weight:600; }
    </style>
</head>
<body>
    <div class='container'>
        <div class='banner'>
            <img src='https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg' alt='M365 MFA Report' class='banner-img' />
            <div class='banner-text'>
                <h1>Microsoft 365 MFA Status Report</h1>
                <p class='banner-subtitle'>Generated on $(Get-Date -Format "MM/dd/yyyy HH:mm:ss") | Total Users: $($users.Count)</p>
            </div>
        </div>

        <div class='section-title'>MFAStatus = Good</div>
        <table>
            <thead>
                <tr>
                    <th>UPN</th>
                    <th>Methods</th>
                    <th>MFAStatus</th>
                </tr>
            </thead>
            <tbody>
                $($goodRows -join "`n")
            </tbody>
        </table>

        <div class='section-title'>MFAStatus = Check!</div>
        <table>
            <thead>
                <tr>
                    <th>UPN</th>
                    <th>Methods</th>
                    <th>MFAStatus</th>
                </tr>
            </thead>
            <tbody>
                $($checkRows -join "`n")
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
Write-Host "MFA report generated at $OutputHtml"
