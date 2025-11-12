<#
.SYNOPSIS
    Export daily outbound phishing counts from Microsoft 365 Defender via Graph API
.DESCRIPTION
    Uses certificate-based app authentication to query Advanced Hunting for outbound phishing messages.
.NOTES
    Requires:
      - App registration with "AdvancedHunting.Read.All" Application permission
      - Certificate uploaded to app registration
      - PowerShell modules: Microsoft.Graph
#>

# === CONFIG ===
$AppId = "4881b8d1-79c6-42cb-9e2d-d114941d4cd5"
$TenantId = "deaa91e3-57cf-46c3-ae77-bb57291f05cd"
$CertificateThumbprint = "D89A3085B3AE582DD60B48553307EAF42B3DD619"
$CSVPath = "$env:USERPROFILE\Downloads\Outbound-Phish-Totals.csv"

# === Prepare certificate ===
$Cert = Get-ChildItem -Cert:\CurrentUser\My | Where-Object Thumbprint -eq $CertificateThumbprint
if (-not $Cert) { Write-Error "Certificate not found"; exit }

# === Connect to Graph ===
Connect-MgGraph -ClientId $AppId -TenantId $TenantId -Certificate $Cert -Scopes "https://graph.microsoft.com/.default"

# === KQL query for outbound phishing messages ===
$Query = @"
EmailEvents
| where Timestamp >= ago(90d)
| where Direction == "Outbound"
| where ThreatTypes has "Phish"
| summarize PhishCount=count() by Date = startofday(Timestamp)
| order by Date
"@

# === Build request body ===
$Body = @{
    query = $Query
} | ConvertTo-Json -Depth 5

# === Run query via Graph Beta API ===
$Uri = "https://graph.microsoft.com/beta/security/advancedHunting/run"
$Results = Invoke-MgGraphRequest -Method POST -Uri $Uri -Body $Body | ConvertFrom-Json

# === Process results and export CSV ===
if ($Results.value -and $Results.value.Count -gt 0) {
    $Results.value | ForEach-Object {
        [PSCustomObject]@{
            Date = $_.Date
            PhishOutboundCount = $_.PhishCount
        }
    } | Export-Csv -Path $CSVPath -NoTypeInformation -Encoding UTF8

    Write-Host "Exported phishing outbound summary to $CSVPath" -ForegroundColor Green
} else {
    Write-Warning "No outbound phishing messages found in the last 7 days."
}

# === Disconnect Graph session ===
Disconnect-MgGraph
