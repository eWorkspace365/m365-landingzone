Connect-MgGraph -TenantId <tenantid> -ClientId <clientid> -CertificateThumbprint <thumbprint> -NoWelcome

# ----------------------------------------
# Azure App Proxy SSL Certificate Monitor
# Modern Graph-based approach
# ----------------------------------------

# Force TLS 1.2
# [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# -----------------------------------------
# Function to check public SSL certificate
# -----------------------------------------
function Get-PublicSslCertificate {
    param (
        [Parameter(Mandatory)]
        [string]$Url
    )

    try {
        $uri      = [Uri]$Url
        $hostname = $uri.Host
        $port     = if ($uri.Port -gt 0) { $uri.Port } else { 443 }

        $tcpClient = New-Object System.Net.Sockets.TcpClient($hostname, $port)
        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(),
            $false,
            { $true } # accept all certs for inspection
        )

        $sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12 -bor `
                        [System.Security.Authentication.SslProtocols]::Tls13

        $sslStream.AuthenticateAsClient($hostname, $null, $sslProtocols, $false)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sslStream.RemoteCertificate)
        $tcpClient.Close()

        [PSCustomObject]@{
            Url            = $Url
            Subject        = $cert.Subject
            Issuer         = $cert.Issuer
            Thumbprint     = $cert.Thumbprint
            ExpirationDate = $cert.NotAfter
            DaysRemaining  = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays, 0)
        }
    }
    catch {
        Write-Warning "SSL check failed for ${Url}: $($_.Exception.Message)"
        return $null
    }
}

Write-Host "Retrieving applications from Microsoft Graph..." -ForegroundColor Cyan
$apps = Get-MgApplication -All
$results = @()
$skippedCount = 0
$checkedCount = 0

foreach ($app in $apps) {
    try {
        $proxy = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/beta/applications/$($app.Id)/onPremisesPublishing"
    }
    catch {
        continue
    }

    if (-not $proxy.externalUrl) { continue }
    $externalUrl = $proxy.externalUrl

    # Skip if not HTTP(S)
    if ($externalUrl -notmatch '^https?://') {
        $skippedCount++
        Write-Host "Skipping non-public URL for: $($app.DisplayName) ($($app.Id))" -ForegroundColor DarkGray
        continue
    }

    $checkedCount++
    # Log with both name and ID
    Write-Host "Checking SSL certificate for: $($app.DisplayName) ($($app.Id))" -ForegroundColor Yellow

    $certInfo = Get-PublicSslCertificate -Url $externalUrl

    if ($certInfo) {
        $results += [PSCustomObject]@{
            ApplicationId   = $app.Id
            ApplicationName = $app.DisplayName
            ExternalUrl     = $externalUrl
            ExpirationDate  = $certInfo.ExpirationDate
            DaysRemaining   = $certInfo.DaysRemaining
            Warning         = if ($certInfo.DaysRemaining -le 30) { "⚠️ Expiring Soon" } else { "" }
        }
    }
}

if ($results.Count -gt 0) {
    Write-Host "`nSSL Certificate Report:" -ForegroundColor Cyan
    $results | Sort-Object ExpirationDate | Format-Table -AutoSize

    $jsonPath = ".\AppProxy_SSL_Report.json"
    $results | ConvertTo-Json -Depth 3 | Out-File $jsonPath -Encoding UTF8
    Write-Host "`nJSON report saved to $jsonPath" -ForegroundColor Green
} else {
    Write-Host "No valid App Proxy SSL data found." -ForegroundColor Yellow
}

# Summary stats
Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "  Checked: $checkedCount apps"
Write-Host "  Skipped: $skippedCount apps (non-public URLs)"
Write-Host "  Found:   $($results.Count) valid SSL cert entries"

