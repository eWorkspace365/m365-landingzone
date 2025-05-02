[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [String]$TenantID,
    
    [Parameter(Mandatory=$false)]
    [String]$AADClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$AADThumbprint,
    
    [Parameter(Mandatory=$true)]
    [String]$EXOMailFrom,
    
    [Parameter(Mandatory=$true)]
    [String]$EXOMailTo,
    
    [Parameter(Mandatory=$true)]
    [String]$EXOClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOThumbprint
)

set-strictmode -version Latest
$ErrorActionPreference = "stop"

# Verbinding maken met Microsoft Graph voor CIS-controles
Write-Output "Verbinding maken met Microsoft Graph voor CIS-controles..."
Connect-MgGraph -ClientId $AADClientId -TenantId $TenantID -CertificateThumbprint $AADThumbprint

# Placeholder voor rapportgegevens
$CISReport = New-Object 'System.Collections.Generic.List[System.Object]'

# Controle 1: MFA voor alle gebruikers
Write-Output "Controle 1: MFA voor alle gebruikers..."
$MFAStatus = Get-MgPolicyAuthenticationMethodsPolicy | Select-Object -ExpandProperty IsEnabled
$CISReport.Add([PSCustomObject]@{
    'Controle' = "MFA voor alle gebruikers"
    'Status'   = if ($MFAStatus -eq $true) { "Ingeschakeld" } else { "Uitgeschakeld" }
})

# Controle 2: Gasttoegang beperken
Write-Output "Controle 2: Gasttoegang beperken..."
$GuestAccess = Get-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty AllowGuestAccess
$CISReport.Add([PSCustomObject]@{
    'Controle' = "Gasttoegang beperken"
    'Status'   = if ($GuestAccess -eq $false) { "Beperkt" } else { "Niet beperkt" }
})

# Controle 3: Beveiligingsstandaarden
Write-Output "Controle 3: Beveiligingsstandaarden inschakelen..."
$SecurityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Select-Object -ExpandProperty IsEnabled
$CISReport.Add([PSCustomObject]@{
    'Controle' = "Beveiligingsstandaarden"
    'Status'   = if ($SecurityDefaults -eq $true) { "Ingeschakeld" } else { "Uitgeschakeld" }
})

# Controle 4: Externe delen in SharePoint
Write-Output "Controle 4: Externe delen in SharePoint beperken..."
$SPSharing = Get-MgSite -SiteId "root" | Select-Object -ExpandProperty SharingCapability
$CISReport.Add([PSCustomObject]@{
    'Controle' = "Externe delen in SharePoint"
    'Status'   = if ($SPSharing -eq "Disabled") { "Uitgeschakeld" } else { "Ingeschakeld" }
})

# Controle 5: Mailbox auditing
Write-Output "Controle 5: Mailbox auditing inschakelen..."
$MailboxAudit = Get-EXOMailbox -PropertySets Audit | Where-Object { $_.AuditEnabled -eq $true }
$CISReport.Add([PSCustomObject]@{
    'Controle' = "Mailbox auditing"
    'Status'   = if ($MailboxAudit.Count -gt 0) { "Ingeschakeld" } else { "Uitgeschakeld" }
})

# HTML-rapport genereren
Write-Output "HTML-rapport genereren..."
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>CIS Rapport</title>
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
            background-color: #4CAF50;
            color: white;
        }
    </style>
</head>
<body>
    <h1>CIS Rapport</h1>
    <table>
        <tr>
            <th>Controle</th>
            <th>Status</th>
        </tr>
"@

foreach ($item in $CISReport) {
    $htmlContent += @"
        <tr>
            <td>$($item.Controle)</td>
            <td>$($item.Status)</td>
        </tr>
"@
}

$htmlContent += @"
    </table>
</body>
</html>
"@

# Verbinding verbreken met Microsoft Graph voor CIS-controles
Disconnect-MgGraph

# Verbinding maken met Microsoft Graph voor e-mailverzending
Write-Output "Verbinding maken met Microsoft Graph voor e-mailverzending..."
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantID -CertificateThumbprint $EXOThumbprint

# E-mail verzenden
Write-Output "E-mail verzenden..."
$params = @{
    message = @{
        subject = "CIS Rapport"
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

Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

# Verbinding verbreken met Microsoft Graph voor e-mailverzending
# Disconnect-MgGraph

Write-Output "CIS Rapport succesvol verzonden!"
