[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [String]$AADClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$AADThumbprint,
  
    [Parameter(Mandatory=$false)]
    [String]$EXOMailFrom,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOMailTo,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOThumbprint,
    
    [Parameter(Mandatory=$false)]
    [String]$OrganizationDomain 
)

# ----------- Unified Audit Logs for SharePoint Site Administration ----------

# Make sure ExchangeOnlineManagement module is available
if (!(Get-Module ExchangeOnlineManagement)) {
    Write-Host "Loading ExchangeOnlineManagement module..." -ForegroundColor DarkGray
    Import-Module ExchangeOnlineManagement
}

Write-Host "Connecting for Unified Audit Logs..." -ForegroundColor DarkGray
Connect-ExchangeOnline -AppId $AADClientId -Organization $OrganizationDomain -CertificateThumbPrint $AADThumbprint

$startDate = (Get-Date).AddDays(-1).Date
$endDate = $startDate.AddDays(1).AddSeconds(-1)

Write-Host "Reading Unified Audit Logs (site administration)..." -ForegroundColor DarkGray
$UALResults = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -ResultSize 5000

$ualProcessed = @()
foreach ($entry in $UALResults) {
    $ad = ($entry.AuditData | ConvertFrom-Json)
    $ualProcessed += [PSCustomObject]@{
        CreationDate = $entry.CreationDate
        RecordType   = $entry.RecordType
		Operations   = $entry.Operations
        UserId       = $entry.UserIds
		AuditData    = $entry.AuditData
    }
}

Write-Host "Total unified audit log events found: $($ualProcessed.Count)" -ForegroundColor Cyan

# ----------- Generate HTML Report ----------
Write-Host "Generating HTML report for directory audits..." -ForegroundColor DarkGray
$CSSStyle = "<style>
table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
table td, th {border: 1px solid #ddd; padding: 8px;}
table tr:nth-child(even){background-color: #F39C12;}
table tr:hover {background-color: #ddd;}
table th { padding-top: 10px; padding-bottom: 10px; text-align: left; background-color: #F39C12; color: white;}
</style>"

$HTMLTable = $results | ConvertTo-Html -Head $CSSStyle -Title "Directory Audits Report" | Out-String

$htmlContent = @"
<h2>Directory Audits Report</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" height="10%" alt="Banner Image" class="banner">
<h4>Organization Domain: $OrganizationDomain</h4>
<p>This report lists all directory audits retrieved from Microsoft Graph.</p>
<h3>Directory Audits</h3>
$HTMLTable
"@

if ($ualProcessed.Count -gt 0) {
    $UALTable = $ualProcessed | ConvertTo-Html -Property CreationDate,RecordType,Operations,UserId,AuditData -Fragment -PreContent "<h3>Unified Audit Log - Site Administration Activities</h3>" | Out-String
    $htmlContent += $UALTable
}

# ----------- Send Email With Report ----------
Write-Host "Connecting to Microsoft Graph for email operations..." -ForegroundColor DarkGray
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

$params = @{
    message = @{
        subject = "Directory Audits Report"
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

Write-Host "Sending HTML report via email..." -ForegroundColor DarkGray
Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

Disconnect-MgGraph
Disconnect-ExchangeOnline

Write-Host "Email sent successfully" -ForegroundColor Green
