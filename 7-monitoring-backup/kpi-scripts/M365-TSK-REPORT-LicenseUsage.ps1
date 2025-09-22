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
    
    [Parameter(Mandatory=$true)]
    [String]$OrganizationDomain,
    
    [Parameter(Mandatory=$true)]
    [Int]$ReportPeriodDays
)

# Connect to Microsoft Graph
Connect-MgGraph -ClientId $AADClientId -TenantId $TenantId -CertificateThumbprint $AADThumbprint

# Initialize HTML report
$html = @"
<html>
<head>
    <title>Microsoft 365 Usage Report</title>
    <style>
        table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
        table td, th {border: 1px solid #ddd; padding: 8px;}
        table tr:nth-child(even){background-color: #f2f2f2;}
        table tr:hover {background-color: #ddd;}
        table th {padding-top: 12px; padding-bottom: 12px; text-align: left; background-color: #4CAF50; color: white;}
    </style>
</head>
<body>
    <h1>Microsoft 365 Usage Report</h1>
    <h2>Organization Domain: $OrganizationDomain</h2>
"@

# Define the report period
$startDate = (Get-Date).AddDays(-$ReportPeriodDays).ToString("yyyy-MM-dd")
$endDate = (Get-Date).ToString("yyyy-MM-dd")

#==============================================
# Licenses Assigned Report
#==============================================
Write-Output "$(Get-Date) : Generating Licenses Assigned Report"
$uri = "https://graph.microsoft.com/v1.0/reports/getOffice365ActiveUserDetail(period='D$ReportPeriodDays')"
$licenseData = (Invoke-RestMethod -Method Get -Uri $uri -Headers @{Authorization = "Bearer $((Get-MgAccessToken).AccessToken)"}).Value

$totalUsers = $licenseData.Count
$licensedUsers = ($licenseData | Where-Object { $_."Assigned Products" }).Count
$unlicensedUsers = $totalUsers - $licensedUsers

$html += @"
<h2>Users and Assigned Licenses</h2>
<table>
    <tr><th>Total Users</th><td>$totalUsers</td></tr>
    <tr><th>Licensed Users</th><td>$licensedUsers</td></tr>
    <tr><th>Unlicensed Users</th><td>$unlicensedUsers</td></tr>
</table>
"@

#==============================================
# Active Users Report
#==============================================
Write-Output "$(Get-Date) : Generating Active Users Report"
$uri = "https://graph.microsoft.com/v1.0/reports/getOffice365ServicesUserCounts(period='D$ReportPeriodDays')"
$activeUserData = (Invoke-RestMethod -Method Get -Uri $uri -Headers @{Authorization = "Bearer $((Get-MgAccessToken).AccessToken)"}).Value

$html += @"
<h2>Active Users</h2>
<table>
    <tr><th>Service</th><th>Active</th><th>Inactive</th></tr>
"@

foreach ($service in $activeUserData) {
    $html += "<tr><td>$($service.ServiceName)</td><td>$($service.ActiveUsers)</td><td>$($service.InactiveUsers)</td></tr>"
}

$html += "</table>"

#==============================================
# Product Activations Report
#==============================================
Write-Output "$(Get-Date) : Generating Product Activations Report"
$uri = "https://graph.microsoft.com/v1.0/reports/getOffice365ActivationsUserCounts"
$productActivationData = (Invoke-RestMethod -Method Get -Uri $uri -Headers @{Authorization = "Bearer $((Get-MgAccessToken).AccessToken)"}).Value

$html += @"
<h2>Product Activations</h2>
<table>
    <tr><th>Product Type</th><th>Assigned</th><th>Activated</th><th>Shared Computer Activation</th></tr>
"@

foreach ($product in $productActivationData) {
    $html += "<tr><td>$($product.ProductType)</td><td>$($product.Assigned)</td><td>$($product.Activated)</td><td>$($product.SharedComputerActivation)</td></tr>"
}

$html += "</table>"

#==============================================
# Mailbox Usage Report
#==============================================
Write-Output "$(Get-Date) : Generating Mailbox Usage Report"
$uri = "https://graph.microsoft.com/v1.0/reports/getMailboxUsageDetail(period='D$ReportPeriodDays')"
$mailboxData = (Invoke-RestMethod -Method Get -Uri $uri -Headers @{Authorization = "Bearer $((Get-MgAccessToken).AccessToken)"}).Value

$activeMailboxes = ($mailboxData | Where-Object { $_.IsActive -eq $true }).Count
$inactiveMailboxes = ($mailboxData | Where-Object { $_.IsActive -eq $false }).Count

$html += @"
<h2>Mailbox Usage</h2>
<table>
    <tr><th>Active Mailboxes</th><td>$activeMailboxes</td></tr>
    <tr><th>Inactive Mailboxes</th><td>$inactiveMailboxes</td></tr>
</table>
"@

#==============================================
# Finalize HTML Report
#==============================================
$html += "</body></html>"

# Save the report to a file
$reportPath = "C:\Reports\Microsoft365UsageReport.html"
$html | Out-File -FilePath $reportPath -Encoding UTF8

#==============================================
# Send Email with Report
#==============================================
Write-Output "$(Get-Date) : Sending Email with Report"
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

$params = @{
    message = @{
        subject = "Microsoft 365 Usage Report"
        body = @{
            contentType = "HTML"
            content = $html
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

Write-Output "$(Get-Date) : Report Sent Successfully"
Disconnect-MgGraph
