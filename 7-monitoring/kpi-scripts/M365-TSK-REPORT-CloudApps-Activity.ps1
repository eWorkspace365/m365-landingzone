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
    [String]$EXOThumbprint
)

# Connect to Microsoft Graph
Connect-MgGraph -ClientId $AADClientId -TenantId $TenantId -CertificateThumbprint $AADThumbprint

Write-Host "Fetching service principals..."
[array]$ServicePrincipals = Get-MgServicePrincipal -All -PageSize 500 | Sort-Object AppId

# Filter service principals to count only those with a DisplayName (Application Name)
$ServicePrincipalsWithName = $ServicePrincipals | Where-Object { $_.DisplayName -ne $null }
$TotalApplicationsWithName = $ServicePrincipalsWithName.Count

# Define the date range for activity analysis (last 180 days)
$CheckDate = (Get-Date).AddDays(-180).ToString('yyyy-MM-ddTHH:mm:ssZ')

Write-Host "Fetching application activity data..."
$ActivityReport = [System.Collections.Generic.List[Object]]::new()
[array]$AppSignInLogs = Get-MgBetaReportServicePrincipalSignInActivity -Filter "(lastSignInActivity/lastSignInDateTime ge $CheckDate)" -All -PageSize 500

If (!($AppSignInLogs)) {
    Write-Host "No application activity found in the last 180 days."
    Break
} Else {
    Write-Host ("Found {0} application sign-ins in the last 180 days." -f $AppSignInLogs.Count)
}

Write-Host "Analyzing application activity data..."
ForEach ($AppSignIn in $AppSignInLogs) {
    # Match AppId to DisplayName and exclude apps without a name
    $AppName = $ServicePrincipalsWithName | Where-Object { $_.AppId -eq $AppSignIn.AppId } | Select-Object -ExpandProperty DisplayName
    if ($AppName) { # Exclude apps without an Application Name
        $DaysSince = (New-TimeSpan $AppSignIn.lastSignInActivity.lastSignInDateTime).Days
        $ActivityLine = [PSCustomObject]@{
            'Application Name'          = $AppName
            AppId                       = $AppSignIn.AppId
            LastSignIn                  = Get-Date $AppSignIn.lastSignInActivity.lastSignInDateTime -Format 'dd-MMM-yyyy HH:mm:ss'
            'Days Since Last Sign-In'   = $DaysSince
        }
        $ActivityReport.Add($ActivityLine)
    }
}

# Sort the report by Days Since Last Sign-In in descending order
$ActivityReport = $ActivityReport | Sort-Object -Property 'Days Since Last Sign-In' -Descending

Write-Host "Application activity report"
Write-Host "------------------------------------------------------------------------"
Write-Host ""
Write-Host ("Total Applications with Application Name: {0}" -f $TotalApplicationsWithName)
Write-Host ("Applications with activity in the last 180 days: {0}" -f $ActivityReport.Count)
Write-Host ("Applications with no activity in the last 180 days: {0}" -f ($TotalApplicationsWithName - $ActivityReport.Count))
Write-Host ""

$TotalApplicationsReported = $ActivityReport.Count


# Generate HTML report
$CSSStyle = "<style>
table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
table td, th {border: 1px solid #ddd; padding: 8px;}
table tr:nth-child(even){background-color: #F39C12;}
table tr:hover {background-color: #ddd;}
table th { padding-top: 10px; padding-bottom: 10px; text-align: left; background-color: #F39C12; color: white;}
</style>"

$TableActivityReport = $ActivityReport | ConvertTo-Html -Head $CSSStyle -Title "Application Activity Report" | Out-String

$htmlContent = @"
<h2>Application Activity Report</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" height="10%" alt="Banner Image" class="banner">
<p>This report provides details about Cloud Apps ($TotalApplicationsReported) with activity in the last 180 days.</p>
<h3>Applications with Activity</h3>
$TableActivityReport
"@

# Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
$params = @{
    message = @{
        subject = "Cloud Apps activity report from Rubicon Cloud Advisor"
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

# Send the email
Write-Verbose "Sending email with the report"
Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

# Disconnect from Microsoft Graph for email operations
Disconnect-MgGraph

Write-Verbose "Email sent successfully"
