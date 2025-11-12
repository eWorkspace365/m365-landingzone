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


# Connect to Microsoft Graph for Application data
Connect-MgGraph -ClientId $AADClientId -TenantId $TenantId -CertificateThumbprint $AADThumbprint -NoWelcome

Write-Host "Fetching service principals..."
[array]$ServicePrincipals = Get-MgServicePrincipal -All -PageSize 500 | Sort-Object AppId
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
    $AppId = $AppSignIn.AppId
    $SP = $ServicePrincipalsWithName | Where-Object { $_.AppId -eq $AppId }
    $AppName = $SP.DisplayName

    if ($AppName) {
        # Get API Permissions
        $Permissions = @()

        try {
            $AppRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AppRoleId
            if ($AppRoles) {
                $Permissions += "AppRoles: " + ($AppRoles -join ", ")
            }
        } catch {}

        try {
            $DelegatedPerms = Get-MgBetaOauth2PermissionGrant -Filter "clientId eq '$($SP.Id)'" -ErrorAction SilentlyContinue
            if ($DelegatedPerms) {
                $Scopes = $DelegatedPerms | Select-Object -ExpandProperty Scope
                if ($Scopes) {
                    $Permissions += "Delegated: " + ($Scopes -join ", ")
                }
            }
        } catch {}

        $PermissionsSummary = if ($Permissions) { $Permissions -join "; " } else { "None found" }

        # Add to report
        $DaysSince = (New-TimeSpan $AppSignIn.lastSignInActivity.lastSignInDateTime).Days
        $ActivityLine = [PSCustomObject]@{
            'Application Name'        = $AppName
            'AppId'                   = $AppId
            'Last Sign-In'            = Get-Date $AppSignIn.lastSignInActivity.lastSignInDateTime -Format 'dd-MMM-yyyy HH:mm:ss'
            'Days Since Last Sign-In' = $DaysSince
            'Permissions'             = $PermissionsSummary
        }
        $ActivityReport.Add($ActivityLine)
    }
}

# Sort activity report
$ActivityReport = $ActivityReport | Sort-Object -Property 'Days Since Last Sign-In' -Descending

# Identify new applications
$NewAppThreshold = (Get-Date).AddDays(-30)
$NewApplications = $ServicePrincipalsWithName | Where-Object { $_.CreatedDateTime -gt $NewAppThreshold }
$NewAppsReport = $NewApplications | Select-Object DisplayName, AppId, @{Name="Created";Expression={Get-Date $_.CreatedDateTime -Format 'dd-MMM-yyyy HH:mm:ss'}}

# HTML Styling
$CSSStyle = "<style>
table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
table td, th {border: 1px solid #ddd; padding: 8px;}
table tr:nth-child(even){background-color: #F39C12;}
table tr:hover {background-color: #ddd;}
table th { padding-top: 10px; padding-bottom: 10px; text-align: left; background-color: #F39C12; color: white;}
</style>"

# Convert tables to HTML
$TableActivityReport = $ActivityReport | ConvertTo-Html -Fragment | Out-String
$TableNewApps = $NewAppsReport | ConvertTo-Html -Fragment | Out-String

# Compose HTML body
$htmlContent = @"
<html>
<head>
$CSSStyle
</head>
<body>
<h2>Application Activity Report</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" height="10%" alt="Banner Image" class="banner">
<p>This report provides details about Cloud Apps with activity in the last 180 days.</p>
<h3>Summary</h3>
<ul>
    <li>Total Applications with Name: <b>$TotalApplicationsWithName</b></li>
    <li>Applications Active Last 180 Days: <b>$($ActivityReport.Count)</b></li>
    <li>No Activity Last 180 Days: <b>$($TotalApplicationsWithName - $ActivityReport.Count)</b></li>
</ul>
<h3>Applications with Activity</h3>
$TableActivityReport
<h3>Newly Created Applications (Last 30 Days)</h3>
$TableNewApps
</body>
</html>
"@

# Output HTML report to file
$outputFile = "CloudApps-Activity-Report.html"
$htmlContent | Out-File -FilePath $outputFile -Encoding utf8
Write-Host "Report saved to: $outputFile"

# Reconnect to Microsoft Graph for email
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint -NoWelcome

# Send email
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

Write-Host "Sending report to $EXOMailTo..."
Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

Disconnect-MgGraph
Write-Host "Email sent successfully."
