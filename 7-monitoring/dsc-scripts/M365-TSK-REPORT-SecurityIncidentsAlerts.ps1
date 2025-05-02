[CmdletBinding()]
param( 
    [Parameter(Mandatory=$true)]
    [String]$TenantID,
    
    [Parameter(Mandatory=$false)]
    [String]$SECClientId,
    
    [Parameter(Mandatory=$true)]
    [String]$SECAppSecret,
    
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

# Step 1: Authenticate and get Bearer token for Microsoft Graph API
Write-Verbose "Authenticating to Microsoft Graph API"
$OAuthUri = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
$AuthBody = @{
    client_id = $SECClientId
    client_secret = $SECAppSecret
    scope = "https://graph.microsoft.com/.default"
    grant_type = "client_credentials"
}
$AuthResponse = Invoke-RestMethod -Method Post -Uri $OAuthUri -Body $AuthBody -ErrorAction Stop
$BearerToken = $AuthResponse.access_token

# Common headers for API calls
$Headers = @{
    Authorization = "Bearer $BearerToken"
    "Content-Type" = "application/json"
}

# Step 2: Set Graph API URI for incidents and alerts
Write-Verbose "Setting Graph API URI for incidents and alerts"
$IncidentsUri = "https://graph.microsoft.com/v1.0/security/incidents?`$expand=alerts"
$AlertsUri = "https://graph.microsoft.com/v1.0/security/alerts_v2"

# Step 3: Get incidents and alerts from Microsoft Graph API
Write-Verbose "Getting incidents and alerts from Microsoft Graph API"
$IncidentsResponse = Invoke-RestMethod -Uri $IncidentsUri -Method Get -Headers $Headers -ErrorAction Stop
$AlertsResponse = Invoke-RestMethod -Uri $AlertsUri -Method Get -Headers $Headers -ErrorAction Stop

# Function to format date-time strings
function Format-DateTime {
    param(
        [string]$DateTimeString
    )
    try {
        $DateTimeObject = [datetime]::Parse($DateTimeString)
        return $DateTimeObject.ToString("dd-MM-yyyy 'T'HH:mm")
    } catch {
        return $DateTimeString  # Return original string if parsing fails
    }
}

# Step 4: Generate HTML tables for incidents and alerts
$CSSStyle = "<style>
table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
table td, th {border: 1px solid #ddd; padding: 8px;}
table tr:nth-child(even){background-color: #F39C12;}
table tr:hover {background-color: #ddd;}
table th { padding-top: 10px; padding-bottom: 10px; text-align: left; background-color: #F39C12; color: white;}
</style>"

# Generate HTML table for incidents
$IncidentsTable = $IncidentsResponse.value | ForEach-Object {
    [PSCustomObject]@{
        "Incident ID" = $_.id
        "Incident Name" = $_.displayName
        "Severity" = $_.severity
        "Status" = $_.status
        "Created DateTime" = Format-DateTime $_.createdDateTime
        "Last Updated DateTime" = Format-DateTime $_.lastUpdateDateTime
    }
} | ConvertTo-Html -Head $CSSStyle -Title "Incidents Report" | Out-String

# Generate HTML table for alerts
$AlertsTable = $AlertsResponse.value | ForEach-Object {
    [PSCustomObject]@{
        "Title" = $_.title
        "Category" = $_.category
        "Severity" = $_.severity
        "Status" = $_.status
        "Created DateTime" = Format-DateTime $_.createdDateTime
        "Last Updated DateTime" = Format-DateTime $_.lastUpdateDateTime
    }
} | ConvertTo-Html -Head $CSSStyle -Title "Alerts Report" | Out-String

# Combine all tables into a single HTML report
$htmlContent = @"
<h2>Security Report from Rubicon Cloud Advisor</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" height="10%" alt="Banner Image" class="banner">
<p>This email contains the latest security incidents and alerts.</p>
<h3>Incidents Report</h3>
$IncidentsTable
<h3>Alerts Report</h3>
$AlertsTable
"@

# Step 5: Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantID -CertificateThumbprint $EXOThumbprint

# Step 6: Define the email message
$params = @{
    message = @{
        subject = "Security Report from Rubicon Cloud Advisor"
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

# Step 7: Send the email
Write-Verbose "Sending email with the security report"
Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

# Step 8: Disconnect from Microsoft Graph for email operations
Disconnect-MgGraph

Write-Verbose "Email sent successfully"
