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

# Step 1: Authenticate and get Bearer token for Defender for Endpoint API
Write-Verbose "Authenticating to Defender for Endpoint API"
$ResourceAppIdUri = "https://securitycenter.onmicrosoft.com/windowsatpservice"
$OAuthUri = "https://login.microsoftonline.com/$TenantID/oauth2/token"
$AuthBody = @{
    resource = $ResourceAppIdUri
    client_id = $SECClientId
    client_secret = $SECAppSecret
    grant_type = "client_credentials"
}
$AuthResponse = Invoke-RestMethod -Method Post -Uri $OAuthUri -Body $AuthBody -ErrorAction Stop
$BearerToken = $AuthResponse.access_token


Write-Verbose "Running script with verbose output enabled"

# Step 2: Set Exposure Insights API URI
Write-Verbose "Setting Exposure Insights API URI"
$ExposureInsightsUri = "https://api.security.microsoft.com/api/exposureInsights"

# Get exposure insights from Defender for Endpoint API
Write-Verbose "Getting exposure insights from Defender for Endpoint API"
$Headers = @{
    Authorization = "Bearer $BearerToken"
    "Content-Type" = "application/json"
}
$ExposureInsightsResponse = Invoke-RestMethod -Uri $ExposureInsightsUri -Method Get -Headers $Headers -ErrorAction Stop

# Step 3: Generate HTML table for exposure insights
$CSSStyle = "<style>
table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
table td, th {border: 1px solid #ddd; padding: 8px;}
table tr:nth-child(even){background-color: #F39C12;}
table tr:hover {background-color: #ddd;}
table th { padding-top: 10px; padding-bottom: 10px; text-align: left; background-color: #F39C12; color: white;}
</style>"

# Generate HTML table for exposure insights
$ExposureInsightsTable = $ExposureInsightsResponse.value | ForEach-Object {
    [PSCustomObject]@{
        "Insight Name" = $_.insightName
        "Category" = $_.category
        "Severity" = $_.severity
        "Affected Assets" = $_.affectedAssets
        "Status" = $_.status
    }
} | ConvertTo-Html -Head $CSSStyle -Title "Exposure Insights Report" | Out-String

# Combine all tables into a single HTML report
$htmlContent = @"
<h2>Exposure Insights Report from Rubicon Cloud Advisor</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" height="10%" alt="Banner Image" class="banner">
<p>This email contains the latest exposure insights details.</p>
<h3>Exposure Insights Report</h3>
$ExposureInsightsTable
"@

# Step 4: Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantID -CertificateThumbprint $EXOThumbprint

# Step 5: Define the email message
$params = @{
    message = @{
        subject = "Exposure Insights Report from Rubicon Cloud Advisor"
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

# Step 6: Send the email
Write-Verbose "Sending email with the exposure insights report"
Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

# Step 7: Disconnect from Microsoft Graph for email operations
Disconnect-MgGraph

Write-Verbose "Email sent successfully"
