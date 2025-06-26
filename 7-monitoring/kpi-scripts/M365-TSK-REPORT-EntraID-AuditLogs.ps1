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

# Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor DarkGray
Connect-MgGraph -ClientId $AADClientId -TenantId $TenantId -CertificateThumbprint $AADThumbprint

# Define the Graph API endpoint for directory audits
$DirectoryAuditsEndpoint = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"

# Retrieve directory audits using the Graph API with pagination
Write-Host "Retrieving directory audits with pagination..." -ForegroundColor DarkGray
$DirectoryAudits = @()

do {
    # Make the API call
    $DirectoryAuditsResponse = Invoke-MgGraphRequest -Uri $DirectoryAuditsEndpoint -Method GET
    
    # Add the current page of results to the array
    $DirectoryAudits += $DirectoryAuditsResponse.value
    
    # Check if there is a next page
    $DirectoryAuditsEndpoint = $DirectoryAuditsResponse.'@odata.nextLink'
} while ($DirectoryAuditsEndpoint)

# Initialize an array to store the filtered results
$results = @()

# Get yesterday's date (date only, no time)
$yesterday = (Get-Date).AddDays(-1).Date
Write-Host "Filtering events for yesterday: $yesterday" -ForegroundColor Yellow

# Process directory audits
Write-Host "Processing directory audits..." -ForegroundColor DarkGray
foreach ($audit in $DirectoryAudits) {
    # Extract initiatedBy details
    $initiatedBy = if ($audit.initiatedBy.user.displayName) {
        $audit.initiatedBy.user.displayName
    } elseif ($audit.initiatedBy.app.displayName) {
        $audit.initiatedBy.app.displayName
    } else {
        "Unknown"
    }

    # Extract targetResources details
    $targetResourceDisplayName = if ($audit.targetResources) {
        $audit.targetResources | ForEach-Object { $_.displayName } | Where-Object { $_ -ne $null } | Out-String
    } else {
        "None"
    }

    # Extract modifiedProperties details
    $modifiedProperties = if ($audit.targetResources) {
        $audit.targetResources | ForEach-Object {
            $_.modifiedProperties | ForEach-Object {
                "Property: $($_.displayName), OldValue: $($_.oldValue), NewValue: $($_.newValue)"
            }
        } | Out-String
    } else {
        "None"
    }

    # Extract event date
    $eventDate = ([DateTime]$audit.activityDateTime).Date  # Parse ISO 8601 and extract only the date portion

    # Filter criteria
    if ($audit.Category -eq "GroupManagement" -and $initiatedBy -ne "Unknown" -and $initiatedBy -ne $null -and $eventDate -eq $yesterday) {
        Write-Host "Audit entry matches filter criteria." -ForegroundColor Green
        $results += [PSCustomObject]@{
            ActivityDateTime = $audit.activityDateTime
            ActivityDisplayName = $audit.activityDisplayName
            InitiatedBy = $initiatedBy
            Category = $audit.Category
            ResultReason = $audit.resultReason
            OperationType = $audit.operationType
            Result = $audit.result
            ModifiedProperties = $modifiedProperties.Trim()  # Remove extra whitespace
        }
    } else {
        Write-Host "Audit entry does not match filter criteria." -ForegroundColor Red
    }
}

# Generate HTML report
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
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" hight="10%" alt="Banner Image" class="banner">
<h4>Organization Domain: $OrganizationDomain</h4>
<p>This report lists all directory audits retrieved from Microsoft Graph.</p>
<h3>Directory Audits</h3>
$HTMLTable
"@

# Connect to Microsoft Graph for email operations
Write-Host "Connecting to Microsoft Graph for email operations..." -ForegroundColor DarkGray
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
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

# Send the email
Write-Host "Sending HTML report via email..." -ForegroundColor DarkGray
Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

# Disconnect from Microsoft Graph for email operations
Disconnect-MgGraph

Write-Host "Email sent successfully" -ForegroundColor Green
