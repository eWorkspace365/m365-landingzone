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
$yesterday = (Get-Date).AddDays(-0).Date

# ---------------- Process audits for yesterday ----------------
$results = @()
Write-Host "Processing events for yesterday: $yesterday" -ForegroundColor Yellow

foreach ($audit in $DirectoryAudits) {
    # Parse event date
    try { $eventDate = ([DateTime]$audit.activityDateTime).Date } catch { continue }

    if ($eventDate -eq $yesterday) {
        # InitiatedBy
        $initiatedBy = if ($audit.initiatedBy.user.displayName) {
            $audit.initiatedBy.user.displayName
        } elseif ($audit.initiatedBy.app.displayName) {
            $audit.initiatedBy.app.displayName
        } else {
            "Unknown"
        }

        # TargetResources
        $targetResourceDisplayName = if ($audit.targetResources) {
            $audit.targetResources | ForEach-Object { $_.displayName } | Where-Object { $_ -ne $null } | Out-String
        } else { "None" }

        # ModifiedProperties
        $modifiedProperties = if ($audit.targetResources) {
            $audit.targetResources | ForEach-Object {
                $_.modifiedProperties | ForEach-Object {
                    "Property: $($_.displayName), OldValue: $($_.oldValue), NewValue: $($_.newValue)"
                }
            } | Out-String
        } else { "None" }

        # Filter criteria
        if ($audit.Category -ne "Agreement" -and $audit.ActivityDisplayName -ne "Self-service password reset flow activity progress" -and $audit.ActivityDisplayName -ne "Update device local administrator password" -and $audit.initiatedBy.app.displayName -ne "Azure AD Cloud Sync" -and $audit.initiatedBy.app.displayName -ne "Azure AD PIM" -and $audit.initiatedBy.app.displayName -ne "Microsoft Office 365 Portal" -and $audit.initiatedBy.user.displayName -ne "Microsoft Office 365 Portal" -and $audit.initiatedBy.app.displayName -ne "Microsoft password reset service" -and $audit.initiatedBy.app.displayName -ne "Azure MFA StrongAuthenticationService") {
            Write-Host "Audit entry matches filter criteria." -ForegroundColor Green
            $results += [PSCustomObject]@{
                ActivityDateTime   = $audit.activityDateTime
                ActivityDisplayName = $audit.activityDisplayName
                InitiatedBy        = $initiatedBy
                Category           = $audit.Category
                ResultReason       = $audit.resultReason
                OperationType      = $audit.operationType
                Result             = $audit.result
                ModifiedProperties = $modifiedProperties.Trim()  # Remove extra whitespace
            }
        } else {
            Write-Host "Audit entry does not match filter criteria." -ForegroundColor Red
        }
    }
}

Write-Host "Total events for yesterday: $($results.Count)" -ForegroundColor Cyan

# Export results to JSON file
$JsonFilePath = "DirectoryAuditsReport.json"
$results | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonFilePath -Encoding UTF8
Write-Host "Results exported to $JsonFilePath" -ForegroundColor Cyan


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
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" height="10%" alt="Banner Image" class="banner">
<h4>Organization Domain: $OrganizationDomain</h4>
<p>This report lists all directory audits retrieved from Microsoft Graph for yesterday ($yesterday).</p>
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
