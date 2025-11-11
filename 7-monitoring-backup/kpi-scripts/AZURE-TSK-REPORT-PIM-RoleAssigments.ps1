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

# Connect to Azure using the provided parameters
Write-Host "Connecting to Azure..." -ForegroundColor DarkGray
Connect-AzAccount -CertificateThumbprint $AADThumbprint -ApplicationId $AADClientId -Tenant $TenantId

# Get all subscriptions
Write-Host "Retrieving Azure subscriptions..." -ForegroundColor DarkGray
$subscriptions = Get-AzSubscription

# Initialize an array to store the results
$results = @()

# Loop through each subscription
Write-Host "Retrieving role assignments for Azure subscriptions..." -ForegroundColor DarkGray
foreach ($subscription in $subscriptions) {
    # Set the current subscription context
    Set-AzContext -SubscriptionId $subscription.Id

    # Get role assignments at the subscription level
    $roleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$($subscription.Id)"

    # Add the role assignments to the results array
    foreach ($roleAssignment in $roleAssignments) {
        $results += [PSCustomObject]@{
            SubscriptionId   = $subscription.Id
            SubscriptionName = $subscription.Name
            RoleAssignment   = $roleAssignment.RoleDefinitionName
            ObjectType       = $roleAssignment.ObjectType
            PrincipalName    = $roleAssignment.DisplayName
        }
    }
}

# Generate HTML report
Write-Host "Generating HTML report for Azure subscriptions..." -ForegroundColor DarkGray
$CSSStyle = "<style>
table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
table td, th {border: 1px solid #ddd; padding: 8px;}
table tr:nth-child(even){background-color: #F39C12;}
table tr:hover {background-color: #ddd;}
table th { padding-top: 10px; padding-bottom: 10px; text-align: left; background-color: #F39C12; color: white;}
</style>"

$HTMLTable = $results | ConvertTo-Html -Head $CSSStyle -Title "Azure Subscription Role Assignments Report" | Out-String

$htmlContent = @"
<h2>Azure Subscription Role Assignments Report</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" hight="10%" alt="Banner Image" class="banner">
<h4>Organization Domain: $OrganizationDomain</h4>
<p>This report lists all role assignments at the subscription level for your Azure environment.</p>
<h3>Role Assignments</h3>
$HTMLTable
"@

# Connect to Microsoft Graph for email operations
Write-Host "Connecting to Microsoft Graph for email operations..." -ForegroundColor DarkGray
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
$params = @{
    message = @{
        subject = "Azure Subscription Role Assignments Report"
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
