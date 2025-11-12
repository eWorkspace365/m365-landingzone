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
$subscriptions = Get-AzSubscription

# Define the time range for the cost analysis (entire previous month)
$startDate = (Get-Date -Day 1 -Hour 0 -Minute 0 -Second 0).AddMonths(-1).ToString("yyyy-MM-dd")
$endDate = (Get-Date -Day 1 -Hour 0 -Minute 0 -Second 0).AddDays(-1).ToString("yyyy-MM-dd")

# Initialize an array to store cost data
$costData = @()

# Loop through each subscription
foreach ($subscription in $subscriptions) {
    Write-Host "Processing subscription: $($subscription.Name)" -ForegroundColor Green

    # Set the current subscription context
    Set-AzContext -SubscriptionId $subscription.Id

    # Query cost data using the Get-AzConsumptionUsageDetail cmdlet
    $usageDetails = Get-AzConsumptionUsageDetail -StartDate $startDate -EndDate $endDate -Expand MeterDetails -Top 1000

    # Process usage details
    foreach ($usage in $usageDetails) {
        $costData += [PSCustomObject]@{
            SubscriptionName = $subscription.Name
            SubscriptionId   = $subscription.Id
            ConsumedService  = $usage.ConsumedService
            MeterCategory    = $usage.MeterDetails.MeterCategory
            MeterSubCategory = $usage.MeterDetails.MeterSubCategory
            MeterName        = $usage.MeterDetails.MeterName
            InstanceName     = $usage.InstanceName
            InstanceLocation = $usage.InstanceLocation
            UsageQuantity    = $usage.UsageQuantity
            PretaxCost       = $usage.PretaxCost
            Currency         = $usage.Currency
        }
    }
}

# Group data by MeterCategory and calculate total cost
$totalCostByCategory = $costData | Group-Object -Property MeterCategory | ForEach-Object {
    [PSCustomObject]@{
        Category    = $_.Name
        Description = ($_.Group | Select-Object -ExpandProperty MeterName -Unique) -join ", "
        Location    = ($_.Group | Select-Object -ExpandProperty InstanceLocation -Unique) -join ", "
        TotalCost   = [math]::Round(($_.Group | Measure-Object -Property PretaxCost -Sum).Sum, 2)
        Currency    = ($_.Group | Select-Object -ExpandProperty Currency -Unique) -join ", "
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

$HTMLTable = $totalCostByCategory | ConvertTo-Html -Head $CSSStyle -Title "Azure Cost Report" | Out-String

$htmlContent = @"
<h2>Azure Cost Report</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" hight="10%" alt="Banner Image" class="banner">
<h4>Organization Domain: $OrganizationDomain</h4>
<p>This report lists the total Azure cost grouped by Category for the last month ($startDate to $endDate).</p>
<h3>Cost Details</h3>
$HTMLTable
"@

# Connect to Microsoft Graph for email operations
Write-Host "Connecting to Microsoft Graph for email operations..." -ForegroundColor DarkGray
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
$params = @{
    message = @{
        subject = "Azure Cost Report by Rubicon Cloud Advisor"
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
