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
    [String]$OrganizationDomain 
)

# Connect to Microsoft Graph
Connect-MgGraph -ClientId $AADClientId -TenantId $TenantId -CertificateThumbprint $AADThumbprint

# Define the service plan IDs for AAD_PREMIUM and AAD_PREMIUM_P2
$TargetServicePlans = @(
    "41781fb2-bc02-4b7c-bd55-b576c07bb09d", # AAD_PREMIUM
    "eec0eb4f-6444-4f95-aba0-50c24d67f998"  # AAD_PREMIUM_P2
)

# Define the target roles
$TargetRoles = @(
    "Global Administrator",
    "Authentication Administrator",
    "Billing Administrator",
    "Conditional Access Administrator",
    "Exchange Administrator",
    "Helpdesk Administrator",
    "Security Administrator",
    "SharePoint Administrator",
    "User Administrator"
)

# Retrieve all users and filter out guest accounts and disabled accounts
$Users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled

# Filter out guest accounts and disabled accounts
$FilteredUsers = $Users | Where-Object {
    $_.AccountEnabled -eq $true -and $_.UserPrincipalName -notlike "*EXT#@$OrganizationDomain"
}

# Retrieve all role assignments
$RoleAssignments = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" -Method GET

# Retrieve all role definitions
$RoleDefinitions = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions" -Method GET

# Initialize an array to store users without premium plans and with target roles
$UsersWithoutPremiumWithRoles = @()

# Loop through each user and check their license details and roles
foreach ($User in $FilteredUsers) {
    # Get license details for the user
    $LicenseDetails = Get-MgUserLicenseDetail -UserId $User.Id

    # Check if the user's service plans include AAD_PREMIUM or AAD_PREMIUM_P2
    $HasTargetPlan = $false
    foreach ($License in $LicenseDetails) {
        $HasTargetPlan = $License.ServicePlans | Where-Object {
            $_.ServicePlanId -in $TargetServicePlans
        }
        if ($HasTargetPlan) {
            break
        }
    }

    # If the user does not have the target plans, check their roles
    if (-not $HasTargetPlan) {
        # Find role assignments for the user
        $UserRoleAssignments = $RoleAssignments.value | Where-Object { $_.principalId -eq $User.Id }

        # Check if the user has any of the target roles
        $UserRoles = @()
        foreach ($Assignment in $UserRoleAssignments) {
            $RoleDefinition = $RoleDefinitions.value | Where-Object { $_.id -eq $Assignment.roleDefinitionId }
            if ($RoleDefinition.displayName -in $TargetRoles) {
                $UserRoles += $RoleDefinition.displayName
            }
        }

        # If the user has a target role, add them to the list
        if ($UserRoles.Count -gt 0) {
            $UsersWithoutPremiumWithRoles += [PSCustomObject]@{
                UserPrincipalName = $User.UserPrincipalName
                DisplayName       = $User.DisplayName
                Roles             = $UserRoles -join ", "
            }
        }
    }
}

# Generate HTML report
$CSSStyle = "<style>
table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
table td, th {border: 1px solid #ddd; padding: 8px;}
table tr:nth-child(even){background-color: #F39C12;}
table tr:hover {background-color: #ddd;}
table th { padding-top: 10px; padding-bottom: 10px; text-align: left; background-color: #F39C12; color: white;}
</style>"

# Generate the table for users without premium plans and with target roles
$TableWithoutPremiumWithRoles = $UsersWithoutPremiumWithRoles | ConvertTo-Html -Head $CSSStyle -Title "Users without Premium Plans and with Target Roles" | Out-String

# Combine the table into the HTML report
$htmlContent = @"
<h2>Users without Premium Plans and with Target Roles Report</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" hight="10%" alt="Banner Image" class="banner">
<h4>Organization Domain: $OrganizationDomain</h4>
<p>This report lists users who do not have AAD_PREMIUM or AAD_PREMIUM_P2 service plans but are assigned one or more of the following roles:</p>
<ul>
    <li>Global Administrator</li>
    <li>Authentication Administrator</li>
    <li>Billing Administrator</li>
    <li>Conditional Access Administrator</li>
    <li>Exchange Administrator</li>
    <li>Helpdesk Administrator</li>
    <li>Security Administrator</li>
    <li>SharePoint Administrator</li>
    <li>User Administrator</li>
</ul>
<h3>Administrative Account without Premium Plans</h3>
$TableWithoutPremiumWithRoles
"@

# Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
$params = @{
    message = @{
        subject = "Users without Premium Plans and with Target Roles Report"
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
