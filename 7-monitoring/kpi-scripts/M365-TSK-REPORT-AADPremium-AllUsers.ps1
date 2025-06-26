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

# Retrieve all users and filter out guest accounts and disabled accounts
$Users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled

# Filter out guest accounts and disabled accounts
$FilteredUsers = $Users | Where-Object {
    $_.AccountEnabled -eq $true -and $_.UserPrincipalName -notlike "*EXT#@$OrganizationDomain"
}

# Initialize arrays to store users with and without the target service plans
$UsersWithTargetPlans = @()
$UsersWithoutTargetPlans = @()

# Loop through each user and check their license details
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
            # Add the user to the "with target plans" list
            $UsersWithTargetPlans += [PSCustomObject]@{
                UserPrincipalName = $User.UserPrincipalName
                DisplayName       = $User.DisplayName
                ServicePlans      = ($HasTargetPlan | ForEach-Object { 
                    if ($_.ServicePlanId -eq "41781fb2-bc02-4b7c-bd55-b576c07bb09d") {
                        "AAD_PREMIUM"
                    } elseif ($_.ServicePlanId -eq "eec0eb4f-6444-4f95-aba0-50c24d67f998") {
                        "AAD_PREMIUM_P2"
                    }
                }) -join ", "
            }
            break
        }
    }

    # If the user does not have the target plans, add them to the "without target plans" list
    if (-not $HasTargetPlan) {
        $UsersWithoutTargetPlans += [PSCustomObject]@{
            UserPrincipalName = $User.UserPrincipalName
            DisplayName       = $User.DisplayName
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

# Generate the table for users with target plans
$TableWithTargetPlans = $UsersWithTargetPlans | ConvertTo-Html -Head $CSSStyle -Title "Users with AAD Premium Plans" | Out-String

# Generate the table for users without target plans
$TableWithoutTargetPlans = $UsersWithoutTargetPlans | ConvertTo-Html -Head $CSSStyle -Title "Users without AAD Premium Plans" | Out-String

# Combine both tables into the HTML report
$htmlContent = @"
<h2>AADPremium service plan report from Rubicon Cloud Advisor</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" hight="10%" alt="Banner Image" class="banner">
<h4>Organization Domain: $OrganizationDomain</h4>
<p>This report contains two tables:</p>
<ul>
    <li>Users with AAD_PREMIUM or AAD_PREMIUM_P2 service plans.</li>
    <li>Users without AAD_PREMIUM or AAD_PREMIUM_P2 service plans.</li>
</ul>
<h3>Users with AAD Premium Plans</h3>
$TableWithTargetPlans
<h3>Users without AAD Premium Plans</h3>
$TableWithoutTargetPlans
"@


# Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
$params = @{
	message = @{
		subject = "AADPremium service plan report from Rubicon Cloud Advisor"
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
Write-Verbose "Sending email with the Secure Score report"
Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

# Disconnect from Microsoft Graph for email operations
Disconnect-MgGraph

Write-Verbose "Email sent successfully"