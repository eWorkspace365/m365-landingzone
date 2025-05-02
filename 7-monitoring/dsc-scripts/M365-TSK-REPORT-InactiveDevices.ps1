[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$DaysInactive,
    
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
Connect-MgGraph -ClientId $AADClientId -TenantId $TenantId -CertificateThumbprint $AADThumbprint

# Set the inactivity threshold
$DaysInactive = 45
$time = (Get-Date).Adddays(-($DaysInactive))

# Define the Graph API endpoint for devices
$Endpoint = "https://graph.microsoft.com/v1.0/devices"

# Retrieve devices using the Graph API
Write-Host "Retrieving all devices..." -ForegroundColor DarkGray
$Devices = Invoke-MgGraphRequest -Uri $Endpoint -Method GET

# Parse the JSON response
$Devices = $Devices.value

# Filter inactive devices
Write-Host "Filtering inactive devices..." -ForegroundColor DarkGray
$InactiveDevices = $Devices | Where-Object {
    ($_.approximateLastSignInDateTime -lt $time -or $null -eq $_.approximateLastSignInDateTime) -and 
    $_.accountEnabled -eq $True
} | ForEach-Object {
    $LastSignInDate = if ($_.approximateLastSignInDateTime) {
        $_.approximateLastSignInDateTime
    } else {
        "Never Signed-in"
    }

    $DaysSinceLastSignIn = if ($_.approximateLastSignInDateTime) {
        (New-TimeSpan -Start $_.approximateLastSignInDateTime -End (Get-Date)).Days
    } else {
        "N/A"
    }

    [PSCustomObject]@{
        DeviceId                 = $_.id
        DisplayName              = $_.displayName
        AccountEnabled           = $_.accountEnabled
        DeviceOwnership          = $_.deviceOwnership
        TrustType                = $_.trustType
        LastSignInDate           = $LastSignInDate
        DaysSinceLastSignIn      = $DaysSinceLastSignIn
    }
}

# Group devices based on TrustType
$EntraIDDevices = $InactiveDevices | Where-Object { $_.TrustType -eq "AzureAD" }
$RegisteredDevices = $InactiveDevices | Where-Object { $_.TrustType -eq "Workplace" }
$OtherDevices = $InactiveDevices | Where-Object { $_.TrustType -notin @("AzureAD", "Workplace") }

# Generate HTML tables for each group
$CSSStyle = "<style>
table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
table td, th {border: 1px solid #ddd; padding: 8px;}
table tr:nth-child(even){background-color: #F39C12;}
table tr:hover {background-color: #ddd;}
table th { padding-top: 10px; padding-bottom: 10px; text-align: left; background-color: #F39C12; color: white;}
</style>"

$EntraIDTable = $EntraIDDevices | ConvertTo-Html -Head $CSSStyle -Title "EntraID Joined Devices" | Out-String
$RegisteredTable = $RegisteredDevices | ConvertTo-Html -Head $CSSStyle -Title "EntraID Registered Devices" | Out-String
$OtherDevicesTable = $OtherDevices | ConvertTo-Html -Head $CSSStyle -Title "Other Devices" | Out-String

# Combine all tables into a single HTML report
$htmlContent = @"
<h2>Inactive device report from Rubicon Cloud Advisor</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" hight="10%" alt="Banner Image" class="banner">
<h4>Organization Domain: $OrganizationDomain</h4>
<p>This email reports devices that have been inactive for $DaysInactive days or more. These devices are NOT automatically disabled.</p>
<h3>EntraID Joined Devices</h3>
$EntraIDTable
<h3>Registered Devices</h3>
$RegisteredTable
<h3>Other Devices</h3>
$OtherDevicesTable
"@

# Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
$params = @{
	message = @{
		subject = "Inactive device report from Rubicon Cloud Advisor"
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