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
    [String]$EXOThumbprint
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

# Disable inactive devices
 foreach ($InactiveDevice in $InactiveDevices) {
     try {
         Update-MgBetaDevice -DeviceId $InactiveDevice.Id -AccountEnabled:$false
         Write-Host "Disabled device: $($InactiveDevice.DisplayName)"
     } catch {
         Write-Host "Failed to disable device: $($InactiveDevice.DisplayName). Error: $($_.Exception.Message)"
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
$htmlReport = @"
<h2>Inactive Devices Report</h2>
<img src="https://media.licdn.com/dms/image/v2/D4E3DAQF-xBYggSs4nQ/image-scale_191_1128/B4EZUUJtBnH0Ac-/0/1739799843917/rubicon_cover?e=2147483647&v=beta&t=uQFvS1K0FL__Uz51FhdBQmwyaVdpYiT0fjv3V4eEF-g" alt="Banner Image" class="banner">
<p>This email reports on devices that have been inactive for $DaysInactive days or more. These devices are NOT automatically disabled.</p>
<p>Report generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") </p>
<h3>EntraID Joined Devices</h3>
$EntraIDTable
<h3>Registered Devices</h3>
$RegisteredTable
<h3>Other Devices</h3>
$OtherDevicesTable
"@

# Define the email message
$Message = @{
    subject = "Microsoft 365 Report: Inactive Devices by Group";
    toRecipients = @(@{
        emailAddress = @{
            address = $EXOMailTo;
        }
    });
    body = @{
        contentType = "HTML";
        content = $htmlReport
    }
}

# Connect to Microsoft Graph for sending email
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Send the email
Write-Host "Sending email report..." -ForegroundColor DarkGray
Send-MgUserMail -UserId $EXOMailFrom -Message $Message

# Disconnect from Microsoft Graph
Disconnect-MgGraph

Write-Host "Script completed successfully!" -ForegroundColor Green
