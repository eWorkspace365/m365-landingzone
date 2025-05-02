[CmdletBinding()]
param( 
    [Parameter(Mandatory=$true)]
    [String]$TenantID,
    
    [Parameter(Mandatory=$false)]
    [String]$AADClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$AADThumbprint,
    
    [Parameter(Mandatory=$true)]
    [String]$EXOMailFrom,
    
    [Parameter(Mandatory=$true)]
    [String]$EXOMailTo,
    
    [Parameter(Mandatory=$true)]
    [String]$EXOClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOThumbprint,
    
    [Parameter(Mandatory=$true)]
    [String]$AppSecret
)

set-strictmode -version Latest
$ErrorActionPreference = "stop"

# Step 1: Authenticate and get Bearer token for Defender for Endpoint API
Write-Verbose "Authenticating to Defender for Endpoint API"
$ResourceAppIdUri = "https://securitycenter.onmicrosoft.com/windowsatpservice"
$OAuthUri = "https://login.microsoftonline.com/$TenantID/oauth2/token"
$AuthBody = @{
    resource = $ResourceAppIdUri
    client_id = $AADClientId
    client_secret = $AppSecret
    grant_type = "client_credentials"
}
$AuthResponse = Invoke-RestMethod -Method Post -Uri $OAuthUri -Body $AuthBody -ErrorAction Stop
$BearerToken = $AuthResponse.access_token

# Connect to Microsoft Graph for Secure Score operations
Connect-MgGraph -ClientId $AADClientId -TenantId $TenantID -CertificateThumbprint $AADThumbprint

Write-Verbose "Running script with verbose output enabled"

# Step 2: Set Graph API URIs
Write-Verbose "Setting Graph API URIs"
$AzureDevicesUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=azureADDeviceId,deviceName,operatingSystem,userPrincipalName,userDisplayName"
$RecommendationsUri = "https://api.securitycenter.microsoft.com/api/recommendations"

# Get managed devices from Graph API
Write-Verbose "Getting managed devices from Graph API"
$AzureDevicesResponse = (Invoke-MgGraphRequest -Uri $AzureDevicesUri -Method Get).value

# Display devices in console output
Write-Verbose "Displaying managed devices in console output"
foreach ($device in $AzureDevicesResponse) {
    Write-Output "Device Name: $($device.deviceName)"
    Write-Output "Operating System: $($device.operatingSystem)"
    Write-Output "Azure AD Device ID: $($device.azureADDeviceId)"
    Write-Output "User Principal Name: $($device.userPrincipalName)"
    Write-Output "User Display Name: $($device.userDisplayName)"
    Write-Output "---------------------------------------------"
}

# Get security recommendations from Defender for Endpoint API
Write-Verbose "Getting security recommendations from Defender for Endpoint API"
$Headers = @{
    Authorization = "Bearer $BearerToken"
    "Content-Type" = "application/json"
}
$RecommendationsResponse = Invoke-RestMethod -Uri $RecommendationsUri -Method Get -Headers $Headers -ErrorAction Stop

# Display recommendations in console output
Write-Verbose "Displaying security recommendations in console output"
foreach ($recommendation in $RecommendationsResponse.value) {
    Write-Output "Recommendation Name: $($recommendation.recommendationName)"
    Write-Output "Recommendation Category: $($recommendation.recommendationCategory)"
    Write-Output "Remediation Type: $($recommendation.remediationType)"
	Write-Output "Total Machine Count: $($recommendation.totalMachineCount)"
    Write-Output "Exposed Machines Count: $($recommendation.exposedMachinesCount)"
    Write-Output "Status: $($recommendation.status)"
    Write-Output "---------------------------------------------"
}

# Disconnect from Microsoft Graph
Disconnect-MgGraph

Write-Verbose "Script execution completed"
