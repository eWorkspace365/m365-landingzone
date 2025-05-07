[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$Customer,
    
    [Parameter(Mandatory=$false)]
    [String]$TenantID,
    
    [Parameter(Mandatory=$false)]
    [String]$AppID,
    
    [Parameter(Mandatory=$false)]
    [String]$CertificateThumbprint

)

try {
    . "./GeneralFunctions.ps1"
}
catch {
    Write-Output "Error while loading supporting PowerShell Scripts $error"
    exit
}

$timeStart = get-date -f "dd MMMM yyyy HH:mm:ss"
$sw = [Diagnostics.Stopwatch]::StartNew()
$timeStart

# Connect to Microsoft Graph API
Connect-MgGraph -ClientId $AppID -TenantId $TenantID -CertificateThumbprint $CertificateThumbprint


$DaysInactive = 45
$time = (Get-Date).Adddays(-($DaysInactive))

Write-Host "Get Risky Users $($sw.Elapsed.Hours.ToString("00")):$($sw.Elapsed.Minutes.ToString("00")):$($sw.Elapsed.Seconds.ToString("00"))" -ForegroundColor DarkGray

# Get risky users
$DaysRange = (Get-Date).AddDays(-30) 
$datetime = Get-Date ($DaysRange).ToUniversalTime() -UFormat '+%Y-%m-%dT%H:%M:%S.000Z' 
$RiskyUsers = Get-MgRiskyUser -filter "riskLastUpdatedDateTime ge $datetime"

# Prepare report
$report = $riskyUsers | ForEach-Object {
    [PSCustomObject]@{
        UserPrincipalName = $_.UserPrincipalName
		RiskLastUpdatedDateTime = $_.RiskLastUpdatedDateTime
		RiskLevel = $_.RiskLevel
        IsProcessing = $_.IsProcessing
		RiskDetail = $_.RiskDetail
		Id = $_.Id
		IsDeleted = $_.IsDeleted
        RiskState = $_.RiskState
        UserDisplayName = $_.UserDisplayName
    }
}
SaveObjectToJsonFile -klantnaam $Customer -filename "entraid-riskyusers.json" -itemToSave $report

# Get risky detections
Write-Host "Get Risk Detections $($sw.Elapsed.Hours.ToString("00")):$($sw.Elapsed.Minutes.ToString("00")):$($sw.Elapsed.Seconds.ToString("00"))" -ForegroundColor DarkGray
$RiskyDetections = Get-MgRiskDetection
$report = $RiskyDetections | ForEach-Object {
      [PSCustomObject]@{
      Activity = $riskyDetection.activity
      RiskEventType = $_.riskEventType
      RiskLevel = $_.riskLevel
      RiskState = $_.riskState
      ActivityDateTime = $_.activityDateTime
      DetectedDateTime = $_.detectedDateTime
      LastUpdatedDateTime = $_.lastUpdatedDateTime
      UserDisplayName = $_.userDisplayName
      UserPrincipalName = $_.userPrincipalName
      UserId = $_.userId     
      IPAddress = $_.ipAddress
      Location = $_.location
    }       
}
SaveObjectToJsonFile -klantnaam $Customer -filename "entraid-riskdetections.json" -itemToSave $report

# Define the properties we want to retrieve
$Properties = @(
    'Id', 'DisplayName', 'Mail', 'UserPrincipalName', 'UserType', 'AccountEnabled', 'SignInActivity', 'CreatedDateTime'
)

Write-Host "Get Inactive Users $($sw.Elapsed.Hours.ToString("00")):$($sw.Elapsed.Minutes.ToString("00")):$($sw.Elapsed.Seconds.ToString("00"))" -ForegroundColor DarkGray

# Get all inactive users
$InactiveUsers = Get-MgUser -All -Property $Properties | 
    Where-Object {
        ($_.SignInActivity.LastSignInDateTime -lt $time -or $null -eq $_.SignInActivity.LastSignInDateTime) -and 
        $_.AccountEnabled -eq $True
    } | ForEach-Object {
    $LastSuccessfulSignInDate = if ($_.SignInActivity.LastSignInDateTime) {
        $_.SignInActivity.LastSignInDateTime
    } else {
        "Never Signed-in"
    }

    $DaysSinceLastSignIn = if ($_.SignInActivity.LastSignInDateTime) {
        (New-TimeSpan -Start $_.SignInActivity.LastSignInDateTime -End (Get-Date)).Days
    } else {
        "N/A"
    }

    [PSCustomObject]@{
        Id                       = $_.Id
        UserPrincipalName        = $_.UserPrincipalName
        DisplayName              = $_.DisplayName
        Email                    = $_.Mail
        UserType                 = $_.UserType
        AccountEnabled           = $_.AccountEnabled
        LastSuccessfulSignInDate = $LastSuccessfulSignInDate
        DaysSinceLastSignIn      = $DaysSinceLastSignIn
        CreatedDateTime          = $_.CreatedDateTime
    }
}
SaveObjectToJsonFile -klantnaam $Customer -filename "entraid-inactive-users.json" -itemToSave $InactiveUsers


Write-Host "Get Inactive Devices $($sw.Elapsed.Hours.ToString("00")):$($sw.Elapsed.Minutes.ToString("00")):$($sw.Elapsed.Seconds.ToString("00"))" -ForegroundColor DarkGray

# Define the properties we want to retrieve
$Properties = @('DisplayName', 'DeviceId', 'OperatingSystem', 'OperatingSystemVersion', 'AccountEnabled', 'ApproximateLastSignInDateTime', 'ProfileType', 'TrustType')

# Get all devices
$Devices = Get-MgDevice -All -Property $Properties

# Filter inactive devices
$InactiveDevices = $Devices | ForEach-Object {
    $device = $_
    $LastSignInDate = $device.ApproximateLastSignInDateTime
    
    if ($LastSignInDate) {
        $DaysSinceLastSignIn = ((Get-Date) - $LastSignInDate).Days
    } else {
        $DaysSinceLastSignIn = $null
    }
    
    # Only include devices inactive for $DaysInactive days or more
    if ($null -eq $LastSignInDate -or $LastSignInDate -le $time) {
        [PSCustomObject]@{
            DisplayName                   = $device.DisplayName
            DeviceId                      = $device.DeviceId
            DeviceOSType                  = $device.OperatingSystem
            DeviceOSVersion               = $device.OperatingSystemVersion
            AccountEnabled                = $device.AccountEnabled
            ApproximateLastLogonTimeStamp = $LastSignInDate
            DaysSinceLastSignIn           = $DaysSinceLastSignIn
            ProfileType                   = $device.ProfileType
            TrustType                     = $device.TrustType
        }
    }
}
SaveObjectToJsonFile -klantnaam $Customer -filename "entraid-inactive-devices.json" -itemToSave $InactiveDevices


#region Get Expiring App Credentials
Write-Host "Get Expired Apps $($sw.Elapsed.Hours.ToString("00")):$($sw.Elapsed.Minutes.ToString("00")):$($sw.Elapsed.Seconds.ToString("00"))" -ForegroundColor DarkGray

$applications = Get-MgApplication -All
[System.Collections.ArrayList]$arrayExpiringAADObjects = @()
$days = 45

$now = get-date
foreach ($app in $applications) {
    $appName = $app.DisplayName
    $appID = $app.Id
    $appCreds = $app.PasswordCredentials + $app.KeyCredentials

    foreach ($cred in $app.PasswordCredentials) {
        $startDate = $cred.StartDateTime
        $endDate = $cred.EndDateTime
        $operation = $EndDate - $now
        $oDays = $operation.Days
        
        if ($oDays -le $days) {
            $owner = Get-MgApplicationOwner -ApplicationId $app.Id
            $username = $owner.UserPrincipalName -join ";"
            $ownerID = $owner.Id -join ";"
            if ($null -eq $owner.UserPrincipalName) {
                $username = $owner.DisplayName + " **<This is an Application>**"
            }
            if ($null -eq $owner.DisplayName) {
                $username = "<<No Owner>>"
            }

            $obj = New-Object System.Object
    
            $obj | Add-Member -MemberType NoteProperty -Name "ApplicationName" -Value $appName
            $obj | Add-Member -MemberType NoteProperty -Name "ApplicationID" -Value $appID
            $obj | Add-Member -MemberType NoteProperty -Name "Secret Start Date" -Value $startDate
            $obj | Add-Member -MemberType NoteProperty -Name "Secret End Date" -value $endDate
            $obj | Add-Member -MemberType NoteProperty -Name "Certificate Start Date" -Value $null
            $obj | Add-Member -MemberType NoteProperty -Name "Certificate End Date" -value $null
            $obj | Add-Member -MemberType NoteProperty -Name "Owner" -Value $username
            $obj | Add-Member -MemberType NoteProperty -Name "Owner_ObjectID" -value $ownerID

            $null = $arrayExpiringAADObjects.Add($obj)
        }
    }

    foreach ($cert in $app.KeyCredentials) {
        $certStartDate = $cert.StartDateTime
        $certEndDate = $cert.EndDateTime
        $certOperation = $certEndDate - $now
        $certODays = $certOperation.Days

        if ($certODays -le $days) {
            $owner = Get-MgApplicationOwner -ApplicationId $app.Id
            $username = $owner.UserPrincipalName -join ";"
            $ownerID = $owner.Id -join ";"
            if ($null -eq $owner.UserPrincipalName) {
                $username = $owner.DisplayName + " **<This is an Application>**"
            }
            if ($null -eq $owner.DisplayName) {
                $username = "<<No Owner>>"
            }

            $obj = New-Object System.Object

            $obj | Add-Member -MemberType NoteProperty -Name "ApplicationName" -Value $appName
            $obj | Add-Member -MemberType NoteProperty -Name "ApplicationID" -Value $appID
            $obj | Add-Member -MemberType NoteProperty -Name "Secret Start Date" -Value $null
            $obj | Add-Member -MemberType NoteProperty -Name "Secret End Date" -value $null
            $obj | Add-Member -MemberType NoteProperty -Name "Certificate Start Date" -Value $certStartDate
            $obj | Add-Member -MemberType NoteProperty -Name "Certificate End Date" -value $certEndDate
            $obj | Add-Member -MemberType NoteProperty -Name "Owner" -Value $username
            $obj | Add-Member -MemberType NoteProperty -Name "Owner_ObjectID" -value $ownerID

            $null = $arrayExpiringAADObjects.Add($obj)
        }
    }
}

SaveObjectToJsonFile -klantnaam $Customer -filename "entraid-appregistrations.json" -itemToSave $arrayExpiringAADObjects

