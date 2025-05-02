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
    [String]$OrganizationDomain,

    [Parameter(Mandatory=$false)]
    [String]$AADExclusion1,
	
	    [Parameter(Mandatory=$false)]
    [String]$AADExclusion2,
	
	    [Parameter(Mandatory=$false)]
    [String]$AADExclusion3,
	
	    [Parameter(Mandatory=$false)]
    [String]$AADExclusion4,
	
	    [Parameter(Mandatory=$false)]
    [String]$AADExclusion5,
	
	    [Parameter(Mandatory=$false)]
    [String]$AADExclusion6
)

#Connect to PnP Online
Connect-MgGraph -ClientId $AADClientId -TenantId $TenantId -CertificateThumbprint $AADThumbprint

$CSSStyle = "<style>
table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
table td, th {border: 1px solid #ddd; padding: 8px;}
table tr:nth-child(even){background-color: #F39C12;}
table tr:hover {background-color: #ddd;}
table th { padding-top: 10px; padding-bottom: 10px; text-align: left; background-color: #F39C12; color: white;}
</style>"

$version = $host | Select-Object Version
If($version.Version.Major -gt 1) {$host.Runspace.ThreadOptions = "ReuseThread"}
$timeStart = get-date -f "dd MMMM yyyy HH:mm:ss"
$sw = [Diagnostics.Stopwatch]::StartNew()
$timeStart

$time = (Get-Date).Adddays(-($DaysInactive))

# Define the NewUserThresholdDate parameter
$NewUserThresholdDate = (Get-Date).AddDays(-30) # Example: exclude users created in the last 90 days

# Define the properties we want to retrieve
$Properties = 'Id,DisplayName,Mail,UserPrincipalName,UserType,AccountEnabled,SignInActivity,CreatedDateTime'

# Define the exclusion list
$ExclusionList = @($AADExclusion1, $AADExclusion1, $AADExclusion2, $AADExclusion3, $AADExclusion4, $AADExclusion5, $AADExclusion6)

Write-Host "Get Inactive Users $($sw.Elapsed.Hours.ToString("00")):$($sw.Elapsed.Minutes.ToString("00")):$($sw.Elapsed.Seconds.ToString("00"))" -ForegroundColor DarkGray

# Get all inactive users excluding those in the exclusion list
$InactiveUsers = Get-MgUser -All -Property $Properties | 
    Where-Object {
        ($_.SignInActivity.LastSignInDateTime -lt $time -or $null -eq $_.SignInActivity.LastSignInDateTime) -and 
        $_.AccountEnabled -eq $True -and
        $_.CreatedDateTime -lt $NewUserThresholdDate -and
        -not ($_.UserPrincipalName -in $ExclusionList)
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
        UserPrincipalName        = $_.UserPrincipalName
        DisplayName              = $_.DisplayName
        UserType                 = $_.UserType
        AccountEnabled           = $_.AccountEnabled
        LastSuccessfulSignInDate = $LastSuccessfulSignInDate
        DaysSinceLastSignIn      = $DaysSinceLastSignIn
        CreatedDateTime          = $_.CreatedDateTime
    }
}

# Group users based on UserType
$EntraIDGuests = $InactiveUsers | Where-Object { $_.UserType -eq "Guest" }
$EntraIDMembers = $InactiveUsers | Where-Object { $_.UserType -eq "Member" }

# Generate HTML report as a string
$GuestsTable = $EntraIDGuests | ConvertTo-Html -Head $CSSStyle | Out-String
$MembersTable = $EntraIDMembers | ConvertTo-Html -Head $CSSStyle | Out-String

# Combine all tables into a single HTML report
$htmlContent = @"
<h2>Inactive user report from Rubicon Cloud Advisor</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" hight="10%" alt="Banner Image" class="banner">
<h4>Organization Domain: $OrganizationDomain</h4>
<p>This email reports users that have been inactive for $DaysInactive days or more. These users are NOT automatically disabled.</p>
<h3>Guests</h3>
$GuestsTable
<h3>Members</h3>
$MembersTable
"@




# Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
$params = @{
	message = @{
		subject = "Inactive user report from Rubicon Cloud Advisor"
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