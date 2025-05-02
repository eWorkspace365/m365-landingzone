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
    [String]$EXOThumbprint
)

set-strictmode -version Latest
$ErrorActionPreference = "stop"

# Connect to Microsoft Graph for Secure Score operations
Connect-MgGraph -ClientId $AADClientID -TenantId $TenantID -CertificateThumbprint $AADThumbprint

Write-Verbose "Running script with verbose output enabled"

# Step 1: Set Graph API URIs
Write-Verbose "Setting Graph API URIs"
$secureScoresUri = "https://graph.microsoft.com/beta/security/securescores?`$top=1" 
$secureScoreControlProfileUri = "https://graph.microsoft.com/beta/security/secureScoreControlProfiles"

# Build table objects for final scores and final reports
Write-Verbose "Creating Objects for final report"
$DetailedControlScoresTable = New-Object 'System.Collections.Generic.List[System.Object]'
$FinalSecureScoreReport = New-Object 'System.Collections.Generic.List[System.Object]'

# Get latest secure score from Graph API
Write-Verbose "Getting latest Secure Score from Graph API"
$secureScoreLatest = (Invoke-MgGraphRequest -Uri $secureScoresUri -Method Get).value

# Set secure score values for tenant score, maximum score, and averages
Write-Verbose "Extracting and calculating secure score data"
$myCurrentScore = $secureScoreLatest.CurrentScore
$myMaxScore = $secureScoreLatest.MaxScore
$myCurrentScorePercentage = (($myCurrentScore / $myMaxScore) * 100)
$allTenantsAverageScore = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "AllTenants" }).AverageScore
$TotalSeatsAverageScore = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "TotalSeats" }).AverageScore

# Add combined secure score data to final report
Write-Verbose "Generating overall secure score data"
$finalView = [PSCustomObject]@{
    'Description'         = "OverallScore"
    'myScore'             = $myCurrentScore 
    'maxScore'            = $myMaxScore
    'percentageScore'     = [math]::Round($myCurrentScorePercentage, 2)
    'allTenantAverage'    = [math]::Round($allTenantsAverageScore, 2)
    'similarSeatsAverage' = [math]::Round($TotalSeatsAverageScore, 2)
}
Write-Verbose "Writing overall secure score data to final report"    
$FinalSecureScoreReport.Add($finalView)

# Loop through each Control score and add the details to the control scores table
Write-Verbose "Looping through each control profile to obtain maximum scores and additional properties" 
foreach ($_ in ($secureScoreLatest).ControlScores) {
    $stopLoop = $false
    [int]$Retries = "0"
 
    do {
        try {
            # Retrieve control profile details
            Write-Verbose "Retrieving control profile details for $($_.ControlName)"
            $controlProfileDetails = (Invoke-MgGraphRequest -Uri "$secureScoreControlProfileUri/$($_.ControlName)" -Method Get)
            $controlProfileMaxScore = $controlProfileDetails.MaxScore
            Write-Verbose "Successfully obtained max score for control profile id $($_.ControlName) ($($controlProfileMaxScore))"
            $stopLoop = $true
        }
        catch {
            if ($Retries -gt 2) {
                Write-Verbose "Unable to retrieve control profile details for $($_.ControlName) after multiple attempts"
                $stopLoop = $true
            }
            else {
                Write-Verbose "Retrying in 2 seconds for control profile id $($_.ControlName)"
                Start-Sleep -Seconds 2
                $Retries = $Retries + 1
            }
        }
    }
    While ($stopLoop -eq $false)
    
    # Calculate the score in percentage
    $scoreInPercentage = [math]::Round((($_.Score / $controlProfileMaxScore) * 100), 2)

    # Skip items where ScoreInPercentage equals 100
    if ($scoreInPercentage -eq 100) {
        Write-Verbose "Skipping control profile id $($_.ControlName) as ScoreInPercentage is 100"
        continue
    }

    # Add details for each object to a table
    Write-Verbose "Adding details to table for profile id $($_.ControlName)"
    $DetailedControlScores = [PSCustomObject]@{
        'ControlName'          = $_.ControlName
        'Total'                = $controlProfileMaxScore
        'ScoreInPercentage'    = $scoreInPercentage
        'UserImpact'           = $controlProfileDetails.userImpact
        'ControlCategory'      = $controlProfileDetails.controlCategory
        'LastSync'             = $controlProfileDetails.lastModifiedDateTime
        'Title'                = $controlProfileDetails.title
        'ActionUrl'            = $controlProfileDetails.actionUrl
        'ImplementationCost'   = $controlProfileDetails.implementationCost
        'Rank'                 = $controlProfileDetails.rank
    }

    # Add all objects to the combined table
    $DetailedControlScoresTable.Add($DetailedControlScores)
}

# Sort the table by ScoreInPercentage in descending order
Write-Verbose "Sorting DetailedControlScoresTable by ScoreInPercentage in descending order"
$SortedControlScoresTable = $DetailedControlScoresTable | Sort-Object -Property ScoreInPercentage

# Group the sorted table by ControlCategory
Write-Verbose "Grouping DetailedControlScoresTable by ControlCategory"
$GroupedControlScores = $SortedControlScoresTable | Group-Object -Property ControlCategory

# Generate HTML report
Write-Verbose "Generating HTML report"
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Secure Score Report</title>
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #F39C12;
        }
    </style>
</head>
<body>
    <h1>Secure Score Report</h1>
        <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" hight="10%" alt="Banner Image" class="banner">
    <h2>Overall Secure Score</h2>
    <table>
        <tr>
            <th>Description</th>
            <th>My Score</th>
            <th>Max Score</th>
            <th>Percentage Score</th>
            <th>All Tenant Average</th>
            <th>Similar Seats Average</th>
        </tr>
"@

foreach ($item in $FinalSecureScoreReport) {
    $htmlContent += @"
        <tr>
            <td>$($item.Description)</td>
            <td>$($item.myScore)</td>
            <td>$($item.maxScore)</td>
            <td>$($item.percentageScore)</td>
            <td>$($item.allTenantAverage)</td>
            <td>$($item.similarSeatsAverage)</td>
        </tr>
"@
}

$htmlContent += @"
    </table>
"@

# Add a separate table for each ControlCategory
foreach ($group in $GroupedControlScores) {
    $htmlContent += @"
    <h2>Control Category: $($group.Name)</h2>
    <table>
        <tr>
            <th>Title</th>
            <th>Score in Percentage</th>
            <th>Control Category</th>
            <th>Action URL</th>
            <th>Implementation Cost</th>
            <th>User Impact</th>
        </tr>
"@
    foreach ($item in $group.Group) {
        $htmlContent += @"
        <tr>
            <td>$($item.Title)</td>
            <td>$($item.ScoreInPercentage)</td>
            <td>$($item.ControlCategory)</td>
            <td><a href='$($item.ActionUrl)' target='_blank'><img src='https://upload.wikimedia.org/wikipedia/commons/6/64/Icon_External_Link.png' alt='External Link' style='width:16px;height:16px;border:none;vertical-align:middle;'></a></td>
            <td>$($item.ImplementationCost)</td>
            <td>$($item.UserImpact)</td>
        </tr>
"@
    }
    $htmlContent += @"
    </table>
"@
}

$htmlContent += @"
</body>
</html>
"@

# Save the HTML content to a file
# $outputFile = "SecureScoreReport.html"
# $htmlContent | Out-File -FilePath $outputFile -Encoding utf8

# Write-Verbose "HTML report created: $outputFile"

# Disconnect from Microsoft Graph for Secure Score operations
Disconnect-MgGraph

# Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
$params = @{
	message = @{
		subject = "Secure Score report from Rubicon Cloud Advisor"
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