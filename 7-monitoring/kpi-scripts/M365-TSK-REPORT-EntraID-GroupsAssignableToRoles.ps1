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

# Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor DarkGray
Connect-MgGraph -ClientId $AADClientId -TenantId $TenantId -CertificateThumbprint $AADThumbprint

# Initialize an array to store all groups
$AllGroups = @()

# Define the initial Graph API endpoint for groups
$GroupsEndpoint = "https://graph.microsoft.com/v1.0/groups"

# Retrieve all groups with pagination
Write-Host "Retrieving all groups with pagination..." -ForegroundColor DarkGray
do {
    # Query the current page of groups
    $GroupsResponse = Invoke-MgGraphRequest -Uri $GroupsEndpoint -Method GET
    $AllGroups += $GroupsResponse.value

    # Check if there is a next page
    $GroupsEndpoint = $GroupsResponse.'@odata.nextLink'
} while ($GroupsEndpoint)

Write-Host "Total groups retrieved: $($AllGroups.Count)" -ForegroundColor Green

# Filter groups locally for isAssignableToRole eq true
Write-Host "Filtering groups eligible for role assignments locally..." -ForegroundColor DarkGray
$EligibleGroups = $AllGroups | Where-Object { $_.isAssignableToRole -eq $true }

# Initialize a variable to store the HTML content
$htmlContent = @"
<h2>Groups Eligible for Role Assignments Report</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" hight="10%" alt="Banner Image" class="banner">
<h4>Organization Domain: $OrganizationDomain</h4>
<p>This report lists all groups eligible for role assignments and their members.</p>
"@

# Process each eligible group
Write-Host "Processing eligible groups and retrieving members..." -ForegroundColor DarkGray
foreach ($group in $EligibleGroups) {
    # Retrieve group members
    $GroupMembersEndpoint = "https://graph.microsoft.com/v1.0/groups/$($group.id)/members"
    $MembersResponse = Invoke-MgGraphRequest -Uri $GroupMembersEndpoint -Method GET
    $Members = $MembersResponse.value

    # Initialize an array to store member details
    $MemberDetails = @()

    # Process each member
    foreach ($member in $Members) {
        $MemberDetails += [PSCustomObject]@{
            MemberName = $member.displayName
            MemberType = if ($member."@odata.type" -eq "#microsoft.graph.user") { "User" } elseif ($member."@odata.type" -eq "#microsoft.graph.group") { "Group" } else { "Other" }
            MemberId   = $member.id
        }
    }

    # Generate an HTML table for the current group
    $CSSStyle = "<style>
    table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
    table td, th {border: 1px solid #ddd; padding: 8px;}
    table tr:nth-child(even){background-color: #F39C12;}
    table tr:hover {background-color: #ddd;}
    table th { padding-top: 10px; padding-bottom: 10px; text-align: left; background-color: #F39C12; color: white;}
    </style>"

    $GroupTable = $MemberDetails | ConvertTo-Html -Head $CSSStyle -Title "Members of $($group.displayName)" | Out-String

    # Append the group table to the HTML content
    $htmlContent += @"
<h3>Group: $($group.displayName) (ID: $($group.id))</h3>
<p>Member Count: $($MemberDetails.Count)</p>
$GroupTable
"@
}

# Connect to Microsoft Graph for email operations
Write-Host "Connecting to Microsoft Graph for email operations..." -ForegroundColor DarkGray
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
$params = @{
    message = @{
        subject = "Groups Eligible for Role Assignments Report"
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
