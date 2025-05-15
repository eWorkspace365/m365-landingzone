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
Connect-MgGraph -ClientId $AADClientId -TenantId $TenantId -CertificateThumbprint $AADThumbprint

# Define the Graph API endpoints
$AssignmentRolesEndpoint = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules"
$EligibleRolesEndpoint = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules"

# Retrieve assignment role schedules using the Graph API
Write-Host "Retrieving assignment role schedules..." -ForegroundColor DarkGray
$AssignmentRolesResponse = Invoke-MgGraphRequest -Uri $AssignmentRolesEndpoint -Method GET
$AssignmentRoles = $AssignmentRolesResponse.value

# Retrieve eligible role schedules using the Graph API
Write-Host "Retrieving eligible role schedules..." -ForegroundColor DarkGray
$EligibleRolesResponse = Invoke-MgGraphRequest -Uri $EligibleRolesEndpoint -Method GET
$EligibleRoles = $EligibleRolesResponse.value

# Initialize arrays to store schedules
$AssignmentRoleSchedules = @()
$EligibleRoleSchedules = @()

# Process assignment role schedules
Write-Host "Processing assignment role schedules and resolving PrincipalId and RoleDefinitionId to readable names..." -ForegroundColor DarkGray
foreach ($AssignmentRole in $AssignmentRoles) {
    # Extract schedule information
    $ScheduleInfo = $AssignmentRole.scheduleInfo
    $ExpirationType = $ScheduleInfo.expiration.type
    $StartDateTime = $ScheduleInfo.startDateTime
    $EndDateTime = if ($ScheduleInfo.expiration.endDateTime) { $ScheduleInfo.expiration.endDateTime } else { "No Expiration" }

    # Resolve PrincipalId to a readable name
    $PrincipalName = "Unknown Principal"
    if ($AssignmentRole.principalId) {
        try {
            $DirectoryObjectEndpoint = "https://graph.microsoft.com/v1.0/directoryObjects/$($AssignmentRole.principalId)"
            $DirectoryObjectResponse = Invoke-MgGraphRequest -Uri $DirectoryObjectEndpoint -Method GET
            if ($DirectoryObjectResponse."@odata.type" -eq "#microsoft.graph.user") {
                $PrincipalName = $DirectoryObjectResponse.displayName
            } elseif ($DirectoryObjectResponse."@odata.type" -eq "#microsoft.graph.group") {
                $PrincipalName = $DirectoryObjectResponse.displayName
            } elseif ($DirectoryObjectResponse."@odata.type" -eq "#microsoft.graph.servicePrincipal") {
                $PrincipalName = $DirectoryObjectResponse.displayName
            } else {
                $PrincipalName = "Unknown Principal Type"
            }
        } catch {
            Write-Warning "Unable to resolve PrincipalId $($AssignmentRole.principalId) to a readable name."
        }
    }

    # Resolve RoleDefinitionId to a readable role name
    $RoleName = "Unknown Role"
    if ($AssignmentRole.roleDefinitionId) {
        try {
            $RoleDefinitionEndpoint = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$($AssignmentRole.roleDefinitionId)"
            $RoleDefinitionResponse = Invoke-MgGraphRequest -Uri $RoleDefinitionEndpoint -Method GET
            $RoleName = $RoleDefinitionResponse.displayName
        } catch {
            Write-Warning "Unable to resolve RoleDefinitionId $($AssignmentRole.roleDefinitionId) to a readable name."
        }
    }

    # Add assignment role schedule details to the array
    $AssignmentRoleSchedules += [PSCustomObject]@{
        PrincipalName     = $PrincipalName
        RoleName          = $RoleName
        AssignmentType    = $AssignmentRole.assignmentType
        MemberType        = $AssignmentRole.memberType
        StartDateTime     = $StartDateTime
        ExpirationType    = $ExpirationType
        EndDateTime       = $EndDateTime
    }
}

# Process eligible role schedules
Write-Host "Processing eligible role schedules and resolving PrincipalId and RoleDefinitionId to readable names..." -ForegroundColor DarkGray
foreach ($EligibleRole in $EligibleRoles) {
    # Extract schedule information
    $ScheduleInfo = $EligibleRole.scheduleInfo
    $ExpirationType = $ScheduleInfo.expiration.type
    $StartDateTime = $ScheduleInfo.startDateTime
    $EndDateTime = if ($ScheduleInfo.expiration.endDateTime) { $ScheduleInfo.expiration.endDateTime } else { "No Expiration" }

    # Resolve PrincipalId to a readable name
    $PrincipalName = "Unknown Principal"
    if ($EligibleRole.principalId) {
        try {
            $DirectoryObjectEndpoint = "https://graph.microsoft.com/v1.0/directoryObjects/$($EligibleRole.principalId)"
            $DirectoryObjectResponse = Invoke-MgGraphRequest -Uri $DirectoryObjectEndpoint -Method GET
            if ($DirectoryObjectResponse."@odata.type" -eq "#microsoft.graph.user") {
                $PrincipalName = $DirectoryObjectResponse.displayName
            } elseif ($DirectoryObjectResponse."@odata.type" -eq "#microsoft.graph.group") {
                $PrincipalName = $DirectoryObjectResponse.displayName
            } elseif ($DirectoryObjectResponse."@odata.type" -eq "#microsoft.graph.servicePrincipal") {
                $PrincipalName = $DirectoryObjectResponse.appDisplayName
            } else {
                $PrincipalName = "Unknown Principal Type"
            }
        } catch {
            Write-Warning "Unable to resolve PrincipalId $($EligibleRole.principalId) to a readable name."
        }
    }

    # Resolve RoleDefinitionId to a readable role name
    $RoleName = "Unknown Role"
    if ($EligibleRole.roleDefinitionId) {
        try {
            $RoleDefinitionEndpoint = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$($EligibleRole.roleDefinitionId)"
            $RoleDefinitionResponse = Invoke-MgGraphRequest -Uri $RoleDefinitionEndpoint -Method GET
            $RoleName = $RoleDefinitionResponse.displayName
        } catch {
            Write-Warning "Unable to resolve RoleDefinitionId $($EligibleRole.roleDefinitionId) to a readable name."
        }
    }

    # Add eligible role schedule details to the array
    $EligibleRoleSchedules += [PSCustomObject]@{
        PrincipalName      = $PrincipalName
        RoleName           = $RoleName
        MemberType         = $EligibleRole.memberType
        StartDateTime      = $StartDateTime
        ExpirationType     = $ExpirationType
        EndDateTime        = $EndDateTime
    }
}

# Generate HTML tables for assignment and eligible role schedules
$CSSStyle = "<style>
table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
table td, th {border: 1px solid #ddd; padding: 8px;}
table tr:nth-child(even){background-color: #F39C12;}
table tr:hover {background-color: #ddd;}
table th { padding-top: 10px; padding-bottom: 10px; text-align: left; background-color: #F39C12; color: white;}
</style>"

$AssignmentRoleSchedulesTable = $AssignmentRoleSchedules | ConvertTo-Html -Head $CSSStyle -Title "Assignment Role Schedules Report" | Out-String
$EligibleRoleSchedulesTable = $EligibleRoleSchedules | ConvertTo-Html -Head $CSSStyle -Title "Eligible Role Schedules Report" | Out-String

# Combine the tables into a single HTML report
$htmlContent = @"
<h2>Role Schedules Report from Rubicon Cloud Advisor</h2>
<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU" width="10%" hight="10%" alt="Banner Image" class="banner">
<h4>Organization Domain: $OrganizationDomain</h4>
<p>This email reports all role assignment and eligibility schedules in your directory.</p>
<h3>Assignment Role Schedules</h3>
$AssignmentRoleSchedulesTable
<h3>Eligible Role Schedules</h3>
$EligibleRoleSchedulesTable
"@

# Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
$params = @{
    message = @{
        subject = "Role Schedules Report from Rubicon Cloud Advisor"
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
Write-Host "Sending email with the Role Schedules report..." -ForegroundColor DarkGray
Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

# Disconnect from Microsoft Graph for email operations
Disconnect-MgGraph

Write-Host "Email sent successfully" -ForegroundColor Green
