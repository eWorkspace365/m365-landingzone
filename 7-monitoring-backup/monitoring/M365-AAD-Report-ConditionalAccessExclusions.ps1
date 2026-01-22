Param (   
    [Parameter(Mandatory=$false)]
    [String]$TenantID,
    
    [Parameter(Mandatory=$false)]
    [String]$AppID,
    
    [Parameter(Mandatory=$false)]
    [String]$CertificateThumbprint
)

# Connect to Microsoft Graph
Connect-MgGraph -ClientId $AppId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint

# Function to get group members recursively
function Get-GroupMembersRecursive {
    param (
        [string]$GroupId
    )
    
    $members = @()
    $groupMembers = Get-MgGroupMember -GroupId $GroupId -All
    
    foreach ($member in $groupMembers) {
        if ($member.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.user") {
            $user = Get-MgUser -UserId $member.Id
            $members += [PSCustomObject]@{
                Type = "User"
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
            }
        }
        elseif ($member.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.group") {
            $nestedGroup = Get-MgGroup -GroupId $member.Id
            $nestedMembers = Get-GroupMembersRecursive -GroupId $member.Id
            $members += [PSCustomObject]@{
                Type = "Group"
                DisplayName = $nestedGroup.DisplayName
                Id = $nestedGroup.Id
                Members = $nestedMembers
            }
        }
    }
    
    return $members
}

# Get all Conditional Access policies
$policies = Get-MgIdentityConditionalAccessPolicy

# Initialize a hashtable to store excluded groups and their associated policies
$excludedGroupsWithPolicies = @{}

# Find excluded groups in each policy
foreach ($policy in $policies) {
    $excludedGroupIds = $policy.Conditions.Users.ExcludeGroups
    if ($excludedGroupIds) {
        foreach ($groupId in $excludedGroupIds) {
            if (-not $excludedGroupsWithPolicies.ContainsKey($groupId)) {
                $excludedGroupsWithPolicies[$groupId] = @()
            }
            $excludedGroupsWithPolicies[$groupId] += $policy.DisplayName
        }
    }
}

# Get unique excluded group IDs
$uniqueExcludedGroups = $excludedGroupsWithPolicies.Keys

# Create an array to store the results
$results = @()

# Get details of each excluded group and its members
foreach ($groupId in $uniqueExcludedGroups) {
    $group = Get-MgGroup -GroupId $groupId
    $members = Get-GroupMembersRecursive -GroupId $groupId
    $groupInfo = [PSCustomObject]@{
        GroupDisplayName = $group.DisplayName
        GroupId = $group.Id
        Members = $members
        ExcludedByPolicies = $excludedGroupsWithPolicies[$groupId]
    }
    $results += $groupInfo
}

# Export to JSON file
$jsonFilePath = "C:\Users\Public\Downloads\entraid-ca-exclusions.json"
$results | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFilePath
Write-Host "Results exported to $jsonFilePath"