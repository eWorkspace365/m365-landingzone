# Import Module
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Applications

###############################################################################
# Connect-MgGraph
# Connect to your Azure Active Directory with "Application Administrator" or "Global Administrator" Role
###############################################################################
Connect-MgGraph -Scopes "Application.Read.All","Application.ReadWrite.All","User.Read.All"
Get-MgContext

###############################################################################
# Choose to create a new application or update an existing one
###############################################################################
$choice = Read-Host "Enter 'new' to create a new application or 'update' to update an existing application"

if ($choice -eq 'new') {
    # Create AAD Application
    $AppName =  "Rubicon-M365-DSC-EntraID"
    $App = New-MgApplication -DisplayName $AppName 
    $APPObjectID = $App.Id
    Write-Host "Created new application with ID: $APPObjectID"
} elseif ($choice -eq 'update') {
    # Update existing application
    $APPObjectID = Read-Host "Enter the Object ID of the existing application"
    Write-Host "Updating application with Object ID: $APPObjectID"
} else {
    Write-Host "Invalid choice. Please run the script again and enter 'new' or 'update'."
    exit
}

###############################################################################
# Add Permissions
###############################################################################
# Combine all required permissions
$Permissions = @{
    RequiredResourceAccess = @(
        @{
            ResourceAppId = "00000003-0000-0000-c000-000000000000"
            ResourceAccess = @(
                @{
                    id = "b0afded3-3588-46d8-8b3d-9842eff778da"  # AuditLog.Read.All
                    type = "Role"
                },
                @{
                    id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"  # Directory.Read.All
                    type = "Role"
                },
                @{
                    id = "c74fd47d-ed3c-45c3-9a9e-b8676de685d2"  # EntitlementManagement.Read.All
                    type = "Role"
                },
                @{
                    id = "498476ce-e0fe-48b0-b801-37ba7e2685c6"  # Organization.Read.All
                    type = "Role"
                },
                @{
                    id = "246dd0d5-5bd0-4def-940b-0421030a5b68"  # Policy.Read.All
                    type = "Role"
                },
                @{
                    id = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c"  # RoleManagement.Read.Directory
                    type = "Role"
                },
                @{
                    id = "01c0a623-fc9b-48e9-b794-0756f8e8f067"  # Policy.ReadWrite.ConditionalAccess
                    type = "Role"
                },
                @{
                    id = "df021288-bdef-4463-88db-98f22de89214"  # User.Read.All
                    type = "Role"
                },
                @{
                    id = "c9090d00-6101-42f0-a729-c41074260d47"  # Agreement.ReadWrite.All
                    type = "Role"
                }
            )
        }
    )
}

# Update the application with combined permissions
Update-MgApplication -ApplicationId $APPObjectID -BodyParameter $Permissions

