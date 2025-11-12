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
    $AppName =  "Rubicon-M365-DSC-Intune"
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
                    id = "78145de6-330d-4800-a6ce-494ff2d33d07"  # DeviceManagementApps.ReadWrite.All
                    type = "Role"
                },
				@{
                    id = "9255e99d-faf5-445e-bbf7-cb71482737c4"  # DeviceManagementScripts.ReadWrite.All
                    type = "Role"
                },
                @{
                    id = "58ca0d9a-1575-47e1-a3cb-007ef2e4583b"  # Read Microsoft Intune RBAC settings
                    type = "Role"
                },
                @{
                    id = "9241abd9-d0e6-425a-bd4f-47ba86e767a4"  # DeviceManagementConfiguration.ReadWrite.All
                    type = "Role"
                },
                @{
                    id = "243333ab-4d21-40cb-a475-36241daa0842"  # DeviceManagementManagedDevices.ReadWrite.All
                    type = "Role"
                },
                @{
                    id = "5ac13192-7ace-4fcf-b828-1a26f28068ee"  # DeviceManagementServiceConfig.ReadWrite.All
                    type = "Role"
                },
                @{
                    id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"  # Directory.Read.All
                    type = "Role"
                },
                @{
                    id = "498476ce-e0fe-48b0-b801-37ba7e2685c6"  # Organization.Read.All
                    type = "Role"
                }
            )
        }
    )
}

# Update the application with combined permissions
Update-MgApplication -ApplicationId $APPObjectID -BodyParameter $Permissions

