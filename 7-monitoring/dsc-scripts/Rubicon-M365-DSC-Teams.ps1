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
    $AppName =  "Rubicon-M365-DSC-Teams"
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
                    id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"  # Directory.ReadWrite.All
                    type = "Role"
                },
                @{
                    id = "62a82d76-70ea-41e2-9197-370581804d09"  # Group.ReadWrite.All
                    type = "Role"
                },
                @{
                    id = "246dd0d5-5bd0-4def-940b-0421030a5b68"  # Policy.Read.All
                    type = "Role"
                },
                @{
                    id = "498476ce-e0fe-48b0-b801-37ba7e2685c6"  # Organization.Read.All
                    type = "Role"
                },
                @{
                    id = "242607bd-1d2c-432c-82eb-bdb27baa23ab"  # TeamSettings.Read.All
                    type = "Role"
                }
            )
        }
    )
}

# Update the application with combined permissions
Update-MgApplication -ApplicationId $APPObjectID -BodyParameter $Permissions

