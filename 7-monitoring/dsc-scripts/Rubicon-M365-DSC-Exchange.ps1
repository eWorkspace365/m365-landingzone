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
    $AppName =  "Rubicon-M365-DSC-Exchange"
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
                    id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"  # Directory.Read.All
                    type = "Role"
                },
                @{
                    id = "810c84a8-4a9e-49e6-bf7d-12d183f40d01"  # Mail.Read
                    type = "Role"
                },
                @{
                    id = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"  # RoleManagement.ReadWrite.Directory
                    type = "Role"
                }
            )
        },
        @{
            resourceAppId = "00000002-0000-0ff1-ce00-000000000000"  # Office 365 Exchange Online
            resourceAccess = @(
                @{
                    id = "dc50a0fb-09a3-484d-be87-e023b12c6440"  # Exchange.ManageAsApp
                    type = "Role"
                }
            )
        }
    )
}

# Update the application with combined permissions
Update-MgApplication -ApplicationId $APPObjectID -BodyParameter $Permissions

