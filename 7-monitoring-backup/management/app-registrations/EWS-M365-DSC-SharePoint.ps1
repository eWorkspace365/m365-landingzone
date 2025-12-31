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
    $AppName =  "EWS-M365-DSC-SharePoint"
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
                    id = "498476ce-e0fe-48b0-b801-37ba7e2685c6"  # Organization.Read.All
                    type = "Role"
                },
                @{
                    id = "0c0bf378-bf22-4481-8f81-9e89a9b4960a"  # Sites.Manage.All
                    type = "Role"
                },
                @{
                    id = "19b94e34-907c-4f43-bde9-38b1909ed408"  # SharePointTenantSettings.ReadWrite.All
                    type = "Role"
                }
                @{
                    id = "a82116e5-55eb-4c41-a434-62fe8a61c773"  # Sites.FullControl.All
                    type = "Role"
                },
                @{
                    id = "9492366f-7969-46a4-8d15-ed1a20078fff"  # Sites.ReadWrite.All
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
        },
        @{
            resourceAppId = "00000003-0000-0ff1-ce00-000000000000"  # SharePoint
            resourceAccess = @(
                @{
                    id = "678536fe-1083-478a-9c59-b99265e6b0d3"  # Sites.FullControl.All (SharePoint API)
                    type = "Role"
                }
            )
        }
    )
}

# Update the application with combined permissions
Update-MgApplication -ApplicationId $APPObjectID -BodyParameter $Permissions

