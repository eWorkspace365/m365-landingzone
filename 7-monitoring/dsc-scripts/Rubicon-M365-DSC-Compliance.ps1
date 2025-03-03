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
    $AppName =  "Rubicon-M365-DSC-Compliance"
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
                    id = "9241abd9-d0e6-425a-bd4f-47ba86e767a4"  # DeviceManagementConfiguration.ReadWrite.All
                    type = "Role"
                },
		@{
                    id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"  # Directory.Read.All
                    type = "Role"
                },
                @{
                    id = "b2620db1-3bf7-4c5b-9cb9-576d29eac736"  # eDiscovery.ReadWrite.All
                    type = "Role"
                },
                @{
                    id = "19da66cb-0fb0-4390-b071-ebc76a349482"  # InformationProtectionPolicy.Read.All
                    type = "Role"
                },
                @{
                    id = "498476ce-e0fe-48b0-b801-37ba7e2685c6"  # Organization.Read.All
                    type = "Role"
                },
		@{
                    id = "01c0a623-fc9b-48e9-b794-0756f8e8f067"  # Policy.ReadWrite.ConditionalAccess
                    type = "Role"
                },
		@{
                    id = "d903a879-88e0-4c09-b0c9-82f6a1333f84"  # SecurityEvents.ReadWrite.All
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

