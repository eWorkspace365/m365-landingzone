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
    $AppName =  "DemoApp"
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
                    Id = "134fd756-38ce-4afd-ba33-e9623dbe66c2"
                    Type = "Role"
                },
                @{
                    Id = "2f3e6f8c-093b-4c57-a58b-ba5ce494a169"
                    Type = "Role"
                },
                @{
                    Id = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"
                    Type = "Role"
                },
    @{
        Id = "b0afded3-3588-46d8-8b3d-9842eff778da"
        Type = "Role"
    },
    @{
        Id = "798ee544-9d2d-430c-a058-570e29e34338"
        Type = "Role"
    },
    @{
        Id = "35930dcf-aceb-4bd1-b99a-8ffed403c974"
        Type = "Role"
    },
    @{
        Id = "243cded2-bd16-4fd6-a953-ff8177894c3d"
        Type = "Role"
    },
    @{
        Id = "7a6ee1e7-141e-4cec-ae74-d9db155731ff"
        Type = "Role"
    },
    @{
        Id = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
        Type = "Role"
    },
    @{
        Id = "9241abd9-d0e6-425a-bd4f-47ba86e767a4"
        Type = "Role"
    },
    @{
        Id = "2f51be20-0bb4-4fed-bf7b-db946066c75e"
        Type = "Role"
    },
    @{
        Id = "58ca0d9a-1575-47e1-a3cb-007ef2e4583b"
        Type = "Role"
    },
    @{
        Id = "06a5fe6d-c49d-46a7-b082-56b1b14103c7"
        Type = "Role"
    },
    @{
        Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
        Type = "Role"
    },
    @{
        Id = "dbb9058a-0e50-45d7-ae91-66909b5d4664"
        Type = "Role"
    },
    @{
        Id = "c74fd47d-ed3c-45c3-9a9e-b8676de685d2"
        Type = "Role"
    },
    @{
        Id = "62a82d76-70ea-41e2-9197-370581804d09"
        Type = "Role"
    },
    @{
        Id = "e321f0bb-e7f7-481e-bb28-e3b0b32d4bd0"
        Type = "Role"
    },
    @{
        Id = "6e472fd1-ad78-48da-a0f0-97ab2c6b769e"
        Type = "Role"
    },
    @{
        Id = "dc5007c0-2d7d-4c42-879c-2dab87571379"
        Type = "Role"
    },
    @{
        Id = "19da66cb-0fb0-4390-b071-ebc76a349482"
        Type = "Role"
    },
    @{
        Id = "4f994bc0-31bb-44bb-b480-7a7c1be8c02e"
        Type = "Role"
    },
    @{
        Id = "498476ce-e0fe-48b0-b801-37ba7e2685c6"
        Type = "Role"
    },
    @{
        Id = "eb76ac34-0d62-4454-b97c-185e4250dc20"
        Type = "Role"
    },
    @{
        Id = "e1a88a34-94c4-4418-be12-c87b00e26bea"
        Type = "Role"
    },
    @{
        Id = "56c84fa9-ea1f-4a15-90f2-90ef41ece2c9"
        Type = "Role"
    },
    @{
        Id = "c18ae2dc-d9f3-4495-a93f-18980a0e159f"
        Type = "Role"
    },
    @{
        Id = "434d7c66-07c6-4b1f-ab21-417cf2cdaaca"
        Type = "Role"
    },
    @{
        Id = "6cdf1fb1-b46f-424f-9493-07247caa22e2"
        Type = "Role"
    },
    @{
        Id = "e4d9cd09-d858-4363-9410-abb96737f0cf"
        Type = "Role"
    },
    @{
        Id = "246dd0d5-5bd0-4def-940b-0421030a5b68"
        Type = "Role"
    },
    @{
        Id = "01c0a623-fc9b-48e9-b794-0756f8e8f067"
        Type = "Role"
    },
    @{
        Id = "1c6e93a6-28e2-4cbb-9f64-1a46a821124d"
        Type = "Role"
    },
    @{
        Id = "230c1aed-a721-4c5d-9cb4-a90514e508ef"
        Type = "Role"
    },
    @{
        Id = "ee353f83-55ef-4b78-82da-555bfa2b4b95"
        Type = "Role"
    },
    @{
        Id = "d5fe8ce8-684c-4c83-a52c-46e882ce4be1"
        Type = "Role"
    },
    @{
        Id = "fee28b28-e1f3-4841-818e-2704dc62245f"
        Type = "Role"
    },
    @{
        Id = "c7fbd983-d9aa-4fa7-84b8-17382c103bc4"
        Type = "Role"
    },
    @{
        Id = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c"
        Type = "Role"
    },
    @{
        Id = "ef31918f-2d50-4755-8943-b8638c0a077e"
        Type = "Role"
    },
    @{
        Id = "fdc4c997-9942-4479-bfcb-75a36d1138df"
        Type = "Role"
    },
    @{
        Id = "5e0edab9-c148-49d0-b423-ac253e121825"
        Type = "Role"
    },
    @{
        Id = "472e4a4d-bb4a-4026-98d1-0b0d74cb74a5"
        Type = "Role"
    },
    @{
        Id = "bf394140-e372-4bf9-a898-299cfc7564e5"
        Type = "Role"
    },
    @{
        Id = "45cc0394-e837-488b-a098-1918f48d186c"
        Type = "Role"
    },
    @{
        Id = "4dfee10b-fa4a-41b5-b34d-ccf54cc0c394"
        Type = "Role"
    },
    @{
        Id = "79c261e0-fe76-4144-aad5-bdc68fbe4037"
        Type = "Role"
    },
    @{
        Id = "bdd80a03-d9bc-451d-b7c4-ce7c63fe3c8f"
        Type = "Role"
    },
    @{
        Id = "df021288-bdef-4463-88db-98f22de89214"
        Type = "Role"
    }
            )
        }
    )
}

# Update the application with combined permissions
Update-MgApplication -ApplicationId $APPObjectID -BodyParameter $Permissions

