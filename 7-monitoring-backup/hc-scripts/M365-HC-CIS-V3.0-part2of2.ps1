############################################################################
#
# WAT DOET DIT SCRIPT:
# controle wordt uitgevoerd op de CIS componenten. Bepaalde zaken zijn nog niet beschikbaar in code en dienen eerst met de hand te worden gecontroleerd.
# output van het bestand is een log met alle items (true/false) waarmee een audit wordt opgemaakt van de Microsoft 365 omgeving.
#
############################################################################
#
# CONTROLS INCLUDES
#	- MICROSOFT 365 - CIS 3.0
#	- DYNAMICS POWERPLATFORM
#   - INTUNE
#
############################################################################
#
# LET OP: voer eerst de handmatige controles uit, update de waardes
# zoek naar tekst 'MET-HAND-VULLEN'
# RUN NU HET HELE SCRIPT: dit zorgt ervoor dat alles netjes in 1 log komt
#
# TODO: handmatige acties in code zetten\
#
# Zorg tot slot dat onderaan de folder voor het dump path lokaal bestaat
#
############################################################################
# PREREQS
# 	      Powershell 7
#              installeer met 'winget install pwsh'
#         Visual Studio Code (als je aan het debuggen bent)
#
# Modules:
#  
#         De-install!! PnP.PowerShell
#           Uninstall-Module PnP.PowerShell
#         PnP.PowerShell 2.5.1 (Explicit!)
#         https://www.powershellgallery.com/api/v2/package/PnP.PowerShell/2.5.1-nightly
#         direct download, hernoemen naar *.zip, unpack, 
#         hernoem map naar 2.5.1 -> copy naar Module map van PnP.Powershell
#         
#         De-install!! ExchangePowerShell
#         Uninstall-Module ExchangePowerShell
#         
#         MSAL.PS 4.37.0.0
#         ExchangeOnlineManagement 3.6.0 (Explicit!)
#         Install-Module -Name ExchangeOnlineManagement -RequiredVersion 3.6.0
#
############################################################################
#
# INPUTS app registration details for the CIS / Graph scan
# App Registration heeft de volgende rechten nodig
# Graph
#     DeviceManagementConfiguration.Read.All
#     DeviceManagementConfiguration.ReadWrite.All
#     Directory.Read.All
#     Group.Read.All
#     IdentityRiskEvent.Read.All
#     IdentityRiskyUser.Read.All
#     Policy.Read.All
#     Policy.ReadWrite.SecurityDefaults
#     SecurityActions.Read.All
#     SecurityAlert.Read.All
#     SecurityEvents.Read.All
#     SecurityIncident.Read.All
#     SharePointTenantSettings.Read.All
# Office 365 Exchange Online
#     Exchange.ManageAsApp
# Office 365 Sharepoint Online   
#     User.Read.All
#     Sites.FullControl.All
#     AllSites.FullControl
#   
# for authentication, use a self signed certificate and register it in the enterprise app
#
# $certname = "{certificateName}"    ## Replace {certificateName}
# $cert = New-SelfSignedCertificate -Subject "CN=$certname" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256
# $mypwd = ConvertTo-SecureString -String "{myPassword}" -Force -AsPlainText  ## Replace {myPassword}
# Export-PfxCertificate -Cert $cert -FilePath "C:\Users\admin\Desktop\$certname.pfx" -Password $mypwd   ## Specify your preferred location
############################################################################
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [String]$CustomerID,
    
    [Parameter(Mandatory=$true)]
    [String]$TenantID,
    
    [Parameter(Mandatory=$true)]
    [String]$ClientID,
    
    [Parameter(Mandatory=$true)]
    [String]$CertificateThumbprint,
    
    [Parameter(Mandatory=$true)]
    [String]$Organization,
    
    [Parameter(Mandatory=$true)]
    [String]$AdminURL

)

Import-Module MSAL.PS
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Groups
Import-Module PNP.PowerShell -RequiredVersion 2.5.1

$ErrorActionPreference = "stop"
$Global:MsalToken=""

# Ability to run scripts based on relative path
if ($myInvocation.MyCommand.CommandType -ne [System.Management.Automation.CommandTypes]::Script)
{
    $scriptfolder = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
    #the output below returns the parent of the scriptfolder (normally where also \modules and \logs are located )
    #$Global:WorkingDir = $($(Get-Item $scriptfolder).Parent).FullName
    $Global:WorkingDir = $($(Get-Item $scriptfolder).FullName)
}

###############
# MAKE SURE TO SAVE THE FILE BEFORE RUNNING THE SCRIPT
###############

# Bepaal of we SPO in de scan uitvoeren of niet (true = ja / false = nee)
$checkSPO = $true

# Check if debugging
$Debug=$true
if ($Debug){
    . .\debug_settings.ps1
}else{
    $basePath="F:"
}

#region Functions

# Description:Recursively creates a folder tree
# Returns: N/A
# Usage EXAMPLE: Ensure-Folder "c:\Folder1\Folder2\"
function Ensure-Folder()
{
    param ([Parameter(Mandatory=$true, Position = 0)][String]$FolderPath)

    $oFSO=New-Object -ComObject scripting.filesystemobject
    # make sure folder does not exist
    if(!$oFSO.FolderExists($FolderPath)){
	    # call recursively for ever parent folder not existing
	    if(!$oFSO.FolderExists($oFSO.GetParentFolderName($FolderPath)))
        {
            $Recurse=$oFSO.GetParentFolderName($FolderPath)+"\"
		    Ensure-Folder "$Recurse"
        }
	    # create the actual folder
	    $oFSO.CreateFolder($FolderPath)
    }
}

function Get-QueryHeaders()
{
    if (!$Global:MsalToken){
        if ($Global:MsalToken.Length -eq 0)
        {
            $scopes="https://graph.microsoft.com/.default"
            # Pick up the client certificate locally
            $ClientCertificate = Get-Item "Cert:\LocalMachine\My\$($CertificateThumbprint)"
            # Get an access token
            $Global:MsalToken = Get-MsalToken -ClientId $ApplicationID -ClientCertificate $ClientCertificate -TenantId $tenantID -Scopes $scopes
        }
    }
    else {
        if ($Global:MsalToken.ExpiresOn -lt $(Get-Date))
        {
            # token expired
            $scopes="https://graph.microsoft.com/.default"
            # Pick up the client certificate locally
            $ClientCertificate = Get-Item "Cert:\LocalMachine\My\$($CertificateThumbprint)"
            # Get an access token
            $Global:MsalToken = Get-MsalToken -ClientId $ApplicationID -ClientCertificate $ClientCertificate -TenantId $tenantID -Scopes $scopes
        }
    }
    # generate headers
    $Headers = @{
            'Content-Type'  = "application\json"
            'Authorization' = $Global:MsalToken.CreateAuthorizationHeader()
            'ConsistencyLevel' = "eventual" }
    #$Response=Invoke-RestMethod -Headers $Headers -Uri $Uri -UseBasicParsing -Method "GET" -ContentType "application/json"  
    return $Headers
}

function Get-QueryHeadersDict()
{
    if ($null -eq $Global:MsalToken)
    {
        $scopes="https://graph.microsoft.com/.default"
        # Pick up the client certificate locally
        $ClientCertificate = Get-Item "Cert:\LocalMachine\My\$($CertificateThumbprint)"
        # Get an access token
        $Global:MsalToken = Get-MsalToken -ClientId $ApplicationID -ClientCertificate $ClientCertificate -TenantId $tenantID -Scopes $scopes
    }
    # Connect to Microsoft Graph
    $Headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $Headers.Add('Content-Type',"application\json")
    $Headers.Add('Authorization',$Global:MsalToken.CreateAuthorizationHeader())
    $Headers.Add('ConsistencyLevel',"eventual")
    return $Headers
}


function Query-Graph()
{
   param ([Parameter(Mandatory=$true, Position = 0)][String]$uri)
    # Connect to Microsoft Graph
    $Headers = Get-QueryHeaders
    $Response=Invoke-RestMethod -Headers $Headers -Uri $Uri -UseBasicParsing -Method "GET" -ContentType "application/json"  
    return $Response
}

#endregion

$outputPath = "$basePath\HealthChecks\$CustomerID\Microsoft 365"
# create folder structure
Ensure-Folder $outputPath | Out-Null

#
#_____________________________________________________________________________________________
#
Write-Output "Creating output object"
$timestamp = Get-Date -Format "dd/MM/yyyy"
$scriptVersion = "2.0"
$localfile = "log_cis.json"
$localsecurescorefile = "log_secure_score.json"
$secureScoreDumpFile = "$outputPath\$localsecurescorefile"

$outputObj = New-Object -TypeName psobject
$outputObj | Add-Member -MemberType NoteProperty -Name version -Value $scriptVersion
$outputObj | Add-Member -MemberType NoteProperty -Name timestamp -Value $timestamp
$outputObj | Add-Member -MemberType NoteProperty -Name customerId -Value $customerId
#
#_____________________________________________________________________________________________
#

##################################
# CONNECT TO SHAREPOINT ONLINE
#region SHAREPOINT
if ($checkSPO) {
    #Connect-ExchangeOnline -CertificateThumbPrint $CertificateThumbprint -AppID $ClientID -Organization $Organization
    Connect-PnPOnline -Url $AdminUrl -ClientId $ApplicationId -Thumbprint $CertificateThumbprint -Tenant $TenantID
    #$GlobalSharepointSettings=Query-Graph "https://graph.microsoft.com/v1.0/admin/sharepoint/settings"
    #Ensure Office 365 SharePoint infected files are disallowed for download
    $SPOTenant = Get-PnPTenant 

    # Check if anonymous users are allowed to join meetings
    $isAllowed = $SPOTenant.DisallowInfectedFileDownload -like "*True*"

    if ($isAllowed) {
       $outputObj | Add-Member -MemberType NoteProperty -Name disallow_infected_files_for_download -Value $true -force
    } else {
       $outputObj | Add-Member -MemberType NoteProperty -Name disallow_infected_files_for_download -Value $false -force
    }

    # Ensure that SharePoint guest users cannot share items they don't own (Automated)
    # Check if anonymous users are allowed to join meetings
    $isAllowed = $SPOTenant.PreventExternalUsersFromResharing -like "*True*"

    if ($isAllowed) {
         $outputObj | Add-Member -MemberType NoteProperty -Name disable_sharing_external_do_not_own -Value $true -force
    } else {
       $outputObj | Add-Member -MemberType NoteProperty -Name disable_sharing_external_do_not_own -Value $false -force
    }

    # Ensure external content sharing is restricted (Automated) - https://admin.microsoft.com/sharepoint - policies & sharing - external sharing -> New and existing guests OR LOWER must be set
    #$MBX = Get-PnPTenant # why requery the same information?

    # Check if anonymous users are allowed to join meetings
    $isRestricted = $SPOTenant.SharingCapability -like "*ExternalUserSharingOnly*" -or $SPOTenant.SharingCapability -like "*ExistingExternalUserSharingOnly*" -or $SPOTenant.SharingCapability -like "*Disabled*"

    if ($isRestricted) {
       $outputObj | Add-Member -MemberType NoteProperty -Name ensure_external_sharing_restricted -Value $true -force
    } else {
       $outputObj | Add-Member -MemberType NoteProperty -Name ensure_external_sharing_restricted -Value $false -force
    }

    # Ensure link sharing is restricted in SharePoint and OneDrive - https://admin.microsoft.com/sharepoint - policies & sharing - Filer and folder links - MOET ZIJN - only the people the user specifies
    # $MBX = Get-PnPTenant # why requery the same information?

    # Check if anonymous users are allowed to join meetings
    $isAllowed = $SPOTenant.DefaultSharingLinkType -like "*Direct*"

    if ($isAllowed) {
       $outputObj | Add-Member -MemberType NoteProperty -Name ensure_link_sharing_restricted -Value $true -force
    } else {
       $outputObj | Add-Member -MemberType NoteProperty -Name ensure_link_sharing_restricted -Value $false -force
    }

    # Ensure guest access to a site or OneDrive will expire automatically
    # $MBX = Get-PnPTenant # why requery the same information?

    # Check if anonymous users are allowed to join meetings
    $isAllowed = $SPOTenant.ExternalUserExpirationRequired -like "*True*" -and $SPOTenant.ExternalUserExpireInDays -like "*30*"

    if ($isAllowed) {
       $outputObj | Add-Member -MemberType NoteProperty -Name ensure_link_expire_auto -Value $true -force
    } else {
       $outputObj | Add-Member -MemberType NoteProperty -Name ensure_link_expire_auto -Value $false -force
}

# Ensure reauthentication with verification code is restricted - https://admin.microsoft.com/sharepoint - policies & sharing - More external sharing settings - MOET ZIJN - People who use a verification code must reauthenticate after this many days (15 OF MINDER)
$SPOTenant = Get-PnPTenant

# Check if anonymous users are allowed to join meetings
$isAllowed = $SPOTenant.EmailAttestationRequired -like "*True*" -and $SPOTenant.EmailAttestationReAuthDays -like "*15*"

if ($isAllowed) {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_reauth_verify_code_restricted -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_reauth_verify_code_restricted -Value $false -force
}

<# MvdS: Setting is no longer located at that location
# PropertyNotFoundException: The property 'DenyAddAndCustomizePages' cannot be found on this object. Verify that the property exists.

$isAllowed = $SPOTenant.DenyAddAndCustomizePages

# Initialize a variable to track if any value is not enabled
$allEnabled = $true

# Check each value in $isAllowed
foreach ($value in $isAllowed) {
    if ($value -notlike "*Enabled*") {
        $allEnabled = $false
        break  # Exit the loop as soon as a non-enabled value is found
    }
}

# Check the $allEnabled variable to determine the final result
if ($allEnabled -eq $false) {
    $isAllowedResult = $false
} else {
    $isAllowedResult = $true
}

if ($isAllowedResult) {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_custom_script_sc_is_restricted -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_custom_script_sc_is_restricted -Value $false -force
}
#>

#disconnect from SharePoint Online
#Disconnect-SPOService
}
#endregion

#region Teams
##################################
# CONNECT TO TEAMS
# Connect-MicrosoftTeams
Connect-MicrosoftTeams -CertificateThumbprint $CertificateThumbprint -ApplicationId $ApplicationID -TenantId $TenantID

$TeamsPolicy = Get-CsTeamsMeetingPolicy -Identity Global

##################################
#Ensure users can report security concerns in Teams (voor deze ingelogd zijn op Teams + ExchangeOnline)
$TeamsMessagingPolicy = Get-CsTeamsMessagingPolicy -Identity Global

# Check if anonymous users are allowed to join meetings
$isAllowed = $TeamsMessagingPolicy.AllowSecurityEndUserReporting -like "*True*"

# Ensure anonymous users can't join a meeting - https://admin.teams.microsoft.com/policies/meetings - Global - (Anonymous users can join a meeting) is OFF
$isAllowed = $TeamsPolicy.AllowAnonymousUsersToJoinMeeting -like "*True*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_anonymous_cant_join_meeting -Value $false -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_anonymous_cant_join_meeting -Value $true -force
}

 # Ensure external file sharing in Teams is enabled for only approved cloud storage services
$TeamsClientConfig = Get-CsTeamsClientConfiguration 

# Check if anonymous users are allowed to join meetings
$isAllowedA = $TeamsClientConfig.AllowDropbox -like "*False*"
$isAllowedB = $TeamsClientConfig.AllowBox -like "*False*"
$isAllowedC = $TeamsClientConfig.AllowGoogleDrive -like "*False*"
$isAllowedD = $TeamsClientConfig.AllowShareFile -like "*False*"
$isAllowedE = $TeamsClientConfig.AllowEgnyte -like "*False*"

if ($isAllowedA -and $isAllowedB -and $isAllowedC -and $isAllowedD -and $isAllowedE) {
     $outputObj | Add-Member -MemberType NoteProperty -Name disable_extern_file_sharing_cloud_storages -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name disable_extern_file_sharing_cloud_storages -Value $false -force
}

# Ensure users can't send emails to a channel email address - https://admin.teams.microsoft.com/ - Teams - Teams settings - Users can send emails to a channel email address - MOET OFF zijn
# Check if anonymous users are allowed to join meetings
$isAllowedA = $TeamsClientConfig.AllowEmailIntoChannel -like "*False*"

if ($isAllowedA) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_cant_mail_to_channel_mail -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_cant_mail_to_channel_mail -Value $false -force
}

# Ensure 'external access' is restricted in the Teams admin center (Manual)
$TenantFederationConfig = Get-CsTenantFederationConfiguration

# Check if anonymous users are allowed to join meetings
$isAllowedA = $TenantFederationConfig.AllowTeamsConsumer -like "*False*"
$isAllowedB = $TenantFederationConfig.AllowTeamsConsumerInbound -like "*False*"
$isAllowedC = $TenantFederationConfig.AllowFederatedUsers -like "*False*"

if ($isAllowedA -and $isAllowedB -and $isAllowedC) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_external_access_not_allowed_teams -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_external_access_not_allowed_teams -Value $false -force
}

# Ensure anonymous users and dial-in callers can't start a meeting - https://admin.teams.microsoft.com/policies/meetings - Global - (Anonymous users and dial-in callers can start a meeting) is OFF
$TeamsMeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global

# Check if anonymous users are allowed to join meetings
$isAllowed = $TeamsMeetingPolicy.AllowAnonymousUsersToStartMeeting -like "*True*"

if ($isAllowed) {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_anonymous_cant_start_meeting -Value $false -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_anonymous_cant_start_meeting -Value $true -force
}

# Ensure only people in my org can bypass the lobby - https://admin.teams.microsoft.com/policies/meetings - Global - (Who can bypass the lobby) is (People in my org)
# Autoadmit users
$isAllowed = $TeamsMeetingPolicy.AutoAdmittedUsers -like "*EveryoneInCompanyExcludingGuests*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_bypass_lobby_meeting_disabled -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_bypass_lobby_meeting_disabled -Value $false -force
}

# Ensure only people in my org can bypass the lobby - https://admin.teams.microsoft.com/policies/meetings - Global - (Who can bypass the lobby) is (People in my org)
$isAllowed = $TeamsMeetingPolicy.AllowPSTNUsersToBypassLobby -like "*False*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_users_cant_bypass_lobby -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_users_cant_bypass_lobby -Value $false -force
}

# Ensure meeting chat does not allow anonymous users
$isAllowed = $TeamsMeetingPolicy.MeetingChatEnabledType -like "*EnabledExceptAnonymous*"

if ($isAllowed) {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_meeting_chat_not_allow_anonymous -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_meeting_chat_not_allow_anonymous -Value $false -force
}

# Ensure only organizers and co-organizers can present
$isAllowed = $TeamsMeetingPolicy.DesignatedPresenterRoleMode -like "*OrganizerOnlyUserOverride*"

if ($isAllowed) {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_only_org_and_co_present -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_only_org_and_co_present -Value $false -force
}

# Ensure external participants can't give or request control
$isAllowed = $TeamsMeetingPolicy.AllowExternalParticipantGiveRequestControl -like "*False*"

if ($isAllowed) {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_extern_cant_give_control -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_extern_cant_give_control -Value $false -force
}
#endregion

#region RestOfCIS
###GET ADDITIONAL CIS ITEMS AND CONTROL INFORMATION 
$modulePath="$env:ProgramFiles\WindowsPowerShell\Modules\Microsoft.Graph.Authentication\2.28.0"
Add-Type -Path "$modulePath\Microsoft.Graph.Authentication.dll"

Connect-MgGraph -ClientId $ApplicationId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint
# needs Policy.Read.All

$SecurityDefaultEnforcementPolicy=Query-Graph -uri "https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy"

#Ensure security defaults is disabled
$getRequiredValue = $SecurityDefaultEnforcementPolicy | Format-Table IsEnabled

if ($getRequiredValue.Enabled -ne $true) {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_security_defaults_is_disabled -Value $true -force
} else {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_security_defaults_is_disabled -Value $false -force
}

# needs Directory.Read.All
#Ensure a dynamic group for guest users is created (Manual)
# Get all dynamic groups
$dynamicGroups = Query-Graph -uri "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(s:s eq 'DynamicMembership')"

# Check if there is a dynamic group for guest users
$guestGroup = $dynamicGroups | Where-Object { $_.MembershipRule -like "*Guest*" }

# If a dynamic group for guest users does not exist, create one
if (!$guestGroup) {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_dynamic_group_guest_created -Value $false -force
} else {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_dynamic_group_guest_created -Value $true -force
}

#Ensure that password hash sync is enabled for hybrid deployments:
$MgOrg = Query-Graph -uri "https://graph.microsoft.com/beta/organization" 

# Check if anonymous users are allowed to join meetings
$isAllowed = $MgOrg.OnPremisesSyncEnabled -like "*True*"

if ($isAllowed) {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_password_hash_sync_is_enabled -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_password_hash_sync_is_enabled -Value $false -force
}

#Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'
$defaultUserRolePermissions = (Query-Graph "https://graph.microsoft.com/beta/policies/authorizationPolicy?`$select=defaultUserRolePermissions").value.defaultUserRolePermissions

$isAllowed = $defaultUserRolePermissions.allowedToCreateTenants -like "*False*"

if ($isAllowed) {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_restrict_non_admin_tenant_creation -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_restrict_non_admin_tenant_creation -Value $false -force
}

#Ensure that collaboration invitations are sent to allowed domains only (Manual)
$publicGroups =  $(Query-Graph -uri "https://graph.microsoft.com/beta/groups?`$filter=groupTypes/any(a:a eq 'unified')").value | Where-Object {$_.Visibility -eq "Public"} | Select-Object DisplayName,Visibility,Review

if ($null -eq $publicGroups) { 
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_collaboration_invite_is_private -Value $true -force
} else {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_collaboration_invite_is_private -Value $false -force
}

#Ensure that only organizationally managed/approved public groups exist
if ($null -ne $publicGroups) {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_organizationally_managed_public_groups_exist -Value $false -force
    $publicGroups | ConvertTo-Json | Out-File -FilePath "$outputPath\PubliclyVisibleGroups.json" -Encoding UTF8
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_organizationally_managed_public_groups_exist -Value $true -force
}

#_____________________________________________________________________________________________
### START GRAPH CONTROLE PROCES 
### HAAL UIT SECURE SCORE WAAR EN CONTROLEER OP PERCENTAGE < 100

# 1. Maak dump van Secure score via Graph naar file

Write-Output "Retrieving secure score results"

$getYesterday = Get-Date((get-date ).AddDays(-1))  -Format "yyyy-MM-dd"
$getTime = "T18:09:31Z"
$combineTime = $getYesterday+$getTime

$enable_sign_in_risk_policies = $false
$enable_user_risk_policies = $false

# Enable Azure AD Identity Protection sign-in risk policies
# needs SecurityEvents.Read.All
$url = "https://graph.microsoft.com/beta/security/secureScores?`$filter=createdDateTime ge $combineTime"
 
$requestList = $(Query-Graph -uri $url).value.controlscores
 
$outputObj | Add-Member -MemberType NoteProperty -Name enable_sign_in_risk_policies -Value $requestList -force

#maak dump van de output
$outputObj | ConvertTo-Json -Depth 100 | Out-File -FilePath "$outputPath\$localsecurescorefile"


# 2. Lees dump uit op de specifieke onderdelen

# search output

# Ensure multifactor authentication is enabled for all users in administrative roles (AdminMFAV2)
$getRequiredValue = $($requestList | Where-Object controlName -eq "AdminMFAV2").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_mfa_for_all_admin -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_mfa_for_all_admin -Value $false -force
}

# Ensure multifactor authentication is enabled for all users in all roles (MFARegistrationV2)
# search specific line for the pattern
$getRequiredValue = $($requestList | Where-Object controlName -eq "MFARegistrationV2").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_mfa_for_all_users -Value $true -force
	$outputObj | Add-Member -MemberType NoteProperty -Name dynamics_mfa_all_users -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_mfa_for_all_users -Value $false -force
	$outputObj | Add-Member -MemberType NoteProperty -Name dynamics_mfa_all_users -Value $false -force
}

#Ensure that between two and four global admins are designated (OneAdmin)
#search specific line for the pattern
$getRequiredValue = $($requestList | Where-Object controlName -eq "OneAdmin").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name prevent_number_of_admins -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name prevent_number_of_admins -Value $false -force
}

#Ensure 'Self service password reset enabled' is set to 'All' (Manual) - (SelfServicePasswordReset)
$getRequiredValue = $($requestList | Where-Object controlName -eq "SelfServicePasswordReset").scoreInPercentage
if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_self_service_password_reset -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_self_service_password_reset -Value $false -force
}

#Enable Conditional Access policies to block legacy authentication  (BlockLegacyAuthentication)
$getRequiredValue = $($requestList | Where-Object controlName -eq "BlockLegacyAuthentication").scoreInPercentage


if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_ca_to_block_basic_authentication -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_ca_to_block_basic_authentication -Value $false -force
}


#Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (PWAgePolicyNew)
$getRequiredValue = $($requestList | Where-Object controlName -eq "PWAgePolicyNew").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_password_do_not_expire -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_password_do_not_expire -Value $false -force
}
        
#Ensure the admin consent workflow is enabled (aad_admin_consent_workflow)
$getRequiredValue = $($requestList | Where-Object controlName -eq "aad_admin_consent_workflow").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_admin_consent_workflow -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_admin_consent_workflow -Value $false -force
}


#Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users (aad_sign_in_freq_session_timeout)
$getRequiredValue = $($requestList | Where-Object controlName -eq "aad_sign_in_freq_session_timeout").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_sign_in_frequency_browser_sessions -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_sign_in_frequency_browser_sessions -Value $false -force
}

#Ensure third party integrated applications are not allowed (aad_third_party_apps)
$getRequiredValue = $($requestList | Where-Object controlName -eq "aad_third_party_apps").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name disable_third_party_applications -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name disable_third_party_applications -Value $false -force
}

#Ensure user consent to apps accessing company data on their behalf is not allowed (IntegratedApps)
$getRequiredValue = $($requestList | Where-Object controlName -eq "IntegratedApps").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_user_consent_to_app_access -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_user_consent_to_app_access -Value $false -force
}

#Ensure SharePoint Online Information Protection policies are set up and used
$getRequiredValue = $($requestList | Where-Object controlName -eq "mip_autosensitivitylabelspolicies").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_spo_information_protection_policies -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_spo_information_protection_policies -Value $false -force
}

#Ensure Microsoft Defender for Cloud Apps is Enabled (mcas_mda_enabled)
$getRequiredValue = $($requestList | Where-Object controlName -eq "mcas_mda_enabled").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_defender_for_cloud_apps -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_defender_for_cloud_apps -Value $false -force
}


#Ensure modern authentication for Exchange Online is enabled
$getRequiredValue = $($requestList | Where-Object controlName -eq "OAuth2ClientProfileEnabled").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_modern_authentication_exo -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_modern_authentication_exo -Value $false -force
}


#Ensure Safe Links for Office Applications is Enabled 
$getRequiredValue = $($requestList | Where-Object controlName -eq "mdo_safelinksforOfficeApps").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_safe_links_in_office_applications -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_safe_links_in_office_applications -Value $false -force
}
  
  
  
#Ensure Safe Links for Office Applications is Enabled 
$getRequiredValue = $($requestList | Where-Object controlName -eq "mdo_safeattachments").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_safe_attachments -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_safe_attachments -Value $false -force
}
  
#Ensure the customer lockbox feature is enabled
$getRequiredValue = $($requestList | Where-Object controlName -eq "CustomerLockBoxEnabled").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_customer_lockbox -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_customer_lockbox -Value $false -force
}
   

#Ensure the Common Attachment Types Filter is enabled
$getRequiredValue = $($requestList | Where-Object controlName -eq "mdo_commonattachmentsfilter").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_common_attachment_type_filter -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_common_attachment_type_filter -Value $false -force
}
 

#Ensure all forms of mail forwarding are blocked and/or disabled
$getRequiredValue = $($requestList | Where-Object controlName -eq "mdo_blockmailforward").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name block_all_forms_of_email_forwarding -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name block_all_forms_of_email_forwarding -Value $false -force
}


#Ensure Safe Attachments policy is enabled
$getRequiredValue = $($requestList | Where-Object controlName -eq "mdo_safeattachments").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_safe_attachments -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_safe_attachments -Value $false -force
}



#Ensure that an anti-phishing policy has been created
$getRequiredValue = $($requestList | Where-Object controlName -eq "mdo_antiphishingpolicies").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_anti_phishing_policy_all_domains -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_anti_phishing_policy_all_domains -Value $false -force
}

#Ensure Exchange Online Spam Policies are set to notify administrators 
$getRequiredValue = $($requestList | Where-Object controlName -eq "mdo_spam_notifications_only_for_admins").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_exo_spam_policies_notify_admin -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_exo_spam_policies_notify_admin -Value $false -force
}

#Ensure notifications for internal users sending malware is Enabled 
$getRequiredValue = $($requestList | Where-Object controlName -eq "mdo_spam_notifications_only_for_admins").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_notifications_internal_users_malware -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_notifications_internal_users_malware -Value $false -force
}

#Ensure MailTips are enabled for end users
$getRequiredValue = $($requestList | Where-Object controlName -eq "exo_mailtipsenabled").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_mailtips -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_mailtips -Value $false -force
}

#Ensure Microsoft 365 audit log search is Enabled
$getRequiredValue = $($requestList | Where-Object controlName -eq "mip_search_auditlog").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_audit_log_search -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_audit_log_search -Value $false -force
}

#Ensure 'AuditDisabled' organizationally is set to 'False' - Ensure mailbox auditing for all users is Enabled
$getRequiredValue = $($requestList | Where-Object controlName -eq "exo_mailboxaudit").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_mailbox_auditing_all_users -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_mailbox_auditing_all_users -Value $false -force
}

#Ensure additional storage providers are restricted in Outlook on the web
$getRequiredValue = $($requestList | Where-Object controlName -eq "exo_storageproviderrestricted").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name block_external_storage_providers_outlook -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name block_external_storage_providers_outlook -Value $false -force
}



#Ensure modern authentication for SharePoint applications is required
$getRequiredValue = $($requestList | Where-Object controlName -eq "spo_legacy_auth").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_modern_authentication_spo -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_modern_authentication_spo -Value $false -force
}

#Ensure OneDrive sync is restricted for unmanaged devices
$getRequiredValue = $($requestList | Where-Object controlName -eq "spo_block_onedrive_sync_unmanaged_devices").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name block_onedrive_sync_unmanaged_devices -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name block_onedrive_sync_unmanaged_devices -Value $false -force
}

#Ensure SharePoint external sharing is managed through domain whitelist/blacklists
$getRequiredValue = $($requestList | Where-Object controlName -eq "spo_external_sharing_managed").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_document_sharing_whitelist -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_document_sharing_whitelist -Value $false -force
}

#Ensure Administrative accounts are separate and cloud-only (Manual) - https://admin.microsoft.com/#/users > filter sync status > all should be cloud if role is admin
$getRequiredValue = $($requestList | Where-Object controlName -eq "aad_admin_accounts_separate_unassigned_cloud_only").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_admin_accounts_are_cloud_only -Value $true -force
	$outputObj | Add-Member -MemberType NoteProperty -Name dynamics_admin_cloud_only -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_admin_accounts_are_cloud_only -Value $false -force
	$outputObj | Add-Member -MemberType NoteProperty -Name dynamics_admin_cloud_only -Value $false -force
}

#Ensure DLP policies are enabled
$getRequiredValue = $($requestList | Where-Object controlName -eq "dlp_datalossprevention").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_dlp -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_dlp -Value $false -force
}

#Ensure DLP policies are enabled for Teams
$getRequiredValue = $($requestList | Where-Object controlName -eq "mip_DLP_policies_Teams").scoreInPercentage

if ($getRequiredValue -like "*100*") { 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_dlp_teams -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_dlp_teams -Value $false -force
}

### START AUDIT OTHER ITEMS
Write-Output "Retrieving IdentityRiskDetections and riskyUsers"
$startDate = (Get-Date).AddDays(-100).ToUniversalTime().ToString("s") #todo: get period from automationaccount variable
$startDate = $startDate + "Z"

$enable_sign_in_risk_policies = $false
$enable_user_risk_policies = $false

#Enable Azure AD Identity Protection sign-in risk policies

$url = "https://graph.microsoft.com/beta/identityProtection/riskDetections?`$filter=detectedDateTime gt $startDate&`$top=1"
 
$requestList = Query-Graph -Uri $url
 
ForEach ($request In $requestList.Value) {
    $request
    $enable_sign_in_risk_policies = $null -ne $request
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_sign_in_risk_policies -Value $enable_sign_in_risk_policies -force
}

if($enable_sign_in_risk_policies -eq $true) {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_sign_in_risk_policies -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_sign_in_risk_policies -Value $false -force
}

#Enable Azure AD Identity Protection user risk policies
$url = "https://graph.microsoft.com/beta/identityProtection/riskyUsers?`$filter=riskLastUpdatedDateTime gt $startDate&`$top=1"
$requestList = Query-Graph -uri $url
 
ForEach ($request In $requestList.Value) {
   $request
   $enable_user_risk_policies = $null -ne $request
   $outputObj | Add-Member -MemberType NoteProperty -Name enable_user_risk_policies -Value $enable_user_risk_policies -force
}

if($enable_user_risk_policies -eq $true) {
   $outputObj | Add-Member -MemberType NoteProperty -Name enable_user_risk_policies -Value $true -force
}else {
   $outputObj | Add-Member -MemberType NoteProperty -Name enable_user_risk_policies -Value $false -force
}

### Ensure the admin consent workflow is enabled

# Write-Output "Retrieving Admin Consent policy settings"
#
# $url = "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy"
# $requestList = Invoke-MgGraphRequest -Uri $url -Method Get
# $outputObj | Add-Member -MemberType NoteProperty -Name enable_admin_consent_workflow -Value $requestList -force
# $getOutputisEnabled = $requestList
# $valueisEnabled = $getOutputisEnabled | Select-Object -ExpandProperty isEnabled
# $getOutputreviewers = $requestList
# $valuereviewers = $getOutputreviewers | Select-Object -ExpandProperty reviewers


# if($valueisEnabled -eq $true -And $valuereviewers -ne $null) {
#     $outputObj | Add-Member -MemberType NoteProperty -Name enable_admin_consent_workflow -Value $true -force
# }else {
#     $outputObj | Add-Member -MemberType NoteProperty -Name enable_admin_consent_workflow -Value $false -force
# }

################################
### CREATE DUMP FILE

Write-Output "Creating local file"
	
$outputObj | ConvertTo-Json -Depth 100 | Out-File -FilePath "$outputPath\$localfile" -Append

# $outputObj | export-csv -Path "$workingdir\audit_results\log_cis.csv" -NoTypeInformation
# $outputObj | Out-File -FilePath "$workingdir\log_cis.txt"
#endregion    
### END
#$true | Out-File -FilePath "$workingdir\audit_results\cis_305.txt"
#        Write-Host "Audit passed" 
Write-Host "CIS audit part 2 of 2 is finished" -fore green
