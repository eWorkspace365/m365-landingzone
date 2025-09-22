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
# RUN NU HET HELE SCRIPT: dit zorgt ervoor dat alles netjes in 1 log komt
#
# TODO: handmatige acties in code zetten\
#
# Zorg tot slot dat onderaan de folder voor het dump path lokaal bestaat
#
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

set-strictmode -version Latest
$ErrorActionPreference = "stop"


# Ability to run scripts based on relative path
If ($myInvocation.MyCommand.CommandType -ne [System.Management.Automation.CommandTypes]::Script)
{
    $scriptfolder = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
    #the output below returns the parent of the scriptfolder (normally where also \modules and \logs are located )
    #$Global:WorkingDir = $($(Get-Item $scriptfolder).Parent).FullName
    $Global:WorkingDir = $($(Get-Item $scriptfolder).FullName)
}
Else
{
    $scriptfolder = [System.IO.Path]::GetDirectoryName($psISE.CurrentFile.FullPath)
    #the output below returns the parent of the scriptfolder (normally where also \modules and \logs are located )
    #$Global:WorkingDir = $($(Get-Item $scriptfolder).Parent).FullName
    $Global:WorkingDir = $($(Get-Item $scriptfolder).FullName)
}
###############
# The section above only works when the script is run if it is SAVED on any given location!!! Otherwise the parentfolder location cannot be retrieved!
# MAKE SURE TO SAVE THE FILE BEFORE RUNNING THE SCRIPT
###############
    
#endregion

############################################################################

#First create the file output
Write-Output "Creating output object"
$timestamp = Get-Date -Format "dd/MM/yyyy"
$scriptVersion = "1.0"
$localfile = "log_cis.json"
$localsecurescorefile = "log_secure_score.json"
$localm365dscfile = "M365TenantConfig.ps1"

#Bepaal of we SPO in de scan uitvoeren of niet (true = ja / false = nee)
$checkSPO = $true

$secureScoreDumpFile = "$localsecurescorefile"

$outputObj = New-Object -TypeName psobject
$outputObj | Add-Member -MemberType NoteProperty -Name version -Value $scriptVersion
$outputObj | Add-Member -MemberType NoteProperty -Name timestamp -Value $timestamp
$outputObj | Add-Member -MemberType NoteProperty -Name customerId -Value $customerId


#Enter the app registration details for the CIS / Graph scan

#app registration heeft de volgende rechten nodig
#DeviceManagementConfiguration.Read.All
#DeviceManagementConfiguration.ReadWrite.All
#Directory.Read.All
#Group.Read.All
#IdentityRiskEvent.Read.All
#IdentityRiskyUser.Read.All
#Policy.Read.All
#Policy.ReadWrite.SecurityDefaults
#SecurityActions.Read.All
#SecurityAlert.Read.All
#SecurityEvents.Read.All
#SecurityIncident.Read.All


#_____________________________________________________________________________________________
 
 
 ###INTUNE CONTROLES
 
 #Controleer of Intune is ingericht conform de best practices: ga naar intune.microsoft.com. Controleer nu het volgende (alles moet correct zijn) met de baseline scripts
 
 ####Compliance policies ingericht	
 
 #Ensure Compliance policy is set for Windows
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_compliance_windows -Value $true -force
 #Ensure Compliance policy is set for Android
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_compliance_android -Value $true -force
 #Ensure Compliance policy is set for iOS
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_compliance_ios -Value $true -force
 #Ensure Compliance policy is set for macOS
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_compliance_macos -Value $true -force
 #Ensure Compliance policy is set for Linux
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_compliance_linux -Value $false -force
 
 ####Patch management oplossing ingericht (remediation, software bijgewerkt)
 
 #Ensure Update rings are set for Windows updates
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_windows_update_rings -Value $true -force
 #Ensure Update rings are set for Windows drivers
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_windows_driver_updates -Value $false -force
 #Ensure Update solutions are in place for third party patching
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_windows_remediation_third_party -Value $false -force
 
 ####Security baselines ingericht voor alle onderdelen  
 
 #Ensure the security baseline is set for Windows
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_security_baseline_windows -Value $true -force
 #Ensure the security baseline is set for Defender for Endpoint
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_security_baseline_defender_endpoint -Value $true -force
 #Ensure the security baseline is set for Edge
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_security_baseline_edge -Value $true -force
 #Ensure the security baseline is set for Windows 365
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_security_baseline_windows365 -Value $true -force
 #Ensure the security baseline is set for Apps for Enterprise
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_security_baseline_appsenterprise -Value $false -force
 
 ####Endpoint security scripts voor alle onderdelen toegevoegd  
 
 #Ensure the security settings are configured for Endpoint antivirus
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_endpoint_security_antivirus -Value $true -force
 #Ensure the security settings are configured for Endpoint disk encryption
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_endpoint_security_diskencryption -Value $true -force
 #Ensure the security settings are configured for Endpoint firewall
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_endpoint_security_firewall -Value $true -force
 #Ensure the security settings are configured for Endpoint ASR
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_endpoint_security_asr -Value $true -force
 #Ensure the security settings are configured for Endpoint account protection
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_endpoint_security_accountprotection -Value $true -force
 #Ensure the security settings are configured for Endpoint and all settings are enabled
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_endpoint_security_all_setup_config -Value $false -force
 
 ####Rollen (RBAC) toegewezen aan gebruikers / groepen
 #Ensure groups are added to their RBAC roles
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_rbac_configured -Value $false -force
 
 ####General settings
 #Ensure Android certifcation sync is in place
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_android_certificate -Value $true -force
 #Ensure Apple certifcation sync is in place
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_apple_certificate -Value $true -force
 #Ensure auto pilot profiles exist and have standard users only
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_auto_pilot_profile -Value $true -force
 
 ####Conditional access for mobile devices
 #Ensure conditional access is active for compliant devices only
 $outputObj | Add-Member -MemberType NoteProperty -Name intune_ca_compliant_devices -Value $true -force

#_____________________________________________________________________________________________


 ###CIS DYNAMIC / POWER PLATFORM CONTROLES

 #Ensure User access to environments is controlled with Security Groups - https://learn.microsoft.com/en-us/power-platform/admin/control-user-access
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_environment_security_groups -Value $true -force

 #Ensure User sessions are terminated upon time limit exceeded and user logoff - https://admin.powerplatform.microsoft.com/
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_environment_session_exceed -Value $false -force

 #Ensure Administrative accounts are separate unassigned and cloud only Dynamics
 # Controle vind plaats bij M365 CIS controle onderaan (dynamics_admin_cloud_only)
 
 #Ensure Multifactor authentication for all users is Enabled Dynamics
 # Controle vind plaats bij M365 CIS controle onderaan (dynamics_mfa_all_users)
 
 #Ensure Creation of new trial production and sandbox environments is restricted to Administrators - https://admin.powerplatform.microsoft.com/tenantsettings?setting=trial_assignment (only admin)
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_trial_sandbox_admin -Value $false -force
 
 #Ensure Security roles provide access to the minimum amount of business data required - https://admin.powerplatform.microsoft.com/ (moet met klant beoordeeld worden of rollen juist zijn per enviroment)
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_security_role_minumum -Value $true -force
 
 #Ensure Set blocked file extensions is configured to match the enterprise block list - https://admin.powerplatform.microsoft.com/ (klant moet beoordelen of de defaults voldoende zijn)
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_block_extensions -Value $true -force
 
 #Ensure Access to the environment is restricted by location - Controle op location based Conditional access - https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_location_ca -Value $true -force

 #Ensure Cross-tenant isolation is enabled for Power Platform Apps and Flows - https://admin.powerplatform.microsoft.com/governance/tenantIsolation?geo=Emea
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_tenant_isolation -Value $false -force
 
 #Ensure Environments with Critical Data are Encrypted with Customer Managed Keys - https://admin.powerplatform.microsoft.com/ > Environment > Settings > Encryption > on
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_encryption_on -Value $true -force
 
 #Ensure Extract customer data privileges from Microsoft Dynamics 365 is controlled - https://admin.powerplatform.microsoft.com/ (moet met klant beoordeeld worden)
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_privileged_role_control -Value $true -force
 
 #Ensure Dynamics 365 restricts incoming email actions for public queue mailboxes - https://admin.powerplatform.microsoft.com/ > Settings > Business > loop stappen door
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_restrict_incoming_email -Value $false -force
 
 #Ensure DLP policies are enabled and restrict the connectors usage - https://admin.powerplatform.microsoft.com/dlp (policies moeten aanwezig zijn)
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_dlp_policies -Value $false -force
 
 #Ensure System Administrator security role changes are reviewed periodically - https://admin.powerplatform.microsoft.com/ > Settings > loop stappen door voor users permissions
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_review_admin_sec_roles -Value $true -force

 #Ensure Environment Activity logging is Enabled - https://admin.powerplatform.microsoft.com/ > Settings > Audit and logs > Audit settings > Start auditing, log access EN read logs moeten aan staan.
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_enable_audit_logs -Value $false -force
 
 #Ensure App creation notification is enabled in the environment - https://admin.powerplatform.microsoft.com/ > Policies > Alert policies > notificatie policy moet aanwezig zijn (omvat compliance app alerts - zie CIS)
 $outputObj | Add-Member -MemberType NoteProperty -Name dynamics_notification_policies -Value $false -force
 
#_____________________________________________________________________________________________




 ### LET OP: ZOEK VERDER OP (MET-HAND-VULLEN) VOOR DE OVERIGE ONDERDELEN DIE MET DE HAND MOETEN VOORDAT COMPLETE CODE WORDT AFGETRAPT
#_____________________________________________________________________________________________
 
 ###ENKELE HANDMATIGE CONTROLES - LET OP BEPAALDE WAARDES MET DE HAND AANPASSEN IN DE OUTPUT!


 ##################################

 # CONNECT TO SHAREPOINT ONLINE

#SHAREPOINT

if ($checkSPO) {

#connect to SharePoint Online
Write-Output "Connecting to SharePoint Online"
	
Connect-ExchangeOnline -CertificateThumbPrint $CertificateThumbprint -AppID $ClientID -Organization $Organization
Connect-PnPOnline -Url $AdminUrl -ClientId $ClientID -Thumbprint $CertificateThumbprint -Tenant $Organization

#Ensure Office 365 SharePoint infected files are disallowed for download
$MBX = Get-PnPTenant 

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.DisallowInfectedFileDownload -like "*True*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name disallow_infected_files_for_download -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name disallow_infected_files_for_download -Value $false -force
}



#Ensure that SharePoint guest users cannot share items they don't own (Automated)
$MBX = Get-PnPTenant 

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.PreventExternalUsersFromResharing -like "*True*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name disable_sharing_external_do_not_own -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name disable_sharing_external_do_not_own -Value $false -force
}





# Ensure external content sharing is restricted (Automated) - https://admin.microsoft.com/sharepoint - policies & sharing - external sharing -> New and existing guests OR LOWER must be set
$MBX = Get-PnPTenant

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.SharingCapability -like "*ExternalUserSharingOnly*" -or $MBX.SharingCapability -like "*ExistingExternalUserSharingOnly*" -or $MBX.SharingCapability -like "*Disabled*"

if ($isAllowed) {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_external_sharing_restricted -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_external_sharing_restricted -Value $false -force
}





# Ensure link sharing is restricted in SharePoint and OneDrive - https://admin.microsoft.com/sharepoint - policies & sharing - Filer and folder links - MOET ZIJN - only the people the user specifies
$MBX = Get-PnPTenant

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.DefaultSharingLinkType -like "*Direct*"

if ($isAllowed) {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_link_sharing_restricted -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_link_sharing_restricted -Value $false -force
}







# Ensure guest access to a site or OneDrive will expire automatically
$MBX = Get-PnPTenant

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.ExternalUserExpirationRequired -like "*True*" -and $MBX.ExternalUserExpireInDays -like "*30*"

if ($isAllowed) {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_link_expire_auto -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_link_expire_auto -Value $false -force
}





# Ensure reauthentication with verification code is restricted - https://admin.microsoft.com/sharepoint - policies & sharing - More external sharing settings - MOET ZIJN - People who use a verification code must reauthenticate after this many days (15 OF MINDER)
$MBX = Get-PnPTenant

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.EmailAttestationRequired -like "*True*" -and $MBX.EmailAttestationReAuthDays -like "*15*"

if ($isAllowed) {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_reauth_verify_code_restricted -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_reauth_verify_code_restricted -Value $false -force
}






# Ensure custom script execution is restricted on site collections


$MBX = Get-PnPTenantSite

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.DenyAddAndCustomizePages

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

$isAllowedResult

if ($isAllowedResult) {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_custom_script_sc_is_restricted -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_custom_script_sc_is_restricted -Value $false -force
}


	
#disconnect from SharePoint Online
#Disconnect-SPOService

}

  ##################################

 # CONNECT TO TEAMS

# Connect-MicrosoftTeams
Connect-MicrosoftTeams -CertificateThumbprint $CertificateThumbprint -ApplicationId $ClientID -TenantId $Organization


 # Ensure anonymous users can't join a meeting - https://admin.teams.microsoft.com/policies/meetings - Global - (Anonymous users can join a meeting) is OFF
$MBX = Get-CsTeamsMeetingPolicy -Identity Global

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.AllowAnonymousUsersToJoinMeeting -like "*True*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_anonymous_cant_join_meeting -Value $false -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_anonymous_cant_join_meeting -Value $true -force
}




 # Ensure external file sharing in Teams is enabled for only approved cloud storage services
$MBX = Get-CsTeamsClientConfiguration 

# Check if anonymous users are allowed to join meetings
$isAllowedA = $MBX.AllowDropbox -like "*False*"
$isAllowedB = $MBX.AllowBox -like "*False*"
$isAllowedC = $MBX.AllowGoogleDrive -like "*False*"
$isAllowedD = $MBX.AllowShareFile -like "*False*"
$isAllowedE = $MBX.AllowEgnyte -like "*False*"


if ($isAllowedA -and $isAllowedB -and $isAllowedC -and $isAllowedD -and $isAllowedE) {
     $outputObj | Add-Member -MemberType NoteProperty -Name disable_extern_file_sharing_cloud_storages -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name disable_extern_file_sharing_cloud_storages -Value $false -force
}




# Ensure users can't send emails to a channel email address - https://admin.teams.microsoft.com/ - Teams - Teams settings - Users can send emails to a channel email address - MOET OFF zijn
$MBX = Get-CsTeamsClientConfiguration -Identity Global

# Check if anonymous users are allowed to join meetings
$isAllowedA = $MBX.AllowEmailIntoChannel -like "*False*"


if ($isAllowedA) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_cant_mail_to_channel_mail -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_cant_mail_to_channel_mail -Value $false -force
}

 
 
 
 











 # Ensure anonymous users and dial-in callers can't start a meeting - https://admin.teams.microsoft.com/policies/meetings - Global - (Anonymous users and dial-in callers can start a meeting) is OFF
$MBX = Get-CsTeamsMeetingPolicy -Identity Global

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.AllowAnonymousUsersToStartMeeting -like "*True*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_anonymous_cant_start_meeting -Value $false -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_anonymous_cant_start_meeting -Value $true -force
}



 # Ensure only people in my org can bypass the lobby - https://admin.teams.microsoft.com/policies/meetings - Global - (Who can bypass the lobby) is (People in my org)
$MBX = Get-CsTeamsMeetingPolicy -Identity Global

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.AutoAdmittedUsers -like "*EveryoneInCompanyExcludingGuests*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_bypass_lobby_meeting_disabled -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_bypass_lobby_meeting_disabled -Value $false -force
}



 # Ensure only people in my org can bypass the lobby - https://admin.teams.microsoft.com/policies/meetings - Global - (Who can bypass the lobby) is (People in my org)
$MBX = Get-CsTeamsMeetingPolicy -Identity Global

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.AllowPSTNUsersToBypassLobby -like "*False*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_users_cant_bypass_lobby -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_users_cant_bypass_lobby -Value $false -force
}



 # Ensure meeting chat does not allow anonymous users
$MBX = Get-CsTeamsMeetingPolicy -Identity Global

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.MeetingChatEnabledType -like "*EnabledExceptAnonymous*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_meeting_chat_not_allow_anonymous -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_meeting_chat_not_allow_anonymous -Value $false -force
}




 # Ensure only organizers and co-organizers can present
$MBX = Get-CsTeamsMeetingPolicy -Identity Global

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.DesignatedPresenterRoleMode -like "*OrganizerOnlyUserOverride*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_only_org_and_co_present -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_only_org_and_co_present -Value $false -force
}



 # Ensure external participants can't give or request control
$MBX = Get-CsTeamsMeetingPolicy -Identity Global

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.AllowExternalParticipantGiveRequestControl -like "*False*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_extern_cant_give_control -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_extern_cant_give_control -Value $false -force
}






 ##################################

 # CONNECT TO EXCHANGE ONLINE

 # Connect-ExchangeOnline
Connect-ExchangeOnline -CertificateThumbPrint $CertificateThumbprint -AppID $ClientID -Organization $Organization

 # Connect-AzureAD
Connect-AzureAD -TenantId $TenantID -ApplicationId $ClientID -CertificateThumbprint $CertificateThumbprint



 #Ensure users installing Outlook add-ins is not allowed - https://admin.exchange.microsoft.com/#/userroles - Default Role - Manage Permissions - My Custom Apps, My Marketplace AND My ReadWriteMailboxApps moeten UNCHECKED zijn

$MBX = Get-EXOMailbox | Select-Object -Unique RoleAssignmentPolicy | 
ForEach-Object { 
 Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | 
 Where-Object {$_.AssignedRoles -like "*Apps*"}
} | Select-Object Identity, @{Name="AssignedRoles"; Expression={

Get-Mailbox | Select-Object -Unique RoleAssignmentPolicy | 
 ForEach-Object { 
 Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | 
 Select-Object -ExpandProperty AssignedRoles | 
 Where-Object {$_ -like "*Apps*"}
 }
}}

$isAllowed = $MBX -eq $null

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name disable_outlook_add_in_install -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name disable_outlook_add_in_install -Value $false -force
}
 
 
 








####
#Ensure users can report security concerns in Teams (voor deze ingelogd zijn op Teams + ExchangeOnline)
$MBX = Get-CsTeamsMessagingPolicy -Identity Global

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.AllowSecurityEndUserReporting -like "*True*"


$MBXDefender = Get-ReportSubmissionPolicy

if ($MBXDefender -ne $null) {
    $isAllowedA = $MBXDefender.ReportJunkToCustomizedAddress -like "*True*"
    $isAllowedB = $MBXDefender.ReportNotJunkToCustomizedAddress -like "*True*"
    $isAllowedC = $MBXDefender.ReportPhishToCustomizedAddress -like "*True*"
    $isAllowedD = $MBXDefender.ReportChatMessageEnabled -like "*False*"
    $isAllowedE = $MBXDefender.ReportChatMessageToCustomizedAddressEnabled -like "*True*"

    $isAllowedF = $MBXDefender.ReportJunkAddresses -like "*@*"
    $isAllowedG = $MBXDefender.ReportNotJunkAddresses -like "*@*"
    $isAllowedH = $MBXDefender.ReportNotJunkAddresses -like "*@*"
} else {
    Write-Host "Geen waarde"
}





if ($isAllowed -and $isAllowedA -and $isAllowedB -and $isAllowedC -and $isAllowedD -and $isAllowedE) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_users_can_report_sec -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_users_can_report_sec -Value $false -force
}



####









 # Ensure 'External sharing' of calendars is not available (Automated)
$MBX = Get-SharingPolicy 

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.Domains -like "*CalendarSharing*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name external_calendar_sharing_not_available -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name external_calendar_sharing_not_available -Value $false -force
}





#Ensure mailbox auditing for E3 users is Enabled (Automated) - AuditEnabled voor alles TRUE zijn (zie logs)
#EN
#Ensure mailbox auditing for E5 users is Enabled (Automated) - AuditEnabled voor alles TRUE zijn (zie logs)
$MailAudit = Get-EXOMailbox -PropertySets Audit -ResultSize Unlimited |  Select-Object UserPrincipalName, AuditEnabled, AuditAdmin, AuditDelegate, AuditOwner

# Define the path to the folder to check
$FolderPath = "C:\Temp"

# Check if the folder exists
if (Test-Path -Path $FolderPath) {
    # The folder exists, do nothing
} else {
    # The folder does not exist, create it
    New-Item -Path $FolderPath -ItemType Directory
}

# Export the MailAudit object to the C:\Temp\AuditSettings.txt file in TXT format
$MailAudit | Export-Csv -Path "C:\Temp\AuditSettings.txt" -NoTypeInformation -Encoding UTF8

# Export the MailAudit object to the C:\Temp\AuditSettings.json file in JSON format
$MailAudit | ConvertTo-Json | Out-File -FilePath "C:\Temp\AuditSettings.json" -Encoding UTF8

##########################################################################################

#VUL HIER DE JUISTE WAARDE MET DE HAND IN (MET-HAND-VULLEN)
 $outputObj | Add-Member -MemberType NoteProperty -Name ensure_mailbox_audit_e3_enabled -Value $false -force
 $outputObj | Add-Member -MemberType NoteProperty -Name ensure_mailbox_audit_e5_enabled -Value $false -force

##########################################################################################


# Ensure 'AuditBypassEnabled' is not enabled on mailboxes (Manual) - Uitkomst moet zijn dat er geen resultaten zijn
$outputObj | Add-Member -MemberType NoteProperty -Name ensure_auditbypass_not_enabled -Value $true -force

# Haal alle mailboxen op die mailbox-auditlogboekregistratie kunnen omzeilen
$MBX = Get-MailboxAuditBypassAssociation -ResultSize unlimited | where {$_.AuditBypassEnabled -eq $true}

# Controleer of er mailboxen zijn met AuditBypassEnabled ingesteld op $true
if ($MBX | Where-Object {$_.AuditBypassEnabled -eq $true}) {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_auditbypass_not_enabled -Value $false -force
}

# Anders, voeg dan de eigenschap ensure_mail_transport_rules_not_whitelist toe aan $outputObj en stel deze in op $true
else {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_auditbypass_not_enabled -Value $true -force
}




# Ensure email from external senders is identified (Automated)
$outputObj | Add-Member -MemberType NoteProperty -Name ensure_external_sender_identified_enabled -Value $true -force

# Haal alle mailboxen op die mailbox-auditlogboekregistratie kunnen omzeilen
$MBX = Get-ExternalInOutlook | where {$_.Enabled -eq $False}

# Controleer of zaken zijn die $true zijn
if ($MBX | Where-Object {$_.Enabled -eq $true}) {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_external_sender_identified_enabled -Value $true -force
}

else {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_external_sender_identified_enabled -Value $false -force
}






#Ensure sign-in to shared mailboxes is blocked
$MBX = Get-EXOMailbox -RecipientTypeDetails SharedMailbox
$MBX | ForEach {Get-AzureADUser -ObjectId $_.ExternalDirectoryObjectId} | Format-Table DisplayName,UserPrincipalName,AccountEnabled
#Expected result: Ensure AccountEnabled is set to False for all Shared Mailboxes. If not false the check failed

##########################################################################################

#VUL HIER DE JUISTE WAARDE MET DE HAND IN (MET-HAND-VULLEN)

$outputObj | Add-Member -MemberType NoteProperty -Name ensure_sign_in_shared_mailbox_blocked -Value $false -force

##########################################################################################




 








 #Ensure mail transport rules do not whitelist specific domains (Automated)
 $getRequiredValue = Get-TransportRule | Where-Object {($_.setscl -eq -1 -and $_.SenderDomainIs -ne $null)} | ft Name,SenderDomainIs
  if ($getRequiredValue -eq $NULL) { 
            $outputObj | Add-Member -MemberType NoteProperty -Name ensure_mail_transport_rules_not_whitelist -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name ensure_mail_transport_rules_not_whitelist -Value $false -force
        }










#Ensure that SPF records are published for all Exchange Domains (Manual)

# Get all Exchange Online domains
$domains = Get-AcceptedDomain | Where-Object { $_.DomainType -eq "Authoritative" }

# Loop through each domain and check SPF record
foreach ($domain in $domains) {
    $spfRecord = Resolve-DnsName -Name ($domain.DomainName + "._spf." + $domain.DomainName) -Type TXT -ErrorAction SilentlyContinue
    
    if ($spfRecord) {


    try {
        $spfValue = $spfRecord | Select-Object -ExpandProperty Strings
        Write-Host "SPF record is published for domain $($domain.DomainName)"
        Write-Host "SPF record value: $spfValue"
            $outputObj | Add-Member -MemberType NoteProperty -Name ensure_spf_is_published_for_all_exo_domains -Value $true -force
    }
    catch {
        Write-Host "Error occurred while processing SPF record for domain $($domain.DomainName): $_"
        $outputObj | Add-Member -MemberType NoteProperty -Name ensure_spf_is_published_for_all_exo_domains -Value $false -force
    }

    }
    else {
        Write-Host "SPF record is not published for domain $($domain.DomainName)"

             if ($($domain.DomainName) -like "*onmicrosoft.com*") { 
                $outputObj | Add-Member -MemberType NoteProperty -Name ensure_spf_is_published_for_all_exo_domains -Value $true -force
            }else {
                $outputObj | Add-Member -MemberType NoteProperty -Name ensure_spf_is_published_for_all_exo_domains -Value $false -force
            }



    }
}
  


#Ensure DMARC Records for all Exchange Online domains are published (Manual)

# Get all Exchange Online domains
$domains = Get-AcceptedDomain | Where-Object { $_.DomainType -eq "Authoritative" }

# Loop through each domain and check DMARC record
foreach ($domain in $domains) {
    $dmarcRecord = Resolve-DnsName -Name ("_dmarc." + $domain.DomainName) -Type TXT -ErrorAction SilentlyContinue
    if ($dmarcRecord) {

        try {
        $dmarcValue = $dmarcRecord | Select-Object -ExpandProperty Strings
        Write-Host "DMARC record is published for domain $($domain.DomainName)"
        Write-Host "DMARC record value: $dmarcValue"
            $outputObj | Add-Member -MemberType NoteProperty -Name ensure_dmark_is_published_for_all_exo_domains -Value $true -force
    }
    catch {
        Write-Host "Error occurred while processing SPF record for domain $($domain.DomainName): $_"
        $outputObj | Add-Member -MemberType NoteProperty -Name ensure_dmark_is_published_for_all_exo_domains -Value $false -force
    }


        
    }
    else {
        Write-Host "DMARC record is not published for domain $($domain.DomainName)"
         if ($($domain.DomainName) -like "*onmicrosoft.com*") { 
                $outputObj | Add-Member -MemberType NoteProperty -Name ensure_dmark_is_published_for_all_exo_domains -Value $true -force
            }else {
                $outputObj | Add-Member -MemberType NoteProperty -Name ensure_dmark_is_published_for_all_exo_domains -Value $false -force
            }

    }
}




#Disconnect-ExchangeOnline
#Disconnect-AzureAD
#Disconnect-PnPOnline

#_____________________________________________________________________________________________
 

###GET ADDITIONAL CIS ITEMS AND CONTROL INFORMATION 


Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint


Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy

#Ensure security defaults is disabled
$getRequiredValue = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | ft IsEnabled

if ($getRequiredValue -ne $true) {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_security_defaults_is_disabled -Value $true -force
} else {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_security_defaults_is_disabled -Value $false -force
}






#Ensure a dynamic group for guest users is created (Manual)

 # Get all dynamic groups
$dynamicGroups = Get-MgGroup | Where-Object { $_.GroupTypes -contains "DynamicMembership" }

# Check if there is a dynamic group for guest users
$guestGroup = $dynamicGroups | Where-Object { $_.MembershipRule -like "*Guest*" }

# If a dynamic group for guest users does not exist, create one
if (!$guestGroup) {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_dynamic_group_guest_created -Value $false -force
}
else {
            $outputObj | Add-Member -MemberType NoteProperty -Name ensure_dynamic_group_guest_created -Value $true -force
        }






#Ensure that password hash sync is enabled for hybrid deployments:
$MBX = Get-MgOrganization 

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.OnPremisesSyncEnabled -like "*True*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_password_hash_sync_is_enabled -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_password_hash_sync_is_enabled -Value $false -force
}




 
 

#Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'
$MBX = Get-MgPolicyAuthorizationPolicy 

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.DefaultUserRolePermissions.AdditionalProperties -like "*False*"

if ($isAllowed) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_restrict_non_admin_tenant_creation -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_restrict_non_admin_tenant_creation -Value $false -force
}





 #Ensure that collaboration invitations are sent to allowed domains only (Manual)

$getRequiredValue =  Get-MgGroup | where {$_.Visibility -eq "Public"} | select DisplayName,Visibility

 if ($getRequiredValue -eq $NULL) { 
            $outputObj | Add-Member -MemberType NoteProperty -Name ensure_collaboration_invite_is_private -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name ensure_collaboration_invite_is_private -Value $false -force
        }
 
 



 
#_____________________________________________________________________________________________
  
###START GRAPH CONTROLE PROCES 


###HAAL UIT SECURE SCORE WAAR EN CONTROLEER OP PERCENTAGE < 100

# 1. Maak dump van Secure score via Graph naar file

    Write-Output "Retrieving secure score results"

    $getYesterday = Get-Date((get-date ).AddDays(-1))  -Format "yyyy-MM-dd"
    $getTime = "T18:09:31Z"
    $combineTime = $getYesterday+$getTime

    $enable_sign_in_risk_policies = $false
    $enable_user_risk_policies = $false

    #Enable Azure AD Identity Protection sign-in risk policies

    $url = "https://graph.microsoft.com/beta/security/secureScores?`$filter=createdDateTime ge $combineTime"
 
    $requestList = Invoke-MgGraphRequest -Uri $url -Method Get
 
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_sign_in_risk_policies -Value $requestList -force

    #maak dump van de output
    $outputObj | ConvertTo-Json -Depth 100 | Out-File -FilePath "F:\HealthChecks\$CustomerID\M365\Audit\$localsecurescorefile"


# 2. Lees dump uit op de specifieke onderdelen

    #search output





    #Ensure multifactor authentication is enabled for all users in administrative roles (AdminMFAV2)

        #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "AdminMFAV2" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_mfa_for_all_admin -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_mfa_for_all_admin -Value $false -force
        }





    #Ensure multifactor authentication is enabled for all users in all roles (MFARegistrationV2)

        #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "MFARegistrationV2" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_mfa_for_all_users -Value $true -force
			$outputObj | Add-Member -MemberType NoteProperty -Name dynamics_mfa_all_users -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_mfa_for_all_users -Value $false -force
			$outputObj | Add-Member -MemberType NoteProperty -Name dynamics_mfa_all_users -Value $false -force
        }




    #Ensure that between two and four global admins are designated (OneAdmin)

        #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "OneAdmin" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name prevent_number_of_admins -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name prevent_number_of_admins -Value $false -force
        }



    #Ensure 'Self service password reset enabled' is set to 'All' (Manual) - (SelfServicePasswordReset)

        #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "SelfServicePasswordReset" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_self_service_password_reset -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_self_service_password_reset -Value $false -force
        }


    #Enable Conditional Access policies to block legacy authentication  (BlockLegacyAuthentication)

        #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "BlockLegacyAuthentication" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_ca_to_block_basic_authentication -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_ca_to_block_basic_authentication -Value $false -force
        }


    #Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (PWAgePolicyNew)

        #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "PWAgePolicyNew" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name ensure_password_do_not_expire -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name ensure_password_do_not_expire -Value $false -force
        }

        
    #Ensure the admin consent workflow is enabled (aad_admin_consent_workflow)

        #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "aad_admin_consent_workflow" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_admin_consent_workflow -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_admin_consent_workflow -Value $false -force
        }


    #Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users (aad_sign_in_freq_session_timeout)

        #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "aad_sign_in_freq_session_timeout" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_sign_in_frequency_browser_sessions -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_sign_in_frequency_browser_sessions -Value $false -force
        }


    #Ensure third party integrated applications are not allowed (aad_third_party_apps)

        #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "aad_third_party_apps" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name disable_third_party_applications -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name disable_third_party_applications -Value $false -force
        }


    #Ensure user consent to apps accessing company data on their behalf is not allowed (IntegratedApps)

        #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "IntegratedApps" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_user_consent_to_app_access -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_user_consent_to_app_access -Value $false -force
        }



    #Ensure SharePoint Online Information Protection policies are set up and used

        #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "mip_autosensitivitylabelspolicies" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_spo_information_protection_policies -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_spo_information_protection_policies -Value $false -force
        }




    #Ensure Microsoft Defender for Cloud Apps is Enabled (mcas_mda_enabled)

        #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "mcas_mda_enabled" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_defender_for_cloud_apps -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_defender_for_cloud_apps -Value $false -force
        }


#Ensure modern authentication for Exchange Online is enabled


        #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "OAuth2ClientProfileEnabled" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_modern_authentication_exo -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_modern_authentication_exo -Value $false -force
        }



  
  
 #Ensure Safe Links for Office Applications is Enabled 
  #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "mdo_safelinksforOfficeApps" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_safe_links_in_office_applications -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_safe_links_in_office_applications -Value $false -force
        }
  
  
  
  #Ensure Safe Links for Office Applications is Enabled 
  #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "mdo_safeattachments" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_safe_attachments -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_safe_attachments -Value $false -force
        }
  
   
  

#Ensure the customer lockbox feature is enabled
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "CustomerLockBoxEnabled" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_customer_lockbox -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_customer_lockbox -Value $false -force
        }

  
  

#Ensure the Common Attachment Types Filter is enabled
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "mdo_commonattachmentsfilter" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_common_attachment_type_filter -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_common_attachment_type_filter -Value $false -force
        }

  

#Ensure all forms of mail forwarding are blocked and/or disabled
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "mdo_blockmailforward" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name block_all_forms_of_email_forwarding -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name block_all_forms_of_email_forwarding -Value $false -force
        }




#Ensure Safe Attachments policy is enabled
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "mdo_safeattachments" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_safe_attachments -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_safe_attachments -Value $false -force
        }



#Ensure that an anti-phishing policy has been created
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "mdo_antiphishingpolicies" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_anti_phishing_policy_all_domains -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_anti_phishing_policy_all_domains -Value $false -force
        }



#Ensure Exchange Online Spam Policies are set to notify administrators 
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "mdo_spam_notifications_only_for_admins" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_exo_spam_policies_notify_admin -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_exo_spam_policies_notify_admin -Value $false -force
        }



#Ensure notifications for internal users sending malware is Enabled 
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "mdo_spam_notifications_only_for_admins" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_notifications_internal_users_malware -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_notifications_internal_users_malware -Value $false -force
        }



#Ensure MailTips are enabled for end users
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "exo_mailtipsenabled" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_mailtips -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_mailtips -Value $false -force
        }



#Ensure Microsoft 365 audit log search is Enabled
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "mip_search_auditlog" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_audit_log_search -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_audit_log_search -Value $false -force
        }

#Ensure 'AuditDisabled' organizationally is set to 'False' - Ensure mailbox auditing for all users is Enabled
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "exo_mailboxaudit" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_mailbox_auditing_all_users -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_mailbox_auditing_all_users -Value $false -force
        }



#Ensure additional storage providers are restricted in Outlook on the web
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "exo_storageproviderrestricted" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name block_external_storage_providers_outlook -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name block_external_storage_providers_outlook -Value $false -force
        }



#Ensure modern authentication for SharePoint applications is required
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "spo_legacy_auth" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_modern_authentication_spo -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_modern_authentication_spo -Value $false -force
        }



#Ensure OneDrive sync is restricted for unmanaged devices
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "spo_block_onedrive_sync_unmanaged_devices" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name block_onedrive_sync_unmanaged_devices -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name block_onedrive_sync_unmanaged_devices -Value $false -force
        }



#Ensure SharePoint external sharing is managed through domain whitelist/blacklists
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "spo_external_sharing_managed" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_document_sharing_whitelist -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_document_sharing_whitelist -Value $false -force
        }



#Ensure Administrative accounts are separate and cloud-only (Manual) - https://admin.microsoft.com/#/users > filter sync status > all should be cloud if role is admin
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "aad_admin_accounts_separate_unassigned_cloud_only" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name ensure_admin_accounts_are_cloud_only -Value $true -force
			$outputObj | Add-Member -MemberType NoteProperty -Name dynamics_admin_cloud_only -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name ensure_admin_accounts_are_cloud_only -Value $false -force
			$outputObj | Add-Member -MemberType NoteProperty -Name dynamics_admin_cloud_only -Value $false -force
        }

 


#Ensure DLP policies are enabled
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "dlp_datalossprevention" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_dlp -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_dlp -Value $false -force
        }




#Ensure DLP policies are enabled for Teams
 #search specific line for the pattern
        $getSpecificLine = Select-String -Pattern "mip_DLP_policies_Teams" -Path $secureScoreDumpFile | Select -ExpandProperty LineNumber

        #get content from line
        $getValue = (Get-Content -Path $secureScoreDumpFile) | where readcount -notin (0..$getSpecificLine)

        #only load fist 11 lines
        $getValueLineTill = $getValue | Select -First 11

        #find mapping on the match
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'


        if ($getRequiredValue -like "*100*") { 
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_dlp_teams -Value $true -force
        }else {
            $outputObj | Add-Member -MemberType NoteProperty -Name enable_dlp_teams -Value $false -force
        }


###







### START AUDIT OTHER ITEMS


Write-Output "Retrieving IdentityRiskDetections and riskyUsers"

$startDate = (Get-Date).AddDays(-100).ToUniversalTime().ToString("s") #todo: get period from automationaccount variable
$startDate = $startDate + "Z"

$enable_sign_in_risk_policies = $false
$enable_user_risk_policies = $false

#Enable Azure AD Identity Protection sign-in risk policies

$url = "https://graph.microsoft.com/beta/identityProtection/riskDetections?`$filter=detectedDateTime gt $startDate&`$top=1"
 
$requestList = Invoke-MgGraphRequest -Uri $url -Method Get
 
ForEach ($request In $requestList.Value) {
    $request
    $enable_sign_in_risk_policies = $request -ne $null
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_sign_in_risk_policies -Value $enable_sign_in_risk_policies -force
}


if($enable_sign_in_risk_policies -eq $true) {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_sign_in_risk_policies -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_sign_in_risk_policies -Value $false -force
}


#Enable Azure AD Identity Protection user risk policies

$url = "https://graph.microsoft.com/beta/identityProtection/riskyUsers?`$filter=riskLastUpdatedDateTime gt $startDate&`$top=1"
 
$requestList = Invoke-MgGraphRequest -Uri $url -Method Get
 
ForEach ($request In $requestList.Value) {
    $request
    $enable_user_risk_policies = $request -ne $null
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_user_risk_policies -Value $enable_user_risk_policies -force
}

if($enable_user_risk_policies -eq $true) {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_user_risk_policies -Value $true -force
}else {
    $outputObj | Add-Member -MemberType NoteProperty -Name enable_user_risk_policies -Value $false -force
}


#Ensure that only organizationally managed/approved public groups exist


$MBX = Get-MgGroup 

# Check if anonymous users are allowed to join meetings
$isAllowed = $MBX.Visibility -like "*Public*"

if ($isAllowed) {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_organizationally_managed_public_groups_exist -Value $false -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_organizationally_managed_public_groups_exist -Value $true -force
}









### Ensure the admin consent workflow is enabled

# Write-Output "Retrieving Admin Consent policy settings"

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
	
	$outputObj | ConvertTo-Json -Depth 100 | Out-File -FilePath "C:\$localfile"

  # $outputObj | export-csv -Path "$workingdir\audit_results\log_cis.csv" -NoTypeInformation

  # $outputObj | Out-File -FilePath "$workingdir\log_cis.txt"
    





### END


#$true | Out-File -FilePath "$workingdir\audit_results\cis_305.txt"
#        Write-Host "Audit passed" 

Write-Host "CIS audit is finished" -fore green







