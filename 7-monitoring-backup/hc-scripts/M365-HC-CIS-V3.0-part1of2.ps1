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
    [String]$ApplicationID,
    
    [Parameter(Mandatory=$true)]
    [String]$CertificateThumbprint,
    
    [Parameter(Mandatory=$true)]
    [String]$Organization,
    
    [Parameter(Mandatory=$true)]
    [String]$AdminURL

)

Import-Module MSAL.PS
Import-Module ExchangeOnlineManagement -RequiredVersion 3.5.0

$Global:MsalToken=$null

Set-StrictMode -version Latest
$ErrorActionPreference = "stop"

# Bepaal of we SPO in de scan uitvoeren of niet (true = ja / false = nee)
$checkSPO = $true

# Check if debugging
$Debug=$false
if ($Debug){
    . .\debug_settings.ps1
}else{
    $basePath="C:\Program Files\Rubicon"
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

$outputObj = New-Object -TypeName psobject
$outputObj | Add-Member -MemberType NoteProperty -Name version -Value $scriptVersion
$outputObj | Add-Member -MemberType NoteProperty -Name timestamp -Value $timestamp
$outputObj | Add-Member -MemberType NoteProperty -Name customerId -Value $customerId
#
#_____________________________________________________________________________________________
#
 
###INTUNE CONTROLES
# Controleer of Intune is ingericht conform de best practices: ga naar intune.microsoft.com. 
# Controleer nu het volgende (alles moet correct zijn) met de baseline scripts
####Compliance policies ingericht	
# Ensure Compliance policy is set for Windows
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
 ### LET OP: ZOEK VERDER OP (MET-HAND-VULLEN) VOOR DE OVERIGE ONDERDELEN 
 ### DIE MET DE HAND MOETEN VOORDAT COMPLETE CODE WORDT AFGETRAPT
#_____________________________________________________________________________________________
 
###ENKELE HANDMATIGE CONTROLES - LET OP BEPAALDE WAARDES MET DE HAND AANPASSEN IN DE OUTPUT!

# MvdS: start with exchange because running it at the end makes auth troublesome

#region Exchange
##################################
# CONNECT TO EXCHANGE ONLINE
# Connect-ExchangeOnline
Connect-ExchangeOnline -CertificateThumbPrint $CertificateThumbprint -AppID $ApplicationID -Organization $Organization -ErrorAction Continue


$ReportSubmissionPolicy = Get-ReportSubmissionPolicy

if ($null -eq $ReportSubmissionPolicy) {
    $isAllowedA = $ReportSubmissionPolicy.ReportJunkToCustomizedAddress -like "*True*"
    $isAllowedB = $ReportSubmissionPolicy.ReportNotJunkToCustomizedAddress -like "*True*"
    $isAllowedC = $ReportSubmissionPolicy.ReportPhishToCustomizedAddress -like "*True*"
    $isAllowedD = $ReportSubmissionPolicy.ReportChatMessageEnabled -like "*False*"
    $isAllowedE = $ReportSubmissionPolicy.ReportChatMessageToCustomizedAddressEnabled -like "*True*"
    <#
    #never checked anywhere....
    $isAllowedF = $MBXDefender.ReportJunkAddresses -like "*@*"
    $isAllowedG = $MBXDefender.ReportNotJunkAddresses -like "*@*"
    $isAllowedH = $MBXDefender.ReportNotJunkAddresses -like "*@*"
    #>
} else {
    Write-Host "Geen waarde"
}

if ($isAllowed -and $isAllowedA -and $isAllowedB -and $isAllowedC -and $isAllowedD -and $isAllowedE) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_users_can_report_sec -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_users_can_report_sec -Value $false -force
}

$ReportSubmissionPolicy = Get-ReportSubmissionPolicy

if ($null -eq $ReportSubmissionPolicy) {
    $isAllowedA = $ReportSubmissionPolicy.ReportJunkToCustomizedAddress -like "*True*"
    $isAllowedB = $ReportSubmissionPolicy.ReportNotJunkToCustomizedAddress -like "*True*"
    $isAllowedC = $ReportSubmissionPolicy.ReportPhishToCustomizedAddress -like "*True*"
    $isAllowedD = $ReportSubmissionPolicy.ReportChatMessageEnabled -like "*False*"
    $isAllowedE = $ReportSubmissionPolicy.ReportChatMessageToCustomizedAddressEnabled -like "*True*"
    <#
    #never checked anywhere....
    $isAllowedF = $MBXDefender.ReportJunkAddresses -like "*@*"
    $isAllowedG = $MBXDefender.ReportNotJunkAddresses -like "*@*"
    $isAllowedH = $MBXDefender.ReportNotJunkAddresses -like "*@*"
    #>
} else {
    Write-Host "Geen waarde"
}

if ($isAllowed -and $isAllowedA -and $isAllowedB -and $isAllowedC -and $isAllowedD -and $isAllowedE) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_users_can_report_sec -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_users_can_report_sec -Value $false -force
}

#Ensure users installing Outlook add-ins is not allowed - https://admin.exchange.microsoft.com/#/userroles - Default Role - Manage Permissions - My Custom Apps, My Marketplace AND My ReadWriteMailboxApps moeten UNCHECKED zijn
#RoleManagementPolicy.Read.Directory
$RoleAssignmentPolicy = Get-EXOMailbox | Select-Object -Unique RoleAssignmentPolicy | 
ForEach-Object { 
     Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | 
     Where-Object {$_.AssignedRoles -like "*Apps*"}
    } | Select-Object Identity, @{Name="AssignedRoles"; Expression=
    {
       Get-Mailbox | Select-Object -Unique RoleAssignmentPolicy | 
       ForEach-Object { 
       Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | 
       Select-Object -ExpandProperty AssignedRoles | 
       Where-Object {$_ -like "*Apps*"}
     }
  }
}

$isAllowed = $null -eq $RoleAssignmentPolicy

if ($isAllowed) {
   $outputObj | Add-Member -MemberType NoteProperty -Name disable_outlook_add_in_install -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name disable_outlook_add_in_install -Value $false -force
}

##################################
# Ensure 'External sharing' of calendars is not available (Automated)
$SharingPolicy = Get-SharingPolicy 

# Check if anonymous users are allowed to join meetings
$isAllowed = $SharingPolicy.Domains -like "*CalendarSharing*"

if ($isAllowed) {
   $outputObj | Add-Member -MemberType NoteProperty -Name external_calendar_sharing_not_available -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name external_calendar_sharing_not_available -Value $false -force
}

##################################
#Ensure mailbox auditing for E3 users is Enabled (Automated) - AuditEnabled voor alles TRUE zijn (zie logs)
#EN
#Ensure mailbox auditing for E5 users is Enabled (Automated) - AuditEnabled voor alles TRUE zijn (zie logs)
$MailAudit = Get-EXOMailbox -PropertySets Audit -ResultSize Unlimited |  Select-Object UserPrincipalName, AuditEnabled, AuditAdmin, AuditDelegate, AuditOwner

# Export the MailAudit object to the C:\Temp\AuditSettings.txt file in TXT format
$MailAudit | Export-Csv -Path "$outputPath\AuditSettings.txt" -NoTypeInformation -Encoding UTF8

# Export the MailAudit object to the C:\Temp\AuditSettings.json file in JSON format
$MailAudit | ConvertTo-Json | Out-File -FilePath "$outputPath\AuditSettings.json" -Encoding UTF8

##########################################################################################

#VUL HIER DE JUISTE WAARDE MET DE HAND IN (MET-HAND-VULLEN)
$outputObj | Add-Member -MemberType NoteProperty -Name ensure_mailbox_audit_e3_enabled -Value $false -force
$outputObj | Add-Member -MemberType NoteProperty -Name ensure_mailbox_audit_e5_enabled -Value $false -force

##########################################################################################

# Ensure 'AuditBypassEnabled' is not enabled on mailboxes (Manual) - Uitkomst moet zijn dat er geen resultaten zijn
$outputObj | Add-Member -MemberType NoteProperty -Name ensure_auditbypass_not_enabled -Value $true -force

# Haal alle mailboxen op die mailbox-auditlogboekregistratie kunnen omzeilen
$MailboxAuditBypassAss = Get-MailboxAuditBypassAssociation -ResultSize unlimited | Where-Object {$_.AuditBypassEnabled -eq $true}

# Controleer of er mailboxen zijn met AuditBypassEnabled ingesteld op $true
if ($MailboxAuditBypassAss | Where-Object {$_.AuditBypassEnabled -eq $true}) {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_auditbypass_not_enabled -Value $false -force
} else { # Anders, voeg dan de eigenschap ensure_mail_transport_rules_not_whitelist toe aan $outputObj en stel deze in op $true
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_auditbypass_not_enabled -Value $true -force
}

# Ensure email from external senders is identified (Automated)
$outputObj | Add-Member -MemberType NoteProperty -Name ensure_external_sender_identified_enabled -Value $true -force

# Haal alle mailboxen op die mailbox-auditlogboekregistratie kunnen omzeilen
$ExternalInOutlook = Get-ExternalInOutlook | Where-Object {$_.Enabled -eq $False}

# Controleer of zaken zijn die $true zijn
if ($ExternalInOutlook | Where-Object {$_.Enabled -eq $true}) {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_external_sender_identified_enabled -Value $true -force
} else {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_external_sender_identified_enabled -Value $false -force
}

#Ensure sign-in to shared mailboxes is blocked
$EXOMailboxSharedDetails = Get-EXOMailbox -RecipientTypeDetails SharedMailbox
$EXOMailboxSharedDetails | ForEach-Object {Get-AzureADUser -ObjectId $_.ExternalDirectoryObjectId} | Format-Table DisplayName,UserPrincipalName,AccountEnabled
#Expected result: Ensure AccountEnabled is set to False for all Shared Mailboxes. If not false the check failed
$EXOMailboxSharedDetails=$EXOMailboxSharedDetails | Where-Object {$_.AccountEnabled -eq $true}

# Controleer of zaken zijn die $true zijn
if ($null -eq $EXOMailboxSharedDetails) {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_sign_in_shared_mailbox_blocked -Value $true -force
} else {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_sign_in_shared_mailbox_blocked -Value $false -force
}

#Ensure mail transport rules do not whitelist specific domains (Automated)
$getRequiredValue = Get-TransportRule | Where-Object {($_.setscl -eq -1 -and $_.SenderDomainIs -ne $null)} | Format-Table Name,SenderDomainIs
if ($null -eq $getRequiredValue) { 
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_mail_transport_rules_not_whitelist -Value $true -force
} else {
    $outputObj | Add-Member -MemberType NoteProperty -Name ensure_mail_transport_rules_not_whitelist -Value $false -force
}

###################################################################
# Ensure that SPF records are published for all Exchange Domains (Manual)
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
#endregion

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

$ReportSubmissionPolicy = Get-ReportSubmissionPolicy

if ($null -eq $ReportSubmissionPolicy) {
    if ($null -eq $ReportSubmissionPolicy.ReportJunkToCustomizedAddress)
    { 
        $isAllowedA=$false
    } else {
        $isAllowedA = $ReportSubmissionPolicy.ReportJunkToCustomizedAddress -like "*True*"
    }
    
    $isAllowedB = $ReportSubmissionPolicy.ReportNotJunkToCustomizedAddress -like "*True*"
    $isAllowedC = $ReportSubmissionPolicy.ReportPhishToCustomizedAddress -like "*True*"
    $isAllowedD = $ReportSubmissionPolicy.ReportChatMessageEnabled -like "*False*"
    $isAllowedE = $ReportSubmissionPolicy.ReportChatMessageToCustomizedAddressEnabled -like "*True*"
    <#
    #never checked anywhere....
    $isAllowedF = $MBXDefender.ReportJunkAddresses -like "*@*"
    $isAllowedG = $MBXDefender.ReportNotJunkAddresses -like "*@*"
    $isAllowedH = $MBXDefender.ReportNotJunkAddresses -like "*@*"
    #>
} else {
    Write-Host "Geen waarde"
}

if ($isAllowed -and $isAllowedA -and $isAllowedB -and $isAllowedC -and $isAllowedD -and $isAllowedE) {
     $outputObj | Add-Member -MemberType NoteProperty -Name ensure_users_can_report_sec -Value $true -force
} else {
   $outputObj | Add-Member -MemberType NoteProperty -Name ensure_users_can_report_sec -Value $false -force
}

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

################################
### CREATE DUMP FILE

Write-Output "Creating local file"
	
$outputObj | ConvertTo-Json -Depth 100 | Out-File -FilePath "C:\Temp\HealthChecks\$CustomerID\Microsoft 365\$localfile"

Write-Host "CIS audit 1 of 2 is finished..." -fore green
