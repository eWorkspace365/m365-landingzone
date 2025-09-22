[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$Customer,
    
	[Parameter(Mandatory=$false)]
    [String]$TenantID,
	
    [Parameter(Mandatory=$false)]
    [String]$AppID,
    
    [Parameter(Mandatory=$false)]
    [String]$CertificateThumbprint,
    
    [Parameter(Mandatory=$false)]
    [String]$Organization,
    
    [Parameter(Mandatory=$false)]
    [String]$AdminURL,
    
    [Parameter(Mandatory=$false)]
    [String]$TenantURL
)

try {
    . "./GeneralFunctions.ps1"
}
catch {
    Write-Output "Error while loading supporting PowerShell Scripts $error"
    exit
}

# Connections
Connect-PnPOnline -Url $AdminUrl -ClientId $AppID -Thumbprint $CertificateThumbPrint -Tenant $Organization
Connect-ExchangeOnline -CertificateThumbPrint $CertificateThumbPrint -AppID $AppID -Organization $Organization
Connect-IPPSSession -CertificateThumbprint $CertificateThumbprint -AppID $AppID -Organization $Organization
$version = $host | Select-Object Version
If ($version.Version.Major -gt 1) { $host.Runspace.ThreadOptions = "ReuseThread" }
$timeStart = get-date -f "dd MMMM yyyy HH:mm:ss"
$sw = [Diagnostics.Stopwatch]::StartNew()
$timeStart

Import-Module AzureAD 
Import-Module ExchangeOnlineManagement 
if ($null -eq $(Get-Module -ListAvailable -Name ImportExcel)) {
    Install-Module ImportExcel 
}

Import-Module ImportExcel 

[datetime]$today = Get-Date -Hour 0 -Minute 0 -Second 0
$monthAgo = $today.AddMonths(-1)
$startDate = Get-Date $monthAgo -Day 1
$endDate = Get-Date $startDate.AddMonths(1).AddSeconds(-1)
$hcPeriod = $(Get-Date $startDate -Format "yyyyMM")

$xls_spo = "$($pSScriptRoot)\$($customer)-SPO.json"



#region functions
Function ReturnO365GroupOwners([String]$siteURL) {
    # Function to return the owners of an Office 365 Group identified by the group GUID
    $owners = $null; $deletedGroup = $False; $i = 0; $siteOwners = $null
    # Get the site properties. We need a separate call here because Get-SPOSite doesn't return all properties when it fetches a set of sites
    $groupId = (Get-PnPTenantSite -Identity $siteURL) 
    If ($groupId.Template -eq "TEAMCHANNEL#0") {
        # If Teams private channel, we use the Related Group Id
        $groupId = $groupId | Select-Object -ExpandProperty RelatedGroupId 
    }
    Else {
        # And for all other group-enabled sites, we use the GroupId
        $groupid = $groupId | Select-Object -ExpandProperty GroupId 
    }
    
    If ($groupId.Guid -eq "00000000-0000-0000-0000-000000000000") {
        # Null group id stored in site
        $siteOwners = "Deleted group"; $deletedGroup = $true 
    }
    If ($deletedGroup -eq $False) {      
        Try { 
            $owners = (Get-UnifiedGroupLinks -Identity $groupId.Guid -LinkType Owners -ErrorAction SilentlyContinue) 
        }
        Catch 
        { $siteOwners = "Possibly deleted Office 365 Group"; $deletedGroup = $true }
    }
    
    If ($null -eq $owners) {
        # Got nothing back, maybe because of an error
        $siteOwners = "Possibly deleted Office 365 Group"
    }
    Else {
        # We have some owners, now format them
        $owners = $owners | Select-Object -ExpandProperty DisplayName
        ForEach ($owner in $owners) {
            If ($i -eq 0) 
            { $siteOwners = $owner; $i = 1 } 
            Else { $siteOwners = $siteOwners + "; " + $owner }
        }
    }
    
    Return $siteOwners 
}

###########################
# Region Sensitivity labels
###########################

$sensitiveLabels = Get-Label | Select DisplayName, Guid 
SaveObjectToJsonFile -klantnaam $Customer -filename "sharepointonline-sensitivity-labels.json" -itemToSave $sensitiveLabels



# Retrieve sensitivity label, sharing capability, title, and conditional access policy information for each site and export to JSON
$siteCollections = Get-PnPTenantSite

$siteInfoArray = @()

foreach ($site in $siteCollections) {
    $siteUrl = $site.Url

    # Skip sites that contain '-my.sharepoint.com'
    if ($siteUrl -like "*-my.sharepoint.com*") {
        continue
    }

    $siteDetails = Get-PnPTenantSite -Url $siteUrl | Select-Object Title, SensitivityLabel, SharingCapability

    $siteInfo = @{
        Title = $siteDetails.Title
        SiteUrl = $siteUrl
        SensitivityLabel = $siteDetails.SensitivityLabel
        SharingCapability = $siteDetails.SharingCapability
    }
    $siteInfoArray += $siteInfo
}
SaveObjectToJsonFile -klantnaam $Customer -filename "sharepointonline-sites-labels.json" -itemToSave $siteInfoArray





################################################
# Region SharePoint Online External Users Report
################################################

$DateTime = "_{0:MM_dd_yy}_{0:HH_mm_ss}" -f (Get-Date)
$BasePath = "F:\HealthChecks\$Customer\M365\Audit"
$CSVPath = $BasePath + "\sharepointonline-sites-externalusers" + $DateTime + ".csv"
$global:ExternalUsersData = @() 
Function LoginToAdminSite() {
    [cmdletbinding()]
    param([parameter(Mandatory = $true, ValueFromPipeline = $true)] $Credentials)
    Write-Host "Connecting to Tenant Admin Site '$($AdminURL)'..." -ForegroundColor Yellow
    Connect-PnPOnline -Url $AdminUrl -ClientId $AppID -Thumbprint $CertificateThumbPrint -Tenant $Organization
    Write-Host "Connection Successfull to Tenant Admin Site :'$($AdminURL)'" -ForegroundColor Green
}
Function ConnectToSPSite() {
    try {
        $SiteCollection = Get-PnPTenantSite -Filter "Url -like '$TenantURL'" | Where { $_.SharingCapability -ne "Disabled" }
        foreach ($Site in $SiteCollection) {
            $SiteUrl = $Site.Url    
            Write-Host "Connecting to Site :'$($SiteUrl)'..." -ForegroundColor Yellow  
            Connect-PnPOnline -Url $SiteUrl -ClientId $AppID -Thumbprint $CertificateThumbPrint -Tenant $Organization
            Write-Host "Connection Successfull to site: '$($SiteUrl)'" -ForegroundColor Green              
            GetExternalUsers($SiteUrl)                        
        }
        ExportData       
    }
    catch {
        Write-Host "Error in connecting to Site:'$($SiteUrl)'" $_.Exception.Message -ForegroundColor Red               
    } 
}
Function GetExternalUsers($siteUrl) {
    try {
        $ExternalUsers = Get-PnPUser | Where { $_.LoginName -like "*#ext#*" -or $_.LoginName -like "*urn:spo:guest*" }   
        Write-host "Found '$($ExternalUsers.count)' External users" -ForegroundColor Gray
        ForEach ($User in $ExternalUsers) {
            $global:ExternalUsersData += New-Object PSObject -Property ([ordered]@{
                    SiteName  = $site.Title
                    SiteURL   = $SiteUrl
                    UserName  = $User.Title
                    Email     = $User.Email
                    LoginName = $User.LoginName
                })
        }          
    }
    catch {
        Write-Host "Error in getting external users :'$($siteUrl)'" $_.Exception.Message -ForegroundColor Red                 
    }        
}

Function ExportData {
    Write-Host "Exporting to CSV" -ForegroundColor Yellow           
    $global:ExternalUsersData | Export-Csv -Path $CSVPath -NoTypeInformation -Append
    Write-Host "Exported Successfully!" -ForegroundColor Green 
}

Function StartProcessing {   
    LoginToAdminSite($AdminURL) 
    ConnectToSPSite
}

StartProcessing

$sitesExternalUsers = Get-Content -path $CSVPath | ConvertFrom-Csv -Delimiter ',' 
SaveObjectToJsonFile -klantnaam $Customer -filename "sharepointonline-sites-externalusers.json" -itemToSave $sitesExternalUsers
# End Region


#################################################################
# Region SharePoint Online File Sharing Activity for past 90 days
#################################################################
$version = $host | Select-Object Version
If($version.Version.Major -gt 1) {$host.Runspace.ThreadOptions = "ReuseThread"}
$timeStart = get-date -f "dd MMMM yyyy HH:mm:ss"
$sw = [Diagnostics.Stopwatch]::StartNew()
$timeStart

# variables
[datetime]$today = Get-Date -Hour 0 -Minute 0 -Second 0
$monthAgo = $today.AddMonths(-1)
$startDate = Get-Date $monthAgo -Day 1
$endDate = Get-Date $startDate.AddMonths(1).AddSeconds(-1)
$hcPeriod = $(Get-Date $startDate -Format "yyyyMM")

$MaxStartDate=((Get-Date).AddDays(-89)).Date

if(($StartDate -eq $null) -and ($EndDate -eq $null))
{
 $EndDate=(Get-Date).Date
 $StartDate=$MaxStartDate
}
$startDate
#Getting start date to generate external sharing report
While($true)
{
 if ($StartDate -eq $null)
 {
  $StartDate=Read-Host Enter start time for report generation '(Eg:04/28/2021)'
 }
 Try
 {
  $Date=[DateTime]$StartDate
  if($Date -ge $MaxStartDate)
  { 
   break
  }
  else
  {
   Write-Host `nExternal sharing report can be retrieved only for past 90 days. Please select a date after $MaxStartDate -ForegroundColor Red
   return
  }
 }
 Catch
 {
  Write-Host `nNot a valid date -ForegroundColor Red
 }
}


#Getting end date to generate external sharing report
While($true)
{
 if ($EndDate -eq $null)
 {
  $EndDate=Read-Host Enter End time for report generation '(Eg: 04/28/2021)'
 }
 Try
 {
  $Date=[DateTime]$EndDate
  if($EndDate -lt ($StartDate))
  {
   Write-Host End time should be later than start time -ForegroundColor Red
   return
  }
  break
 }
 Catch
 {
  Write-Host `nNot a valid date -ForegroundColor Red
 }
}

$OutputCSV="F:\HealthChecks\$Customer\M365\Audit\exchangeonline-sharingreport_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).csv" 
$IntervalTimeInMinutes=1440    #$IntervalTimeInMinutes=Read-Host Enter interval time period '(in minutes)'
$CurrentStart=$StartDate
$CurrentEnd=$CurrentStart.AddMinutes($IntervalTimeInMinutes)

#Check whether CurrentEnd exceeds EndDate
if($CurrentEnd -gt $EndDate)
{
 $CurrentEnd=$EndDate
}

if($CurrentStart -eq $CurrentEnd)
{
 Write-Host Start and end time are same.Please enter different time range -ForegroundColor Red
 Exit
}


$AggregateResults = @()
$CurrentResult= @()
$CurrentResultCount=0
$AggregateResultCount=0
Write-Host `nRetrieving external sharing events from $StartDate to $EndDate...
$ProcessedAuditCount=0
$OutputEvents=0
$ExportResult=""   
$ExportResults=@()  

while($true)
{ 
 #Getting exteranl sharing audit data for given time range
 $Results=Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -Operations "Sharinginvitationcreated,AnonymousLinkcreated,AddedToSecureLink" -SessionId s -SessionCommand ReturnLargeSet -ResultSize 5000
 $ResultCount=($Results | Measure-Object).count
 foreach($Result in $Results)
 {
  $ProcessedAuditCount++
  $MoreInfo=$Result.auditdata
  $Operation=$Result.Operations
  $AuditData=$Result.auditdata | ConvertFrom-Json
  $Workload=$AuditData.Workload

  #Filter for SharePointOnline external Sharing events
  If($SharePointOnline.IsPresent -and ($Workload -eq "OneDrive"))
  {
   continue
  }

  If($OneDrive.IsPresent -and ($Workload -eq "SharePoint"))
  {
   continue
  }
  
  #Check for Guest sharing
  if($Operation -ne "AnonymousLinkcreated")
  {
   If($AuditData.TargetUserOrGroupType -ne "Guest")
   {
    continue
   }
   $SharedWith=$AuditData.TargetUserOrGroupName
  }
  else
  {
   $SharedWith="Anyone with the link can access"
  }

  $ActivityTime=Get-Date($AuditData.CreationTime) -format g
  $SharedBy=$AuditData.userId
  $SharedResourceType=$AuditData.ItemType
  $sharedResource=$AuditData.ObjectId
  $SiteURL=$AuditData.SiteURL
  

  #Export result to csv
  $OutputEvents++
  $ExportResult=@{'Shared Time'=$ActivityTime;'Sharing Type'=$Operation;'Shared By'=$SharedBy;'Shared With'=$SharedWith;'Shared Resource Type'=$SharedResourceType;'Shared Resource'=$SharedResource;'Site url'=$Siteurl;'Workload'=$Workload}
  $ExportResults= New-Object PSObject -Property $ExportResult  
  $ExportResults | Select-Object 'Shared Time','Shared By','Shared With','Shared Resource Type','Shared Resource','Site URL','Sharing Type','Workload' | Export-Csv -Path $OutputCSV -Notype -Append 
 }
 Write-Progress -Activity "`n     Retrieving external sharing events from $CurrentStart to $CurrentEnd.."`n" Processed audit record count: $ProcessedAuditCount"
 $currentResultCount=$CurrentResultCount+$ResultCount
 if($CurrentResultCount -ge 50000)
 {
  Write-Host Retrieved max record for current range.Proceeding further may cause data loss or rerun the script with reduced time interval. -ForegroundColor Red
  $Confirm=Read-Host `nAre you sure you want to continue? [Y] Yes [N] No
  if($Confirm -match "[Y]")
  {
   Write-Host Proceeding audit log collection with data loss
   [DateTime]$CurrentStart=$CurrentEnd
   [DateTime]$CurrentEnd=$CurrentStart.AddMinutes($IntervalTimeInMinutes)
   $CurrentResultCount=0
   $CurrentResult = @()
   if($CurrentEnd -gt $EndDate)
   {
    $CurrentEnd=$EndDate
   }
  }
  else
  {
   Write-Host Please rerun the script with reduced time interval -ForegroundColor Red
   Exit
  }
 }

 
 if($Results.count -lt 5000)
 {
  #$AggregateResultCount +=$CurrentResultCount
  if($CurrentEnd -eq $EndDate)
  {
   break
  }
  $CurrentStart=$CurrentEnd 
  if($CurrentStart -gt (Get-Date))
  {
   break
  }
  $CurrentEnd=$CurrentStart.AddMinutes($IntervalTimeInMinutes)
  $CurrentResultCount=0
  $CurrentResult = @()
  if($CurrentEnd -gt $EndDate)
  {
   $CurrentEnd=$EndDate
  }
  }
}


$sitesSharingactivity = Get-Content -path $OutputCSV | ConvertFrom-Csv -Delimiter ',' 
SaveObjectToJsonFile -klantnaam $Customer -filename "sharepointonline-sites-sharingactivity.json" -itemToSave $sitesSharingactivity
# End region



########################
# Region Site Usage Data
########################

$SiteStorageData = @()
 
ForEach($Site in (Get-PnPTenantSite))
{
    $SiteStorageData += New-Object PSObject -Property ([ordered]@{
        Title  = $Site.Title
        URL = $Site.URL
        Allocated = $Site.StorageQuota
        Used = $Site.StorageUsageCurrent
        Percentage = [math]::Round( ($Site.StorageUsageCurrent/$Site.StorageQuota*100),2)
    })
}
 
#Filter Sites with usage percentage exceeding given threshold
#$SitesExceeding = $SiteStorageData | Where {$_.Percentage -eq $PercentageThreshold}
$SitesExceeding = $SiteStorageData | Where {$_.Percentage -gt $PercentageThreshold}
 
If($SitesExceeding -ne $Null) {
    #[string]$EmailBody = $SitesExceeding | ConvertTo-Html -Title "Storage Report" -Head $CSSStyle -PreContent "Sites Storage Report"
 
    # Site Quota ophalen
    $StorageQuota = (Get-PnPTenant).StorageQuota
 
    # Gebruikte opslag van alle sites optellen
    $StorageUsed = Get-PnPTenantSite | Measure-Object -Property StorageUsageCurrent -Sum | Select-Object -ExpandProperty Sum
 
    # Percentage berekenen
    $TotalPercentage = [math]::Round(($StorageUsed / $StorageQuota * 100), 2)


#Simple JSON
[hashtable]$body = @{}
$Body.StorageQuota = $StorageQuota
$Body.StorageUsed = $StorageUsed
$Body.TotalPercentage = $TotalPercentage


SaveObjectToJsonFile -klantnaam $Customer -filename "sharepointonline-storage.json" -itemToSave $body
}

# End Region
