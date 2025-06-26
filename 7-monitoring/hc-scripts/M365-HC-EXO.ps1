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
    [String]$Organization
)

try {
    . "./GeneralFunctions.ps1"
}
catch {
    Write-Output "Error while loading supporting PowerShell Scripts $error"
    exit
}


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

# set location
$scriptPath = Split-Path -parent $MyInvocation.MyCommand.Definition

#region EXO
if ($null -eq $(Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module ExchangeOnlineManagement 
}

Import-Module ExchangeOnlineManagement

Connect-ExchangeOnline -CertificateThumbPrint $CertificateThumbprint -AppID $AppID -Organization $Organization
Connect-IPPSSession -CertificateThumbPrint $CertificateThumbprint -AppID $AppID  -Organization $Organization

Write-Host "Getting ATP Traffic Report Summary $($sw.Elapsed.Hours.ToString("00")):$($sw.Elapsed.Minutes.ToString("00")):$($sw.Elapsed.Seconds.ToString("00"))" -ForegroundColor DarkGray
$atpTrafficReport = Get-MailFlowStatusReport -StartDate $startDate -EndDate $endDate -Direction Inbound,Outbound -EventType EdgeBlockSpam, EmailMalware, EmailPhish, GoodMail, SpamDetections
SaveObjectToJsonFile -klantnaam $Customer -filename "exchangeonline-traffic.json" -itemToSave $atpTrafficReport

Write-Host "Getting Spam Recipient $($sw.Elapsed.Hours.ToString("00")):$($sw.Elapsed.Minutes.ToString("00")):$($sw.Elapsed.Seconds.ToString("00"))" -ForegroundColor DarkGray
$top10SpamRecipient = Get-MailTrafficSummaryReport -StartDate $startDate -EndDate $endDate -Category TopSpamRecipient | Select-Object @{l='user';e='C1'}, @{l='messagecount';e='C2'}
SaveObjectToJsonFile -klantnaam $Customer -filename "exchangeonline-recipients-spam.json" -itemToSave $top10SpamRecipient

Write-Host "Getting Malware Recipient $($sw.Elapsed.Hours.ToString("00")):$($sw.Elapsed.Minutes.ToString("00")):$($sw.Elapsed.Seconds.ToString("00"))" -ForegroundColor DarkGray
$top10MalwareRecipient = Get-MailTrafficSummaryReport -StartDate $startDate -EndDate $endDate -Category TopMalwareRecipient | Select-Object @{l='user';e='C1'}, @{l='messagecount';e='C2'}
SaveObjectToJsonFile -klantnaam $Customer -filename "exchangeonline-recipients-malware.json" -itemToSave $top10MalwareRecipient

Write-Host "Counting Quarantined Messages for Top Spam Recipients $($sw.Elapsed.Hours.ToString("00")):$($sw.Elapsed.Minutes.ToString("00")):$($sw.Elapsed.Seconds.ToString("00"))" -ForegroundColor DarkGray

# Retrieve quarantined messages within the specified date range
$quarantinedMessages = Get-QuarantineMessage -StartDate $startDate -EndDate $endDate | Select-Object RecipientAddress

# Initialize an array to store the count of quarantined messages for each spam recipient
$spamRecipientQuarantineCount = @()

# Loop through each spam recipient and count their quarantined messages
foreach ($recipient in $top10SpamRecipient) {
    $recipientAddress = $recipient.user
    $quarantineCount = ($quarantinedMessages | Where-Object { $_.RecipientAddress -eq $recipientAddress }).Count
    $spamRecipientQuarantineCount += [PSCustomObject]@{
        User            = $recipientAddress
        SpamMessageCount = $recipient.messagecount
        QuarantineCount = $quarantineCount
    }
}

# Save the spam recipient quarantine count data to a JSON file
SaveObjectToJsonFile -klantnaam $Customer -filename "exchangeonline-spam-quarantine-count.json" -itemToSave $spamRecipientQuarantineCount





#Disconnect-ExchangeOnline
#Remove-Module ExchangeOnlineManagement
#endregion