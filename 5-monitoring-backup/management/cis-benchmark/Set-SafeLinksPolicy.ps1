[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$SPOClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$SPOThumbprint,
    
    [Parameter(Mandatory=$true)]
    [String]$Organization 
)

# Connect to Exchange Online
Connect-ExchangeOnline -CertificateThumbPrint $SPOThumbprint -AppID $SPOClientId -Organization $Organization

# Step 1: Check if the Safe Links policy already exists
Write-Host "Checking if the Safe Links policy 'Baseline Safe Links Policy (Rubicon)' already exists..."
$existingPolicy = Get-SafeLinksPolicy | Where-Object {$_.Name -eq "Baseline Safe Links Policy (Rubicon)"}

if ($existingPolicy) {
    Write-Host "Policy 'Baseline Safe Links Policy (Rubicon)' already exists. Updating the policy..."
    Remove-SafeLinksPolicy -Identity "Baseline Safe Links Policy (Rubicon)"
	New-SafeLinksPolicy -Name "Baseline Safe Links Policy (Rubicon)" -AdminDisplayName "Baseline Safe Links Policy (Rubicon)" -AllowClickThrough $false -CustomNotificationText "This link has been scanned for your safety." -DeliverMessageAfterScan $true -DisableUrlRewrite $false -EnableForInternalSenders $true -EnableOrganizationBranding $true -EnableSafeLinksForEmail $true -EnableSafeLinksForOffice $true -EnableSafeLinksForTeams $true -ScanUrls $true -TrackClicks $true -UseTranslatedNotificationText $false -Confirm:$false  
} else {
    Write-Host "Policy 'Baseline Safe Links Policy (Rubicon)' does not exist. Creating a new policy..."
    New-SafeLinksPolicy -Name "Baseline Safe Links Policy (Rubicon)" -AdminDisplayName "Baseline Safe Links Policy (Rubicon)" -AllowClickThrough $false -CustomNotificationText "This link has been scanned for your safety." -DeliverMessageAfterScan $true -DisableUrlRewrite $false -EnableForInternalSenders $true -EnableOrganizationBranding $true -EnableSafeLinksForEmail $true -EnableSafeLinksForOffice $true -EnableSafeLinksForTeams $true -ScanUrls $true -TrackClicks $true -UseTranslatedNotificationText $false -Confirm:$false
		
	# Wait for 30 seconds to allow policy replication
    Write-Host "Waiting for 30 seconds to ensure policy replication..."
    Start-Sleep -Seconds 30
}

# Step 2: Extract all registered domains in the Microsoft 365 tenant
Write-Host "Extracting all registered domains in the Microsoft 365 tenant..."
$registeredDomains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName
Write-Host "Registered domains extracted: $registeredDomains"

# Step 3: Check if the Safe Links rule already exists
Write-Host "Checking if the Safe Links rule 'Baseline Safe Links Policy (Rubicon)' already exists..."
$existingRule = Get-SafeLinksRule | Where-Object {$_.Name -eq "Baseline Safe Links Policy (Rubicon)"}

if ($existingRule) {
    Write-Host "Rule 'Baseline Safe Links Policy (Rubicon)' already exists. Updating the rule..."
    Remove-SafeLinksRule -Identity "Baseline Safe Links Policy (Rubicon)"
	New-SafeLinksRule -Name "Baseline Safe Links Policy (Rubicon)" -SafeLinksPolicy "Baseline Safe Links Policy (Rubicon)" -Priority 0 -RecipientDomainIs $registeredDomains -Confirm:$false
} else {
    Write-Host "Rule 'Baseline Safe Links Policy (Rubicon)' does not exist. Creating a new rule..."
	New-SafeLinksRule -Name "Baseline Safe Links Policy (Rubicon)" -SafeLinksPolicy "Baseline Safe Links Policy (Rubicon)" -Priority 0 -RecipientDomainIs $registeredDomains -Confirm:$false
}

# Step 4: Verify the policy and rule creation
Write-Host "Verifying Safe Links Policy..."
Get-SafeLinksPolicy | Where-Object {$_.Name -eq "Baseline Safe Links Policy (Rubicon)"}

Write-Host "Verifying Safe Links Rule..."
Get-SafeLinksRule | Where-Object {$_.Name -eq "Baseline Safe Links Policy (Rubicon)"}

# Disconnect from Exchange Online
Disconnect-ExchangeOnline -Confirm:$false

