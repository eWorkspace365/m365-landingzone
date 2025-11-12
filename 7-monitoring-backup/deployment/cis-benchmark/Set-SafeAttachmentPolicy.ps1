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
Write-Host "Checking if the Safe Links policy 'Baseline Safe Attachments Policy (Rubicon)' already exists..."
$existingPolicy = Get-SafeAttachmentPolicy | Where-Object {$_.Name -eq "Baseline Safe Attachments Policy (Rubicon)"}

if ($existingPolicy) {
    Write-Host "Policy 'Baseline Safe Attachments Policy (Rubicon)' already exists. Updating the policy..."
    Remove-SafeAttachmentPolicy -Identity "Baseline Safe Attachments Policy (Rubicon)"
	New-SafeAttachmentPolicy -Name "Baseline Safe Attachments Policy (Rubicon)" -Action Block -AdminDisplayName "Baseline Safe Attachments Policy (Rubicon)" -Enable $true -QuarantineTag "AdminOnlyAccessPolicy" -Redirect $false
} else {
    Write-Host "Policy 'Baseline Safe Attachments Policy (Rubicon)' does not exist. Creating a new policy..."
    New-SafeAttachmentPolicy -Name "Baseline Safe Attachments Policy (Rubicon)" -Action Block -AdminDisplayName "Baseline Safe Attachments Policy (Rubicon)" -Enable $true -QuarantineTag "AdminOnlyAccessPolicy" -Redirect $false
	
	# Wait for 30 seconds to allow policy replication
    Write-Host "Waiting for 30 seconds to ensure policy replication..."
    Start-Sleep -Seconds 30
}

# Step 2: Extract all registered domains in the Microsoft 365 tenant
Write-Host "Extracting all registered domains in the Microsoft 365 tenant..."
$registeredDomains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName
Write-Host "Registered domains extracted: $registeredDomains"

# Step 3: Check if the Safe Links rule already exists
Write-Host "Checking if the Safe Links rule 'Baseline Safe Attachments Policy (Rubicon)' already exists..."
$existingRule = Get-SafeAttachmentRule | Where-Object {$_.Name -eq "Baseline Safe Attachments Policy (Rubicon)"}

if ($existingRule) {
    Write-Host "Rule 'Baseline Safe Attachments Policy (Rubicon)' already exists. Updating the rule..."
    Remove-SafeAttachmentRule -Identity "Baseline Safe Attachments Policy (Rubicon)"
	New-SafeAttachmentRule -Name "Baseline Safe Attachments Policy (Rubicon)" -SafeAttachmentPolicy "Baseline Safe Attachments Policy (Rubicon)" -RecipientDomainIs $registeredDomains -Priority 0
} else {
    Write-Host "Rule 'Baseline Safe Attachments Policy (Rubicon)' does not exist. Creating a new rule..."
	New-SafeAttachmentRule -Name "Baseline Safe Attachments Policy (Rubicon)" -SafeAttachmentPolicy "Baseline Safe Attachments Policy (Rubicon)" -RecipientDomainIs $registeredDomains -Priority 0
}

# Step 4: Verify the policy and rule creation
Write-Host "Verifying Safe Attachments Policy..."
Get-SafeAttachmentPolicy | Where-Object {$_.Name -eq "Baseline Safe Attachments Policy (Rubicon)"}

Write-Host "Verifying Safe Attachments Rule..."
Get-SafeAttachmentRule | Where-Object {$_.Name -eq "Baseline Safe Attachments Policy (Rubicon)"}

# Disconnect from Exchange Online
Disconnect-ExchangeOnline -Confirm:$false

