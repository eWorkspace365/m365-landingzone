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

# Step 1: Create the Hosted Outbound Spam Filter Policy
New-HostedOutboundSpamFilterPolicy -Name "Baseline Outbound Anti-Spam Policy (Rubicon)" `
    -ActionWhenThresholdReached RestrictUser `
    -AdminDisplayName "Baseline Outbound Anti-Spam Policy (Rubicon)" `
    -AutoForwardingMode Automatic `
    -BccSuspiciousOutboundMail $false `
    -NotifyOutboundSpam $true `
    -RecipientLimitExternalPerHour 500 `
    -RecipientLimitInternalPerHour 1000 `
    -RecipientLimitPerDay 1000

# Step 2: Create a rule to assign the policy to the rubicon.nl domain
New-HostedOutboundSpamFilterRule -Name "Baseline Outbound Anti-Spam Rule (Rubicon)" `
    -HostedOutboundSpamFilterPolicy "Baseline Outbound Anti-Spam Policy (Rubicon)" `
    -RecipientDomainIs "rubicon.nl" `
    -Priority 0

# Step 3: Verify the policy and rule creation
Write-Host "Policy and rule created successfully. Verifying configuration..."
Get-HostedOutboundSpamFilterPolicy -Identity "Baseline Outbound Anti-Spam Policy (Rubicon)"
Get-HostedOutboundSpamFilterRule -Name "Baseline Outbound Anti-Spam Rule (Rubicon)"

# Disconnect from Exchange Online
Disconnect-ExchangeOnline
