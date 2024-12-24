Connect-exchangeonline

$TipsParams = @{
MailTipsAllTipsEnabled = $true
MailTipsExternalRecipientsTipsEnabled = $true
MailTipsGroupMetricsEnabled = $true
MailTipsLargeAudienceThreshold = '25'
}

Set-OrganizationConfig @TipsParams