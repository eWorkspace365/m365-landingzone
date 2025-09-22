$SourceSite = "https://klieka.sharepoint.com/sites/Public"

# Create a site design from an existing site (TeamSite or CommunicationSite)
Add-PnPSiteDesignFromWeb `
  -Url $SourceSite `
  -Title "Contoso – Project Site" `
  -Description "Standard project site (nav, theme, lists)" `
  -WebTemplate CommunicationSite `
  -IncludeAll `

$schema = Get-PnPSiteScriptFromWeb -Url $SourceSite -IncludeAll
$script = Add-PnPSiteScript -Title "Project Site – v2" -Content $schema
Add-PnPSiteDesign -Title "Contoso – Project Site v2" -SiteScriptIds $script.Id -WebTemplate CommunicationSite 

