#To remove all redirect sites, use:
$RedirectSites = Get-PnPTenantSite | Where {$_.Template -in "REDIRECTSITE#0","REDIRECTSITE#1"}
 
ForEach ($Site in $RedirectSites) {
    Write-Host "Deleting redirect site: $($site.Url)"
    Remove-PnPTenantSite -Url $site.Url -Force
}