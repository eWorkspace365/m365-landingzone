**SharePoint Online**

# Connect with Powershell
Connect-PnPOnline -Url "https://eworkspace365.sharepoint.com/" -UseWebLogin
Connect-PnPOnline -url "https://eworkspace365.sharepoint.com/sites/public" -ClientId "dd32vf5cb-5604-34c5-8csd-cerf5bg47k809" -Thumbprint "F5HDF625E7F409FE706999D1380E3340A3E8" -Tenant "e345gn-54e3-8934-2349-cb0e02226b58"

# Remove All Pages from Page Library
$pages = Get-PnPListItem -List "SitePages"  
foreach ($page in $pages) {Remove-PnPListItem -List "SitePages" -Identity $page.Id -Force}   

# Assign Site Template
Invoke-PnPSiteTemplate -Path "C:\Users\Public\Downloads\BrandAtContoso.pnp" -Parameters @{"SiteTitle"="Information Portal";"SiteUrl"="/sites/public"}

# Rename html file to aspx file
Get-ChildItem *.html | Rename-Item -NewName { $_.Name -replace '\.html','.aspx' }

# Reference URLS
https://support.microsoft.com/nl-nl/office/metagegevensnavigatie-voor-een-lijst-of-bibliotheek-instellen-c222a75d-8b18-44e2-9ed8-7ee4e0d23cfc
https://github.com/Barbarur/NovaPointPowerShell/blob/main/Solutions/Report/Preservation%20Hold%20Library%20in%20each%20Site.md


**Defender for Endpoint**
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Disabled

Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\Windows\Microsoft.NET\Framework64\v4.0.30319"
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Disabled

get-mppreference | select-object -expandproperty AttackSurfaceReductionRules_Actions
get-mppreference | select-object -expandproperty AttackSurfaceReductionRules_Ids
get-mppreference | select-object -expandproperty ExclusionExtension
get-mppreference | select-object -expandproperty ExclusionIpAddress
get-mppreference | select-object -expandproperty ExclusionPath
get-mppreference | select-object -expandproperty ExclusionProcess
get-mppreference | select-object -expandproperty AttackSurfaceReductionOnlyExclusions


https://www.techcrafters.com/portal/en/kb/articles/powershell-tutorial-configuring-asr-to-block-processes-from-psexec-and-wmi#Testing_Specific_ASR_Rules
https://gist.github.com/api0cradle/1fdf6bd7fa1a03cd0423feca1ee692eb
https://www.techcrafters.com/portal/en/kb/articles/powershell-tutorial-configuring-asr-to-block-processes-from-psexec-and-wmi#Setting_Rule_Actions
https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test
https://nmmhelp.getnerdio.com/hc/en-us/articles/30697922879501-Attack-Surface-Reduction-AVD-Exclusions



**EntraID**
- https://borncity.com/win/2024/05/13/azure-entra-id-microsoft-confirms-issues-with-single-sign-on-sso/
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks


**Conditional Access**
- https://www.cswrld.com/2024/02/recommended-conditional-access-policies-in-microsoft-entra-id/
- https://learn.microsoft.com/nl-nl/graph/api/conditionalaccesspolicy-delete?view=graph-rest-1.0&tabs=powershell


**Intune**
https://www-intuneirl-com.cdn.ampproject.org/c/s/www.intuneirl.com/implementing-platform-sso-for-macos-a-deep-dive-into-configuration-troubleshooting/amp/
https://www.linkedin.com/pulse/mobile-security-microsoft-intune-configuration-frameworks-peter-chen-kgarc
https://github.com/microsoft/Intune-Config-Frameworks/tree/master/AndroidEnterprise/FullyManaged
https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-windows#enable-with-microsoft-intune
https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-device-registration
https://jonconwayuk.wordpress.com/2023/03/25/intune-force-microsoft-edge-update-to-latest-version-during-windows-autopilot

**Security Hardening**
https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Intune%20Files/Hardening%20Policies/Windows%20Update.json
https://github.com/TheTechBeast8/HardeningAudit/tree/main/CIS%20Win11%20v3.0/Deployment%20Scripts
https://public.cyber.mil/stigs/gpo/
https://www.coreview.com/product-tour
https://blueprint.asd.gov.au/
