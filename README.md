**SharePoint Online**

# Connect with Powershell
- `Connect-PnPOnline -Url "https://eworkspace365.sharepoint.com/" -UseWebLogin`
- `Connect-PnPOnline -url "https://eworkspace365.sharepoint.com/sites/public" -ClientId "dd32vf5cb-5604-34c5-8csd-cerf5bg47k809" -Thumbprint "F5HDF625E7F409FE706999D1380E3340A3E8" -Tenant "e345gn-54e3-8934-2349-cb0e02226b58"`

# Remove All Pages from Page Library
`$pages = Get-PnPListItem -List "SitePages"  
foreach ($page in $pages) {Remove-PnPListItem -List "SitePages" -Identity $page.Id -Force}`

# Assign Site Template
`Invoke-PnPSiteTemplate -Path "C:\Users\Public\Downloads\BrandAtContoso.pnp" -Parameters @{"SiteTitle"="Information Portal";"SiteUrl"="/sites/public"}`

# Rename html file to aspx file
`Get-ChildItem *.html | Rename-Item -NewName { $_.Name -replace '\.html','.aspx' }`

# Reference URLS
- https://support.microsoft.com/nl-nl/office/metagegevensnavigatie-voor-een-lijst-of-bibliotheek-instellen-c222a75d-8b18-44e2-9ed8-7ee4e0d23cfc
- https://github.com/Barbarur/NovaPointPowerShell/blob/main/Solutions/Report/Preservation%20Hold%20Library%20in%20each%20Site.md
- https://support.microsoft.com/en-us/office/view-usage-data-for-sharepoint-pages-and-news
- https://pkbullock.com/blog/2020/can-i-convert-a-publishing-page-to-the-modern-experience
- https://learn.microsoft.com/en-us/sharepoint/dev/transform/modernize-userinterface-site-pages
- https://adoption.microsoft.com/en-us/sharepoint-look-book/
- https://www.sitedesigner.io/#/
- https://www.sharepointdiary.com/2022/06/create-site-template-in-sharepoint-online.html
- https://sharepoint.handsontek.net/2022/02/07/host-static-html-sites-modern-sharepoint-site-collections/
- https://www.sharepointdiary.com/2012/10/bulk-upload-files-to-sharepoint-using-powershell.html

**Microsoft Teams (versions)**
- https://www.microsoft.com/nl-nl/microsoft-teams/compare-microsoft-teams-business-options?market=nl
- https://www.microsoft.com/nl-nl/microsoft-teams/premium?market=nl#Pricing
- https://www.microsoft.com/nl-nl/microsoft-teams/enterprise/teams-enterprise?activetab=pivot%3Aoverzichttab&market=nl

**Defender for Endpoint**
- `Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Disabled`

- `Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\Windows\Microsoft.NET\Framework64\v4.0.30319"`
- `Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Disabled`

- `get-mppreference | select-object -expandproperty AttackSurfaceReductionRules_Actions`
- `get-mppreference | select-object -expandproperty AttackSurfaceReductionRules_Ids`
- `get-mppreference | select-object -expandproperty ExclusionExtension`
- `get-mppreference | select-object -expandproperty ExclusionIpAddress`
- `get-mppreference | select-object -expandproperty ExclusionPath`
- `get-mppreference | select-object -expandproperty ExclusionProcess`
- `get-mppreference | select-object -expandproperty AttackSurfaceReductionOnlyExclusions`


- https://www.techcrafters.com/portal/en/kb/articles/powershell-tutorial-configuring-asr-to-block-processes-from-psexec-and-wmi#Testing_Specific_ASR_Rules
- https://gist.github.com/api0cradle/1fdf6bd7fa1a03cd0423feca1ee692eb
- https://www.techcrafters.com/portal/en/kb/articles/powershell-tutorial-configuring-asr-to-block-processes-from-psexec-and-wmi#Setting_Rule_Actions
- https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
- https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test
- https://nmmhelp.getnerdio.com/hc/en-us/articles/30697922879501-Attack-Surface-Reduction-AVD-Exclusions



**EntraID**
- https://borncity.com/win/2024/05/13/azure-entra-id-microsoft-confirms-issues-with-single-sign-on-sso/
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks


**Conditional Access**
- https://www.cswrld.com/2024/02/recommended-conditional-access-policies-in-microsoft-entra-id/
- https://learn.microsoft.com/nl-nl/graph/api/conditionalaccesspolicy-delete?view=graph-rest-1.0&tabs=powershell


**Intune**
- https://www-intuneirl-com.cdn.ampproject.org/c/s/www.intuneirl.com/implementing-platform-sso-for-macos-a-deep-dive-into-configuration-troubleshooting/amp/
- https://www.linkedin.com/pulse/mobile-security-microsoft-intune-configuration-frameworks-peter-chen-kgarc
- https://github.com/microsoft/Intune-Config-Frameworks/tree/master/AndroidEnterprise/FullyManaged
- https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-windows#enable-with-microsoft-intune
- https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-device-registration
- https://jonconwayuk.wordpress.com/2023/03/25/intune-force-microsoft-edge-update-to-latest-version-during-windows-autopilot

**Security Hardening**
- https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Intune%20Files/Hardening%20Policies/Windows%20Update.json
- https://github.com/TheTechBeast8/HardeningAudit/tree/main/CIS%20Win11%20v3.0/Deployment%20Scripts
- https://public.cyber.mil/stigs/gpo/
- https://www.coreview.com/product-tour
- https://blueprint.asd.gov.au/

**General**
- https://www.syxsense.com/syxsense-securityarticles/cis_benchmarks/cis_benchmarks.htm
- https://blog.expta.com/2021/10/how-to-install-outlook-add-in-to-view.html
- https://learn.microsoft.com/en-us/defender-office-365/quarantine-admin-manage-messages-files
- https://www.microsoft.com/en-us/servicesagreementpening-read-on/
- https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#eop-outbound-spam-policy-settings
- https://learn.microsoft.com/en-us/graph/permissions-reference
- https://blueprint.asd.gov.au/configuration/intune/devices/configuration-profiles/ios-microsoft-enterprise-sso-plugin

**Azure Virtual Desktop (AVD) with Intune**
Azure Virtual Desktop (AVD) multi-session environments have certain limitations when it comes to Intune management. Below are the key Intune features and profiles that are not supported in AVD multi-session scenarios:

1. Device Configuration Profiles
Device-based profiles: These profiles are designed for single-user devices and may not work as expected in a multi-session environment.
Endpoint Protection: Settings like BitLocker encryption and other device security configurations are not supported in multi-session AVD.

2. User-Specific Settings
User-based settings, such as per-user certificates or email profiles, may not work as expected in a multi-session environment.

3. Compliance Policies
Compliance policies that rely on device-specific attributes (e.g., encryption, password policies) are not fully supported because multi-session AVD is not treated as a single-user device.

4. App Deployment
Win32 Apps: While Win32 apps can be deployed, they may not function as expected in a multi-session environment due to user-specific configurations.
Line-of-Business (LOB) Apps: Some LOB apps may face challenges in multi-session scenarios, especially if they require per-user installation or configuration.

5. Windows Update for Business
Multi-session AVD does not support Windows Update for Business policies managed through Intune. Updates for AVD multi-session images are typically managed through other methods, such as WSUS or Configuration Manager.

6. Endpoint Analytics
Some features of Endpoint Analytics, such as device performance monitoring, are not fully supported in multi-session environments.


