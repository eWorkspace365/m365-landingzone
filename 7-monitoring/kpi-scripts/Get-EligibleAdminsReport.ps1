<#
Report: users ELIGIBLE (PIM) for Entra ID admin roles
- Eligible roles (direct + group-based)
- Last sign-in info (prefers lastSuccessfulSignInDateTime)
- License plans (friendly names + SkuPartNumbers)

App perms (app-only): RoleManagement.Read.Directory, Directory.Read.All, AuditLog.Read.All (for signInActivity)
Optional email: Mail.Send
#>

[CmdletBinding()]
param(
  # Graph (read)
  [string]$TenantId,
  [string]$AADClientId,
  [string]$AADThumbprint,

  # Graph (mail)
  [string]$EXOMailFrom,   # UPN or userId
  [string]$EXOMailTo,     # comma/semicolon separated list
  [string]$EXOClientId,
  [string]$EXOThumbprint,

  # Cosmetic
  [Parameter(Mandatory=$true)][string]$OrganizationDomain,
  [string]$BannerImageUrl = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxp5ZQ7C2whpooKNrwsYW3knxp4M5rDjHljILObOVcLVI_o5HsnAT3g6KBYAbLY_SXgA&usqp=CAU",

  # Filters/behavior
  [switch]$ExcludeGuests = $true,
  [string[]]$TargetRoles,
  [switch]$EmailReport
)

$ErrorActionPreference = 'Stop'

# ---- Styling (ASCII-safe) ----
$CSS = @"
<style>
 body{font-family:Arial,Helvetica,sans-serif}
 table{border-collapse:collapse;width:100%}
 th,td{border:1px solid #ddd;padding:8px}
 tr:nth-child(even){background:#fff6e6}
 tr:hover{background:#f1f1f1}
 th{background:#F39C12;color:#fff;text-align:left}
 .banner{margin:8px 0 12px 0}
 .pill{display:inline-block;padding:2px 8px;border-radius:10px;background:#f0f0f0;margin-right:6px}
 .meta{color:#555;font-size:12px}
</style>
"@

# ---- Friendly SKU map ----
$SkuMap = @{
  "AAD_PREMIUM"       = "Entra ID P1"
  "AAD_PREMIUM_P2"    = "Entra ID P2"
  "ENTERPRISEPACK"    = "Office 365 E3"
  "ENTERPRISEPREMIUM" = "Microsoft 365 E5 (legacy O365)"
  "SPE_E3"            = "Microsoft 365 E3"
  "SPE_E5"            = "Microsoft 365 E5"
  "EMS"               = "Enterprise Mobility + Security E3"
  "EMSPREMIUM"        = "Enterprise Mobility + Security E5"
}
function Get-FriendlySkuNames {
  param([array]$LicenseDetails)
  if (-not $LicenseDetails) { return @() }
  $LicenseDetails |
    ForEach-Object { $_.SkuPartNumber } |
    Sort-Object -Unique |
    ForEach-Object {
      if ($SkuMap.ContainsKey($_)) { "$($SkuMap[$_]) [$($_)]" } else { $_ }
    }
}

# ---- Helper for REST paging ----
function Invoke-GraphPaged {
  param([Parameter(Mandatory)][string]$Uri)
  $items = @()
  $next = $Uri
  while ($next) {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $next
    if ($resp.value) { $items += $resp.value }
    $next = $resp.'@odata.nextLink'
  }
  return $items
}

# ---- Connect (read) ----
Write-Host "Connecting to Microsoft Graph (read)..." -ForegroundColor DarkGray
Connect-MgGraph -ClientId $AADClientId -TenantId $TenantId -CertificateThumbprint $AADThumbprint -NoWelcome

# ---- PIM eligibility via REST ----
Write-Host "Retrieving eligible directory roles (PIM) via REST..." -ForegroundColor DarkGray

$eligUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances" +
           "?`$expand=roleDefinition,principal" +
           "&`$select=id,principalId,roleDefinitionId,appScopeId,directoryScopeId,memberType"
$eligibilityInstances = Invoke-GraphPaged -Uri $eligUri

# Optional role filter
$limitToRoles = $false
$roleAllow = @{}
if ($TargetRoles -and $TargetRoles.Count -gt 0) {
  $limitToRoles = $true
  foreach ($r in $TargetRoles) { $roleAllow[$r.ToLowerInvariant()] = $true }
}

# userId -> HashSet[string] of role names
$eligibleUsersRoles = @{}

function Ensure-RoleSet {
  param([string]$UserId)
  if (-not $eligibleUsersRoles.ContainsKey($UserId) -or `
      -not ($eligibleUsersRoles[$UserId] -is [System.Collections.Generic.HashSet[string]])) {
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    if ($eligibleUsersRoles.ContainsKey($UserId)) {
      $existing = $eligibleUsersRoles[$UserId]
      if ($existing -is [string]) { [void]$set.Add($existing) }
      elseif ($existing -is [System.Collections.IEnumerable] -and -not ($existing -is [string])) {
        foreach ($e in $existing) { if ($e) { [void]$set.Add([string]$e) } }
      }
    }
    $eligibleUsersRoles[$UserId] = $set
  }
}

function Add-EligibleRole {
  param([string]$UserId,[string]$RoleName)
  if (-not $UserId -or -not $RoleName) { return }
  if ($limitToRoles -and -not $roleAllow.ContainsKey($RoleName.ToLowerInvariant())) { return }
  Ensure-RoleSet -UserId $UserId
  [void]$eligibleUsersRoles[$UserId].Add($RoleName)
}

# Separate group-based entries for expansion
$groupInst = @()
foreach ($inst in $eligibilityInstances) {
  $roleName = $null
  if ($inst.roleDefinition -and $inst.roleDefinition.displayName) { $roleName = $inst.roleDefinition.displayName }
  elseif ($inst.roleDefinitionId) { $roleName = $inst.roleDefinitionId }

  $p = $inst.principal
  $pType = $null
  if ($p -and $p.'@odata.type') { $pType = $p.'@odata.type' }

  if ($pType -eq '#microsoft.graph.user') {
    Add-EligibleRole -UserId $p.id -RoleName $roleName
  } elseif ($pType -eq '#microsoft.graph.group' -or -not $pType) {
    $groupInst += $inst
  }
}

# Expand group-based eligibility into transitive user members
if ($groupInst.Count -gt 0) {
  Write-Host "Expanding group-based eligibility..." -ForegroundColor DarkGray
  foreach ($gi in $groupInst) {
    $roleName = if ($gi.roleDefinition -and $gi.roleDefinition.displayName) { $gi.roleDefinition.displayName } else { $gi.roleDefinitionId }
    $gid = $gi.principalId
    if (-not $gid) { continue }

    $membersUri = "https://graph.microsoft.com/v1.0/groups/$gid/transitiveMembers?`$select=id,userPrincipalName,userType"
    $members = Invoke-GraphPaged -Uri $membersUri
    foreach ($m in $members) {
      if ($m.'@odata.type' -eq '#microsoft.graph.user') {
        Add-EligibleRole -UserId $m.id -RoleName $roleName
      }
    }
  }
}

if ($eligibleUsersRoles.Count -eq 0) {
  Write-Host "No eligible users found (after filters)." -ForegroundColor Yellow
}

# ---- Fetch user details + sign-in + license (SDK cmdlets) ----
$reportRows = @()
$needSignInActivityNote = $false

foreach ($userId in $eligibleUsersRoles.Keys) {
  try {
    $u = Get-MgUser -UserId $userId -Property "Id,DisplayName,UserPrincipalName,UserType,AccountEnabled,SignInActivity,CreatedDateTime"
  } catch {
    Write-Warning "Unable to read user $userId : $_"
    continue
  }

  if ($ExcludeGuests) {
    if ($u.UserType -eq 'Guest') { continue }
    if ($OrganizationDomain -and $u.UserPrincipalName -like "*#EXT#@$OrganizationDomain") { continue }
  }

  # Licenses
  $lic = @()
  try { $lic = Get-MgUserLicenseDetail -UserId $u.Id } catch {}

  $skuPartNumbers = $lic | ForEach-Object { $_.SkuPartNumber } | Sort-Object -Unique
  $friendly = Get-FriendlySkuNames -LicenseDetails $lic
  $hasP1 = $skuPartNumbers -contains "AAD_PREMIUM"
  $hasP2 = $skuPartNumbers -contains "AAD_PREMIUM_P2"

  # Sign-in stamps
  $lastSucc = $null
  $lastSign = $null
  if ($u.SignInActivity) {
    $lastSucc = $u.SignInActivity.lastSuccessfulSignInDateTime
    $lastSign = $u.SignInActivity.lastSignInDateTime
  } else {
    $needSignInActivityNote = $true
  }

  $lastShown = $null
  if ($lastSucc) { $lastShown = [DateTime]$lastSucc }
  elseif ($lastSign) { $lastShown = [DateTime]$lastSign }

  $daysAgo = $null
  if ($lastShown) { $daysAgo = (New-TimeSpan -Start $lastShown -End (Get-Date)).Days }

  # Robust role list
  $rolesValue = $eligibleUsersRoles[$u.Id]
  if ($rolesValue -is [System.Collections.Generic.HashSet[string]]) {
    $roles = ($rolesValue | Sort-Object) -join ", "
  } elseif ($rolesValue -is [System.Collections.IEnumerable] -and -not ($rolesValue -is [string])) {
    $roles = (@($rolesValue) | Sort-Object -Unique) -join ", "
  } else {
    $roles = [string]$rolesValue
  }

  $reportRows += [PSCustomObject]@{
    DisplayName                  = $u.DisplayName
    AccountEnabled               = $u.AccountEnabled
    EligibleRoles                = $roles
    LastSuccessfulSignInDateTime = $( if ($lastSucc) { Get-Date $lastSucc -Format 'dd MMMM yyyy HH:mm' } else { "" } )
    LastSignInDateTime           = $( if ($lastSign) { Get-Date $lastSign -Format 'dd MMMM yyyy HH:mm' } else { "" } )
    DaysSinceLastSuccessful      = $( if ($null -ne $daysAgo) { $daysAgo } else { "" } )
    Licenses                     = $( if ($friendly.Count -gt 0) { $friendly -join "; " } else { "None" } )
    SkuPartNumbers               = $( if ($skuPartNumbers) { $skuPartNumbers -join "; " } else { "" } )
    CreatedDateTime              = $( if ($u.CreatedDateTime) { Get-Date $u.CreatedDateTime -Format 'dd MMMM yyyy HH:mm' } else { "" } )
  }
}

# ---- HTML output ----
$rowsSorted = $reportRows | Sort-Object -Property @{Expression='EligibleRoles';Descending=$false}, @{Expression='DisplayName';Descending=$false}

$tbl = $rowsSorted | Select-Object `
  DisplayName,AccountEnabled,EligibleRoles,
  LastSuccessfulSignInDateTime,DaysSinceLastSuccessful,
  Licenses |
  ConvertTo-Html -Fragment

$generated = Get-Date -Format 'dd MMMM yyyy HH:mm'

$summary = @"
<h2>Eligible Admin Roles - Last Sign-in and License Report</h2>
"@
if ($BannerImageUrl) {
  $summary += "<img src=""$BannerImageUrl"" width=""120"" height=""auto"" alt=""Banner"" class=""banner"">"
}
$summary += @"
<div class="meta">
  <span class="pill">Organization: <strong>$OrganizationDomain</strong></span>
  <span class="pill">Users with eligible directory roles</span>
"@
if ($TargetRoles -and $TargetRoles.Count -gt 0) {
  $summary += "<span class='pill'>Filtered roles: <strong>$([string]::Join(', ', $TargetRoles))</strong></span>"
}
$summary += "<br/>Generated: $generated</div>"

$note = ""
if ($needSignInActivityNote) {
  $note = "<p class=""meta"">Note: signInActivity was not returned for some users. Ensure the app has AuditLog.Read.All and the tenant has Entra ID P1 or P2.</p>"
}

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>Eligible Admin Roles - Last Sign-in and License</title>
$CSS
</head>
<body>
$summary
$tbl
$note
</body>
</html>
"@

# ---- Optional email ----
if ($EmailReport) {
  Write-Host "Connecting to Microsoft Graph (mail)..." -ForegroundColor DarkGray
  Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint -NoWelcome

  $toList = @()
  if ($EXOMailTo) {
    $EXOMailTo -split '[;,]' | ForEach-Object {
      $a = $_.Trim()
      if ($a) { $toList += @{ emailAddress = @{ address = $a } } }
    }
  }

  $params = @{
    message = @{
      subject = ("Eligible Admin Roles - Last Sign-in and License ({0})" -f $OrganizationDomain)
      body    = @{ contentType = "HTML"; content = $html }
      toRecipients = $toList
    }
    saveToSentItems = $true
  }

  Write-Verbose "Sending email with the eligible admin roles report"
  Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params
  Write-Host "Email sent." -ForegroundColor Green

  try { Disconnect-MgGraph | Out-Null } catch {}
} else {
  $html
  try { Disconnect-MgGraph | Out-Null } catch {}
}
