<# Requires: Az.Accounts, Az.Security, Az.PolicyInsights
   Install-Module Az.Accounts,Az.Security,Az.PolicyInsights -Scope CurrentUser
#>

param(
  [Parameter(Mandatory=$true)] [string]$TenantId,
  [string]$AppId,                  # optional: for SPN login
  [string]$CertificateThumbprint,  # optional: for SPN login
  [int]$LookbackDays = 30
)

# Harden TLS and clean context
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Disable-AzContextAutosave -Scope Process | Out-Null

# ---------- LOGIN (choose ONE of the following) ----------
if ($AppId -and $CertificateThumbprint) {
  # Certificate-based service principal (recommended for automation)
  Connect-AzAccount -ServicePrincipal -Tenant $TenantId `
    -ApplicationId $AppId -CertificateThumbprint $CertificateThumbprint | Out-Null
}
else {
  # Interactive but CA/MFA-friendly
  Connect-AzAccount -Tenant $TenantId -UseDeviceAuthentication | Out-Null
}
# --------------------------------------------------------

# Time window for policy states (up to 90 days supported)
$from = (Get-Date).AddDays(-1 * [Math]::Min($LookbackDays,90)).ToUniversalTime()
$to   = (Get-Date).ToUniversalTime()

$controlSummary = New-Object System.Collections.Generic.List[object]
$nonCompliant   = New-Object System.Collections.Generic.List[object]

# Loop all accessible subscriptions in this tenant
Get-AzSubscription -TenantId $TenantId | ForEach-Object {
  $sub = $_
  Set-AzContext -Subscription $sub.Id -Tenant $TenantId | Out-Null

  # --- Regulatory standards/controls (counts) ---
  $standards = Get-AzRegulatoryComplianceStandard
  foreach ($std in $standards) {
    $controls = Get-AzRegulatoryComplianceControl -StandardName $std.Name
    foreach ($ctrl in $controls) {
      $assess = Get-AzRegulatoryComplianceAssessment -StandardName $std.Name -ControlName $ctrl.Name

      $failed  = ($assess | Where-Object { $_.State -eq 'Failed'  }).Count
      $passed  = ($assess | Where-Object { $_.State -eq 'Passed'  }).Count
      $skipped = ($assess | Where-Object { $_.State -eq 'Skipped' }).Count

      $controlSummary.Add([pscustomobject]@{
        SubscriptionName = $sub.Name
        SubscriptionId   = $sub.Id
        StandardName     = $std.Name
        ControlName      = $ctrl.Name
        FailedResources  = $failed
        PassedResources  = $passed
        SkippedResources = $skipped
        TotalAssessments = $assess.Count
      })
    }
  }

  # --- Actual non-compliant resources via Policy States ---
  $states = Get-AzPolicyState -SubscriptionId $sub.Id -From $from -To $to `
            -Filter "ComplianceState eq 'NonCompliant'"

  foreach ($s in $states) {
    $nonCompliant.Add([pscustomobject]@{
      SubscriptionName        = $sub.Name
      SubscriptionId          = $sub.Id
      ResourceId              = $s.ResourceId
      ResourceType            = $s.ResourceType
      PolicyAssignmentName    = $s.PolicyAssignmentName
      PolicyDefinitionName    = $s.PolicyDefinitionName
      PolicySetDefinitionName = $s.PolicySetDefinitionName  # initiative (often the regulatory standard)
      ComplianceState         = $s.ComplianceState
      Timestamp               = $s.Timestamp
    })
  }
}

$stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
$path1 = "RegulatoryControls_Summary_$stamp.csv"
$path2 = "NonCompliant_Resources_$stamp.csv"

$controlSummary | Sort-Object SubscriptionName,StandardName,ControlName |
  Export-Csv -NoTypeInformation -Path $path1

$nonCompliant   | Sort-Object SubscriptionName,PolicySetDefinitionName,ResourceId |
  Export-Csv -NoTypeInformation -Path $path2

Write-Host "✔ Saved:`n  $path1`n  $path2"
