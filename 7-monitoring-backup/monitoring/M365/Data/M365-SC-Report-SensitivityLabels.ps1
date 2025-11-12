[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$Customer,
    
    [Parameter(Mandatory=$false)]
    [String]$TenantID,
    
    [Parameter(Mandatory=$false)]
    [String]$AppID,
    
    [Parameter(Mandatory=$false)]
    [String]$CertificateThumbprint,
    
    [Parameter(Mandatory=$false)]
    [String]$Organization,
    
    [Parameter(Mandatory=$false)]
    [String]$AdminURL,
    
    [Parameter(Mandatory=$false)]
    [String]$TenantURL
)


# Connect to services
Write-Host "Connecting to services..." -ForegroundColor Cyan
Connect-PnPOnline -Url $AdminUrl -ClientId $AppID -Thumbprint $CertificateThumbPrint -Tenant $Organization
Connect-ExchangeOnline -CertificateThumbPrint $CertificateThumbprint -AppID $AppID -Organization $Organization
Connect-IPPSSession -CertificateThumbprint $CertificateThumbprint -AppID $AppID -Organization $Organization

# Get Sensitivity Labels
Write-Host "Retrieving Sensitivity Labels..." -ForegroundColor Cyan
$labels = Get-Label

# Get Label Policies for associations
$labelPolicies = Get-LabelPolicy

# Build the report
$report = foreach ($label in $labels) {
    $policyNames = $labelPolicies | Where-Object { $_.AssignedLabels -contains $label.Identity } | Select-Object -ExpandProperty Name

    [PSCustomObject]@{
        Customer        = $Customer
        LabelName       = $label.DisplayName
        LabelId         = $label.Identity
        Description     = $label.Tooltip
        Status          = if ($label.Enabled) { "Active" } else { "Inactive" }
        ContentType     = $label.ContentType
        DefaultLabel    = $label.IsDefault
        Policies        = if ($policyNames) { ($policyNames -join ", ") } else { "None" }
    }
}

# Export report
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$reportFile = "SensitivityLabels-$Customer-$timestamp.csv"
$report | Export-Csv -Path $reportFile -NoTypeInformation -Encoding UTF8
Write-Host "Report exported to $reportFile" -ForegroundColor Green

# Optionally: Email logic can be added here (SMTP or Graph Mail)
