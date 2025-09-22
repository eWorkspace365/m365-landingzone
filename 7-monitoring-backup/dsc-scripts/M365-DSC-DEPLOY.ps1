[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$Customer,
    
    [Parameter(Mandatory=$false)]
    [String]$Workload
)


Start-DSCConfiguration -Path "C:\Program Files\Rubicon\microsoft365dsc\customers\$customer\deploy\$workload\M365TenantConfig" -Wait -Verbose -Force -ErrorAction Ignore

Exit 0
