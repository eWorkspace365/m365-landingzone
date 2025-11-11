[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$Customer,
    
    [Parameter(Mandatory=$false)]
    [String]$Workload
)


Start-DSCConfiguration -Path "C:\DevOps\$customer\build\M365\$workload\M365TenantConfig" -Wait -Verbose -Force -ErrorAction Ignore

Exit 0
