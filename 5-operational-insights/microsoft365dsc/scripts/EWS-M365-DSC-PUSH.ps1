[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$Company,
    
    [Parameter(Mandatory=$false)]
    [String]$Workload
)


Start-DSCConfiguration -Path "C:\DevOps\$company\build\M365\$workload\M365TenantConfig" -Wait -Verbose -Force -ErrorAction Ignore

Exit 0
