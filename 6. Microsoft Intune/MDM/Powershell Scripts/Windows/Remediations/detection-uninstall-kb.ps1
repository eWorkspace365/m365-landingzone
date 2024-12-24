<#
Run as: System
Context: 64 Bit
#> 

$servicename = "WSearch"

$checkarray = 0

$serviceexist = Get-Service -Name $servicename -ErrorAction SilentlyContinue
if ($null -ne $serviceexist) {
    $checkarray++
}

$servicerunning = Get-Service -Name $servicename | Where-Object {$_.Status -eq "Running"}
if ($null -ne $servicerunning) {
    $checkarray++
}

if ($checkarray -ne 0) {
    Write-Host "Service is available and running"
    exit 1
} else {
    Write-Host "Service is not there/running"
    exit 1
}