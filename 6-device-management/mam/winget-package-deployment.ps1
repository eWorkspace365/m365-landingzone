# WinGet Software installation script for Intune
#
# Arian Bode / eWorkspace / Ocober 2024
 
# Usage
#
# Install:
#     powershell -executionpolicy bypass -file winget-package-deployment.ps1 "install" "[winget-id] or [winget-name]"
# Uninstall:
#     powershell -executionpolicy bypass -file winget-package-deployment.ps1 "uninstall" "[winget-id] or [winget-name]"
#
# Check https://winget.run or https://winstall.app for winget ID
 
param(
    [Parameter(Mandatory)]
    [string]$Action,
    [Parameter(Mandatory)]
    [string]$AppName,
    [Parameter()]
    [string]$AppSource = "winget"
)
 
# Fix Winget Sources (Optional)
# winget source reset --force
# $msix = Join-Path -Path $env:TEMP -ChildPath 'source.msix'
# Invoke-WebRequest https://cdn.winget.microsoft.com/cache/source.msix -OutFile $msix
# Add-AppXPackage -Path $msix
# Remove-Item -Path $msix
# winget source update
 
# Ensure the log directory exists
$logDir = "C:\ProgramData\WinGetLogs"
if (-Not (Test-Path -Path $logDir)) {
    mkdir $logDir
}
 
# Locate the winget executable
$nativeAppFilePath = Get-ChildItem "C:\Program Files\WindowsApps" -Recurse -File |
    Where-Object { $_.Name -like "winget.exe" } |
    Select-Object -ExpandProperty FullName |
    Select-Object -Last 1
 
if (-Not $nativeAppFilePath) {
    "Winget.exe Not Found" | Out-File "$logDir\InstallScript-error.log" -Append
    Write-Error -Message "Winget not found." -Category OperationStopped
    exit
}
 
# Switch statement to handle install and uninstall actions
switch ($Action) {
    "install" {
        try {
            $response = &"$nativeAppFilePath" install --name $AppName -s $AppSource --silent --accept-source-agreements --accept-package-agreements --force
        }
        catch {
            $_.Exception.Message | Out-File "$logDir\InstallScript-error.log" -Append
            Write-Error -Message "Error happened during installation." -Category OperationStopped
        }
    }
    "uninstall" {
        try {
            $response = &"$nativeAppFilePath" uninstall --name $AppName --silent --accept-source-agreements --all
        }
        catch {
            $_.Exception.Message | Out-File "$logDir\InstallScript-error.log" -Append
            Write-Error -Message "Error happened during uninstallation." -Category OperationStopped
        }
    }
    default {
        Write-Error -Message "Invalid action specified. Use 'install' or 'uninstall'." -Category InvalidArgument
        exit
    }
}
 
# Log the response
if ($response -like "*Successfully*") {
    $response | Out-File "$logDir\$AppName.log" -Force
} else {
    $response | Out-File "$logDir\InstallScript-error.log" -Append
    Write-Error -Message "Error happened during action: $Action." -Category OperationStopped
}