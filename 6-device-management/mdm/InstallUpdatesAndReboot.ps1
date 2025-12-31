# Save this script as InstallUpdatesAndReboot.ps1

# Define the log file path
$logFilePath = "C:\ProgramData\UpdateLog.txt"

# Function to log messages
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Add-Content -Path $logFilePath -Value $logMessage
}

# Start logging
Log-Message "Starting Windows Update installation."

# Import the PSWindowsUpdate module
Import-Module PSWindowsUpdate

# Search for updates
Log-Message "Searching for updates..."
$updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot

# Install updates
if ($updates) {
    Log-Message "Installing updates..."
    Install-WindowsUpdate -AcceptAll -IgnoreReboot -Verbose | Out-File -FilePath $logFilePath -Append
    Log-Message "Installation complete."

 
}

Log-Message "Windows Update installation script completed."
