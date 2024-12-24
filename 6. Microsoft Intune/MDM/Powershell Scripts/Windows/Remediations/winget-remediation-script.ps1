# Winget Remediation Script for Intune Proactive Remediation

# Function to install Winget
function Install-Winget {
    # Download the latest release of Microsoft.DesktopAppInstaller from GitHub
    $releaseUrl = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
    $asset = (Invoke-RestMethod -Uri $releaseUrl).assets | Where-Object { $_.name -like "*msixbundle" }
    $downloadUrl = $asset.browser_download_url
    $outFile = "$env:TEMP\Microsoft.DesktopAppInstaller.msixbundle"

    Invoke-WebRequest -Uri $downloadUrl -OutFile $outFile

    # Install the package
    Add-AppxPackage -Path $outFile

    # Clean up
    Remove-Item $outFile
}

# Check if winget is installed
$wingetPath = Get-Command winget -ErrorAction SilentlyContinue

if (-not $wingetPath) {
    Write-Output "Winget is not installed. Installing now..."
    Install-Winget
    
    # Verify installation
    $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetPath) {
        Write-Output "Winget has been successfully installed."
        Exit 0
    } else {
        Write-Output "Failed to install Winget."
        Exit 1
    }
} else {
    Write-Output "Winget is already installed."
    Exit 0
}
