# Winget Detection Script for Intune Proactive Remediation

# Check if winget is installed
$wingetPath = Get-Command winget -ErrorAction SilentlyContinue

if ($wingetPath) {
    Write-Output "Winget is installed."
    Exit 0
} else {
    Write-Output "Winget is not installed."
    Exit 1
}
