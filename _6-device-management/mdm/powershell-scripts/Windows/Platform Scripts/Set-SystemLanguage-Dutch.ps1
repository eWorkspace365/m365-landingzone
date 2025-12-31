<#
.SYNOPSIS
  Install Dutch (nl-NL) language features and set system/user language to Dutch.
  Schedules a delayed reboot (default 10 minutes) and notifies users.

.NOTES
  Run as Administrator (Intune system context is OK).
  To abort the scheduled reboot: shutdown /a
#>

# -------------------------
# Configuration
# -------------------------
$LangTag = 'nl-NL'                      # Dutch (Netherlands)
$Capabilities = @(
    "Language.Basic~~~$LangTag~0.0.1.0",
    "Language.Handwriting~~~$LangTag~0.0.1.0",
    "Language.OCR~~~$LangTag~0.0.1.0",
    "Language.TextToSpeech~~~$LangTag~0.0.1.0"
)

# Reboot delay (minutes) - change this if you want a different delay
$DelayMinutes = 10
$DelaySeconds = [int]($DelayMinutes * 60)

# Message shown to users (use a double-quoted here-string so $DelayMinutes expands)
$UserMessage = @"
Dutch (nl-NL) language has been installed.
A system restart is required to apply the language change.

The system will restart in $DelayMinutes minutes. Please save your work.
To abort the scheduled restart, an administrator can run:
  shutdown /a
"@

# -------------------------
# Admin check
# -------------------------
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator. Right-click PowerShell and choose 'Run as administrator'."
    exit 1
}

# -------------------------
# Install language capabilities (best-effort)
# -------------------------
Write-Host "Installing Dutch language capabilities (if available)..." -ForegroundColor Cyan
foreach ($cap in $Capabilities) {
    try {
        Add-WindowsCapability -Online -Name $cap -ErrorAction Stop | Out-Null
        Write-Host "Installed capability: $cap"
    } catch {
        Write-Warning "Could not install capability: $cap. (This may be fine; it could already be installed or internet is required.)"
    }
}

# -------------------------
# Make Dutch the user's language list (primary)
# -------------------------
Write-Host "Setting user language list to $LangTag..." -ForegroundColor Cyan
try {
    $newList = New-WinUserLanguageList -Language $LangTag
    # attempt to enable handwriting if available
    if ($newList.Count -gt 0) {
        $newList[0].Handwriting = $true
    }
    Set-WinUserLanguageList -LanguageList $newList -Force
    Write-Host "User language list set to $LangTag."
} catch {
    Write-Warning "Failed to set WinUserLanguageList: $($_.Exception.Message)"
}

# -------------------------
# Set culture, system locale and UI language
# -------------------------
Write-Host "Setting culture, system locale and UI language override to $LangTag..." -ForegroundColor Cyan
try {
    Set-Culture -CultureInfo $LangTag
    Set-WinSystemLocale -SystemLocale $LangTag
    Set-WinUILanguageOverride -Language $LangTag
    Write-Host "Culture, system locale and UI language override set to $LangTag."
} catch {
    Write-Warning "One or more settings could not be applied via cmdlets: $($_.Exception.Message)"
}

# -------------------------
# Set time zone and home location (Netherlands)
# -------------------------
Write-Host "Setting time zone and home location to Netherlands..." -ForegroundColor Cyan
try {
    # Set timezone to Western Europe Standard Time (covers Netherlands)
    Set-TimeZone -Id "W. Europe Standard Time"

    # GeoID for Netherlands = 159
    Set-WinHomeLocation -GeoId 159

    Write-Host "Time zone and location set to Netherlands."
} catch {
    Write-Warning "Failed to set time zone or home location: $($_.Exception.Message)"
}
