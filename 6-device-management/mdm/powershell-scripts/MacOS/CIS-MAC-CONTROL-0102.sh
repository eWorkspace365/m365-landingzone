#!/bin/sh

# 1.2 Enable Auto Update
sudo /usr/bin/defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true 

# 1.3 Enable Download new updates when available
sudo /usr/bin/defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true

# 1.4 Ensure Install of macOS Updates Is Enabled
sudo /usr/bin/defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true

# 1.5 Enable system data files and security update installs 
sudo /usr/bin/defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true

# 1.6 Enable macOS Update Installs 
sudo  /usr/bin/defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true 
sudo  /usr/bin/defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true

# 2.2.2 Ensure Firewall Stealth Mode Is Enabled
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# 2.3.2.1 Ensure Set Time and Date Automatically Is Enabled
sudo /usr/sbin/systemsetup -setusingnetworktime on

# 2.3.2.2 Ensure Time Is Set Within Appropriate Limits
sudo /usr/sbin/systemsetup -getnetworktimeserver
sudo /usr/bin/sntp -sS time.apple.com

# 2.3.3.1 Ensure DVD or CD Sharing Is Disabled
sudo /bin/launchctl disable system/com.apple.ODSAgent

# 2.3.3.2 Ensure Screen Sharing Is Disabled
sudo /bin/launchctl disable system/com.apple.screensharing

# 2.3.3.3 Ensure File Sharing Is Disabled
sudo /bin/launchctl disable system/com.apple.smbd

# 2.3.3.4 Ensure Printer Sharing Is Disabled
sudo /usr/sbin/cupsctl --no-share-printers

# 2.3.3.6 Ensure Remote Management Is Disabled
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop

# 2.3.3.7 Ensure Remote Apple Events Is Disabled
sudo /usr/sbin/systemsetup -setremoteappleevents off

# 2.3.3.8 Ensure Internet Sharing Is Disabled
sudo /usr/bin/defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict Enabled -int 0

# 2.3.4.1 Ensure Backup Automatically is Enabled If Time Machine Is Enabled
sudo /usr/bin/defaults write /Library/Preferences/com.apple.TimeMachine.plist AutoBackup -bool true

# 2.4.1 Ensure Show Wi-Fi status in Menu Bar Is Enabled 
sudo /usr/bin/defaults write com.apple.systemuiserver menuExtras -array-add "/System/Library/CoreServices/Menu Extras/AirPort.menu"

# 2.4.2 Ensure Show Bluetooth Status in Menu Bar Is Enabled
sudo /usr/bin/defaults write com.apple.systemuiserver menuExtras -array-add "/System/Library/CoreServices/Menu Extras/Bluetooth.menu"

# 2.5.2 Ensure Listen for "Hey Siri" Is Disabled
sudo /usr/bin/defaults write com.apple.assistant.support.plist "Assistant Enabled" -bool false

# 2.6.1.1 Ensure Location Services Is Enabled
sudo /usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool true
sudo /bin/launchctl kickstart -k system/com.apple.locationd

# 2.6.5 Ensure Gatekeeper Is Enabled
sudo /usr/sbin/spctl --master-enable

# 2.10.3 Ensure a Custom Message for the Login Screen Is Enabled
sudo /usr/bin/defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText "Center for Internet Security Test Message"

# Ensure Login Window Displays as Name and Password Is Enabled
sudo /usr/bin/defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true

# 2.10.5 Ensure Show Password Hints Is Disabled
sudo /usr/bin/defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0

# 2.12.2 Ensure Guest Access to Shared Folders Is Disabled 
sudo /usr/sbin/sysadminctl -smbGuestAccess off
