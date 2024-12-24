#!/bin/sh

# 3.6 Ensure Firewall Logging Is Enabled and Configured
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingopt detail

# 4.1 Ensure Bonjour Advertising Services Is Disabled
sudo /usr/bin/defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true

