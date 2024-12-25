#!/bin/sh

# 5.7 Ensure an Administrator Account Cannot Login to Another Users Session
sudo /usr/bin/security authorizationdb write system.login.screensaver use-login-window-ui

# 5.8 Ensure a Login Window Banner Exists
sudo defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText "Welcome to Brand New Day"

# 6.1.1 Ensure Show All Filename Extensions Setting is Enabled
defaults write NSGlobalDomain AppleShowAllExtensions -bool true

# 6.3.1 Ensure Automatic Opening of Safe Files in Safari Is Disabled
defaults write com.apple.Safari AutoOpenSafeDownloads -bool false

# 6.3.3 Ensure Warn When Visiting A Fraudulent Website in Safari
defaults write com.apple.Safari WarnAboutFraudulentWebsites -bool true

# 6.3.4 Ensure Prevent Cross-site Tracking in Safari Is Enabled
defaults write com.apple.Safari com.apple.Safari.ContentPageGroupIdentifier.WebKit2ResourceLoadStatisticsEnabled -bool true

# 6.4.1 Ensure Secure Keyboard Entry Terminal.app Is Enabled
defaults write com.apple.terminal SecureKeyboardEntry -bool true