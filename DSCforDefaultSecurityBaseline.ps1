Configuration DSCforDefaultSecurityBaseline
{

	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
	Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Node localhost
	
	{
		Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxConnectionTime'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'MaxConnectionTime'
			ValueType   = 'Dword'
			ValueData   = '60000'
		}

		Registry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
			ValueName   = 'RunAsPPL'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\DisableDomainCreds'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
			ValueName   = 'DisableDomainCreds'
			ValueType   = 'Dword'
			ValueData   = '1'
		}
		
		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\EnableControlledFolderAccess'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
			ValueName   = 'EnableControlledFolderAccess'
			ValueType   = 'Dword'
			ValueData   = '1'
		}
		
		Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
			ValueName   = 'AllowLocalIPsecPolicyMerge'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
			ValueName   = 'NC_AllowNetBridge_NLA'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
			ValueName   = 'NC_StdDomainUserSetLocation'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
			ValueName   = 'EnumerateAdministrators'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
			ValueName   = 'NoDriveTypeAutoRun'
			ValueType   = 'Dword'
			ValueData   = '255'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
			ValueName   = 'NoAutorun'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
			ValueName   = 'PreXPSP2ShellProtocolBehavior'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
			ValueName   = 'NoWebServices'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordExpirationProtectionEnabled'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
			ValueName   = 'PasswordExpirationProtectionEnabled'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\ADPasswordEncryptionEnabled'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
			ValueName   = 'ADPasswordEncryptionEnabled'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordComplexity'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
			ValueName   = 'PasswordComplexity'
			ValueType   = 'Dword'
			ValueData   = '4'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordLength'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
			ValueName   = 'PasswordLength'
			ValueType   = 'Dword'
			ValueData   = '15'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordAgeDays'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
			ValueName   = 'PasswordAgeDays'
			ValueType   = 'Dword'
			ValueData   = '30'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PassphraseLength'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
			ValueName   = 'PassphraseLength'
			ValueType   = 'Dword'
			ValueData   = '8'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PostAuthenticationResetDelay'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
			ValueName   = 'PostAuthenticationResetDelay'
			ValueType   = 'Dword'
			ValueData   = '24'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PostAuthenticationActions'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
			ValueName   = 'PostAuthenticationActions'
			ValueType   = 'Dword'
			ValueData   = '3'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueName   = 'DisableAutomaticRestartSignOn'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueName   = 'LocalAccountTokenFilterPolicy'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy'
		{
			Ensure      = 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueName   = 'DisableBkGndGroupPolicy'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueName   = 'MSAOptional'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
			ValueName   = 'ProcessCreationIncludeCmdLine_Enabled'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\AllowEncryptionOracle'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
			ValueName   = 'AllowEncryptionOracle'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
			ValueName   = 'AutoAdminLogon'
			ValueType   = 'String'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
			ValueName   = 'ScreenSaverGracePeriod'
			ValueType   = 'String'
			ValueData   = '5'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Biometrics\FacialFeatures'
			ValueName   = 'EnhancedAntiSpoofing'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\InputPersonalization\AllowInputPersonalization'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization'
			ValueName   = 'AllowInputPersonalization'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Feeds'
			ValueName   = 'DisableEnclosureDownload'
			ValueType   = 'Dword'
			ValueData   = '1'
		}
		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Feeds'
			ValueName   = 'AllowBasicAuthInClear'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftAccount\DisableUserAuth'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftAccount'
			ValueName   = 'DisableUserAuth'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
			ValueName   = 'DCSettingIndex'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
			ValueName   = 'ACSettingIndex'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\W32time\TimeProviders\NtpClient\Enabled'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\W32time\TimeProviders\NtpClient'
			ValueName   = 'Enabled'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\W32time\TimeProviders\NtpServer\Enabled'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\W32time\TimeProviders\NtpServer'
			ValueName   = 'Enabled'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppCompat\DisableInventory'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat'
			ValueName   = 'DisableInventory'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppInstaller\EnableAppInstaller'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppInstaller'
			ValueName   = 'EnableAppInstaller'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppInstaller\EnableExperimentalFeatures'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppInstaller'
			ValueName   = 'EnableExperimentalFeatures'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppInstaller\EnableHashOverride'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppInstaller'
			ValueName   = 'EnableHashOverride'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppInstaller\EnableMSAppInstallerProtocol'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppInstaller'
			ValueName   = 'EnableMSAppInstallerProtocol'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CloudContent\DisableConsumerAccountStateContent'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent'
			ValueName   = 'DisableConsumerAccountStateContent'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent'
			ValueName   = 'DisableWindowsConsumerFeatures'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Connect\RequirePinForPairing'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Connect'
			ValueName   = 'RequirePinForPairing'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation'
			ValueName   = 'AllowProtectedCreds'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI'
			ValueName   = 'DisablePasswordReveal'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoToastApplicationNotification'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
			ValueName   = 'NoToastApplicationNotification'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection'
			ValueName   = 'AllowTelemetry'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection'
			ValueName   = 'DoNotShowFeedbackNotifications'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\EnableOneSettingsAuditing'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection'
			ValueName   = 'EnableOneSettingsAuditing'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\LimitDiagnosticLogCollection'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection'
			ValueName   = 'LimitDiagnosticLogCollection'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\LimitDumpCollection'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection'
			ValueName   = 'LimitDumpCollection'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeliveryOptimization'
			ValueName   = 'DODownloadMode'
			ValueType   = 'Dword'
			ValueData   = '2'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Device Metadata\PreventDeviceMetadataFromNetwork'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Device Metadata'
			ValueName   = 'PreventDeviceMetadataFromNetwork'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard'
			ValueName   = 'EnableVirtualizationBasedSecurity'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard'
			ValueName   = 'RequirePlatformSecurityFeatures'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard'
			ValueName   = 'HypervisorEnforcedCodeIntegrity'
			ValueType   = 'Dword'
			ValueData   = '3'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard'
			ValueName   = 'HVCIMATRequired'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard'
			ValueName   = 'LsaCfgFlags'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard'
			ValueName   = 'ConfigureSystemGuardLaunch'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application'
			ValueName   = 'MaxSize'
			ValueType   = 'Dword'
			ValueData   = '32768'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\Retention'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application'
			ValueName   = 'Retention'
			ValueType   = 'String'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security'
			ValueName   = 'MaxSize'
			ValueType   = 'Dword'
			ValueData   = '196608'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\Retention'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security'
			ValueName   = 'Retention'
			ValueType   = 'String'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup\Retention'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup'
			ValueName   = 'Retention'
			ValueType   = 'String'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup\MaxSize'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup'
			ValueName   = 'MaxSize'
			ValueType   = 'Dword'
			ValueData   = '32768'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System'
			ValueName   = 'MaxSize'
			ValueType   = 'Dword'
			ValueData   = '32768'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\Retention'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System'
			ValueName   = 'Retention'
			ValueType   = 'String'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
			ValueName   = 'NoAutoplayfornonVolume'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
			ValueName   = 'NoDataExecutionPrevention'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
			ValueName   = 'NoHeapTerminationOnCorruption'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
			ValueName   = 'NoBackgroundPolicy'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
			ValueName   = 'NoGPOListChanges'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer'
			ValueName   = 'EnableUserControl'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer'
			ValueName   = 'AlwaysInstallElevated'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\SafeForScripting'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer'
			ValueName   = 'SafeForScripting'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Kernel DMA Protection'
			ValueName   = 'DeviceEnumerationPolicy'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation'
			ValueName   = 'AllowInsecureGuestAuth'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\*\SYSVOL'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
			ValueName   = '\\*\SYSVOL'
			ValueType   = 'String'
			ValueData   = 'RequireMutualAuthentication=1, RequireIntegrity=1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\*\NETLOGON'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
			ValueName   = '\\*\NETLOGON'
			ValueType   = 'String'
			ValueData   = 'RequireMutualAuthentication=1, RequireIntegrity=1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OneDrive'
			ValueName   = 'DisableFileSyncNGSC'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization'
			ValueName   = 'NoLockScreenSlideshow'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization'
			ValueName   = 'NoLockScreenCamera'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
			ValueName   = 'EnableScriptBlockLogging'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
		{
			Ensure      = 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
			ValueName   = 'EnableScriptBlockInvocationLogging'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
			ValueName   = 'EnableTranscripting'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
			ValueName   = 'OutputDirectory'
			ValueType   = 'String'
			ValueData   = 'C:\ProgramData\PS_Transcript'
		}

		Registry 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader'
		{
			Ensure      = 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
			ValueName   = 'EnableInvocationHeader'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds'
			ValueName   = 'AllowBuildPreview'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
			ValueName   = 'DontDisplayNetworkSelectionUI'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
			ValueName   = 'EnableSmartScreen'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
			ValueName   = 'ShellSmartScreenLevel'
			ValueType   = 'String'
			ValueData   = 'Block'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
			ValueName   = 'EnumerateLocalUsers'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableCdp'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
			ValueName   = 'EnableCdp'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\AllowCustomSSPsAPs'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
			ValueName   = 'AllowCustomSSPsAPs'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
			ValueName   = 'BlockUserFromShowingAccountDetailsOnSignin'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
			ValueName   = 'DontEnumerateConnectedUsers'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
			ValueName   = 'DisableLockScreenAppNotifications'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\BlockDomainPicturePassword'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
			ValueName   = 'BlockDomainPicturePassword'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\AllowDomainPINLogon'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
			ValueName   = 'AllowDomainPINLogon'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search'
			ValueName   = 'AllowIndexingEncryptedStoresOrItems'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuildsPolicyValue'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate'
			ValueName   = 'ManagePreviewBuildsPolicyValue'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\BranchReadinessLevel'
		{
			Ensure      = 'Absent'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate'
			ValueName   = 'BranchReadinessLevel'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
			ValueName   = 'NoAutoRebootWithLoggedOnUsers'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
			ValueName   = 'NoAutoUpdate'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
			ValueName   = 'AUOptions'
			ValueType   = 'Dword'
			ValueData   = '4'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AutomaticMaintenanceEnabled'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
			ValueName   = 'AutomaticMaintenanceEnabled'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
			ValueName   = 'ScheduledInstallDay'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallTime'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
			ValueName   = 'ScheduledInstallTime'
			ValueType   = 'Dword'
			ValueData   = '6'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallEveryWeek'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
			ValueName   = 'ScheduledInstallEveryWeek'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallFirstWeek'
		{
			Ensure      = 'Absent'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
			ValueName   = 'ScheduledInstallFirstWeek'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallSecondWeek'
		{
			Ensure      = 'Absent'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
			ValueName   = 'ScheduledInstallSecondWeek'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallThirdWeek'
		{
			Ensure      = 'Absent'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
			ValueName   = 'ScheduledInstallThirdWeek'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallFourthWeek'
		{
			Ensure      = 'Absent'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
			ValueName   = 'ScheduledInstallFourthWeek'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AllowMUUpdateService'
		{
			Ensure      = 'Absent'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
			ValueName   = 'AllowMUUpdateService'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client'
			ValueName   = 'AllowBasic'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client'
			ValueName   = 'AllowUnencryptedTraffic'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client'
			ValueName   = 'AllowDigest'
			ValueType   = 'Dword'
			ValueData   = '0'
		}


		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
		{
			Ensure      = 'Present'  
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
			ValueName   = 'AllowBasic'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
		{
			Ensure      = 'Present'  # You can also set Ensure to 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
			ValueName   = 'AllowUnencryptedTraffic'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
			ValueName   = 'DisableRunAs'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\PUAProtection'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender'
			ValueName   = 'PUAProtection'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender'
			ValueName   = 'DisableAntiSpyware'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine\EnableFileHashComputation'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\MpEngine'
			ValueName   = 'EnableFileHashComputation'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableIOAVProtection'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
			ValueName   = 'DisableIOAVProtection'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
			ValueName   = 'DisableRealtimeMonitoring'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
			ValueName   = 'DisableBehaviorMonitoring'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScriptScanning'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
			ValueName   = 'DisableScriptScanning'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisablePackedExeScanning'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Scan'
			ValueName   = 'DisablePackedExeScanning'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Scan'
			ValueName   = 'DisableRemovableDriveScanning'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Scan'
			ValueName   = 'DisableEmailScanning'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet'
			ValueName   = 'LocalSettingOverrideSpynetReporting'
			ValueType   = 'Dword'
			ValueData   = '0'
		}
		
			Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet'
			ValueName   = 'SpynetReporting'
			ValueType   = 'Dword'
			ValueData   = '2'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
			ValueName   = 'ExploitGuard_ASR_Rules'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\26190899-1602-49e8-8b27-eb1d0a1ce869'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = '26190899-1602-49e8-8b27-eb1d0a1ce869'
			ValueType   = 'String'
			ValueData   = '1'
		}
		
		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\01443614-cd74-433a-b99e-2ecdc07bfc25'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = '01443614-cd74-433a-b99e-2ecdc07bfc25'
			ValueType   = 'String'
			ValueData   = '1'
		}
		
		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\c1db55ab-c21a-4637-bb3f-a12568109d35'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = 'c1db55ab-c21a-4637-bb3f-a12568109d35'
			ValueType   = 'String'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\3b576869-a4ec-4529-8536-b80a7769e899'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = '3b576869-a4ec-4529-8536-b80a7769e899'
			ValueType   = 'String'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\56a863a9-875e-4185-98a7-b882c64b5ce5'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = '56a863a9-875e-4185-98a7-b882c64b5ce5'
			ValueType   = 'String'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\5beb7efe-fd9a-4556-801d-275e5ffc04cc'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
			ValueType   = 'String'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
			ValueType   = 'String'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
			ValueType   = 'String'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
			ValueType   = 'String'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
			ValueType   = 'String'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
			ValueType   = 'String'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
			ValueType   = 'String'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\d3e037e1-3eb8-44c8-a917-57927947596d'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = 'd3e037e1-3eb8-44c8-a917-57927947596d'
			ValueType   = 'String'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\d4f940ab-401b-4efc-aadc-ad5f3c50688a'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
			ValueType   = 'String'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\e6db77e5-3df2-4cf1-b95a-636979351e5b'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
			ValueType   = 'String'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\d1e49aac-8f56-4280-b9ba-993a6d77406c'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
			ValueName   = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
			ValueType   = 'String'
			ValueData   = '2'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
			ValueName   = 'EnableNetworkProtection'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\DisallowExploitProtectionOverride'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'
			ValueName   = 'DisallowExploitProtectionOverride'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers'
			ValueName   = 'DisableWebPnPDownload'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers'
			ValueName   = 'DisableHTTPPrinting'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RedirectionGuardPolicy'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers'
			ValueName   = 'RedirectionGuardPolicy'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\CopyFilesPolicy'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers'
			ValueName   = 'CopyFilesPolicy'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
			ValueName   = 'RestrictDriverInstallationToAdministrators'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\RpcUseNamedPipeProtocol'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\RPC'
			ValueName   = 'RpcUseNamedPipeProtocol'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\RpcAuthentication'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\RPC'
			ValueName   = 'RpcAuthentication'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\RpcProtocols'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\RPC'
			ValueName   = 'RpcProtocols'
			ValueType   = 'Dword'
			ValueData   = '5'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\ForceKerberosForRpc'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\RPC'
			ValueName   = 'ForceKerberosForRpc'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC\RpcTcpPort'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\RPC'
			ValueName   = 'RpcTcpPort'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc'
			ValueName   = 'RestrictRemoteClients'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc'
			ValueName   = 'EnableAuthEpResolution'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'DisablePasswordSaving'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'fDisableCdm'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'fPromptForPassword'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'fEncryptRPCTraffic'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'MinEncryptionLevel'
			ValueType   = 'Dword'
			ValueData   = '3'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'fAllowUnsolicited'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicitedFullControl'
		{
			Ensure      = 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'fAllowUnsolicitedFullControl'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'fAllowToGetHelp'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
		{
			Ensure      = 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'fAllowFullControl'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
		{
			Ensure      = 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'MaxTicketExpiry'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
		{
			Ensure      = 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'MaxTicketExpiryUnits'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
		{
			Ensure      = 'Absent'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'fUseMailto'
			ValueType   = 'String'
			ValueData   = ''
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\SecurityLayer'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'SecurityLayer'
			ValueType   = 'Dword'
			ValueData   = '2'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'UserAuthentication'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'DeleteTempDirsOnExit'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueName   = 'PerSessionTempDir'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PolicyVersion'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall'
			ValueName   = 'PolicyVersion'
			ValueType   = 'Dword'
			ValueData   = '545'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
			ValueName   = 'DisableNotifications'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
			ValueName   = 'EnableFirewall'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
			ValueName   = 'DefaultInboundAction'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
			ValueName   = 'LogFilePath'
			ValueType   = 'String'
			ValueData   = '%systemroot%\system32\logfiles\firewall\pfirewall.log'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
			ValueName   = 'LogFileSize'
			ValueType   = 'Dword'
			ValueData   = '16384'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
			ValueName   = 'LogDroppedPackets'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
			ValueName   = 'LogSuccessfulConnections'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableNotifications'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
			ValueName   = 'DisableNotifications'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
			ValueName   = 'EnableFirewall'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
			ValueName   = 'DefaultInboundAction'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFilePath'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
			ValueName   = 'LogFilePath'
			ValueType   = 'String'
			ValueData   = '%systemroot%\system32\logfiles\firewall\pfirewall.log'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
			ValueName   = 'LogFileSize'
			ValueType   = 'Dword'
			ValueData   = '16384'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
			ValueName   = 'LogDroppedPackets'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
			ValueName   = 'LogSuccessfulConnections'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableNotifications'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
			ValueName   = 'DisableNotifications'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
			ValueName   = 'EnableFirewall'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
			ValueName   = 'DefaultInboundAction'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFilePath'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
			ValueName   = 'LogFilePath'
			ValueType   = 'String'
			ValueData   = '%systemroot%\system32\logfiles\firewall\pfirewall.log'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
			ValueName   = 'LogFileSize'
			ValueType   = 'Dword'
			ValueData   = '16384'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
			ValueName   = 'LogDroppedPackets'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
			ValueName   = 'LogSuccessfulConnections'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsInkWorkspace'
			ValueName   = 'AllowWindowsInkWorkspace'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
			ValueName   = 'UseLogonCredential'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager'
			ValueName   = 'SafeDllSearchMode'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
			ValueName   = 'DriverLoadPolicy'
			ValueType   = 'Dword'
			ValueData   = '3'
		}

		Registry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
			ValueName   = 'WarningLevel'
			ValueType   = 'Dword'
			ValueData   = '90'
		}

		Registry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
			ValueName   = 'SMB1'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MrxSmb10'
			ValueName   = 'Start'
			ValueType   = 'Dword'
			ValueData   = '4'
		}

		Registry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
			ValueName   = 'NoNameReleaseOnDemand'
			ValueType   = 'Dword'
			ValueData   = '1'
		}

		Registry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NodeType'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
			ValueName   = 'NodeType'
			ValueType   = 'Dword'
			ValueData   = '2'
		}

		Registry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
			ValueName   = 'DisableIPSourceRouting'
			ValueType   = 'Dword'
			ValueData   = '2'
		}

		Registry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
			ValueName   = 'EnableICMPRedirect'
			ValueType   = 'Dword'
			ValueData   = '0'
		}

		Registry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
		{
			Ensure      = 'Present'
			Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
			ValueName   = 'DisableIPSourceRouting'
			ValueType   = 'Dword'
			ValueData   = '2'
		}

          AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
         {
              Name = 'Credential Validation'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
         {
              Name = 'Credential Validation'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Application Group Management (Success) - Inclusion'
         {
              Name = 'Application Group Management'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Application Group Management (Failure) - Inclusion'
         {
              Name = 'Application Group Management'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
         {
              Name = 'Other Account Management Events'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Other Account Management Events (Failure) - Inclusion'
         {
              Name = 'Other Account Management Events'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
         {
              Name = 'Security Group Management'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
         {
              Name = 'Security Group Management'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
         {
              Name = 'User Account Management'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
         {
              Name = 'User Account Management'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
         {
              Name = 'Plug and Play Events'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
         {
              Name = 'Plug and Play Events'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
         {
              Name = 'Process Creation'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
         {
              Name = 'Process Creation'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
         {
              Name = 'Account Lockout'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

          AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
         {
              Name = 'Account Lockout'
              Ensure = 'Absent'
              AuditFlag = 'Success'
         }

         AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
         {
              Name = 'Group Membership'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
         {
              Name = 'Group Membership'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
         {
              Name = 'Logoff'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
         {
              Name = 'Logoff'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
         {
              Name = 'Logon'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
         {
              Name = 'Logon'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success) - Inclusion'
         {
              Name = 'Other Logon/Logoff Events'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure) - Inclusion'
         {
              Name = 'Other Logon/Logoff Events'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
         {
              Name = 'Special Logon'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
         {
              Name = 'Special Logon'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Detailed File Share (Failure) - Inclusion'
         {
              Name = 'Detailed File Share'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

          AuditPolicySubcategory 'Audit Detailed File Share (Success) - Inclusion'
         {
              Name = 'Detailed File Share'
              Ensure = 'Absent'
              AuditFlag = 'Success'
         }

         AuditPolicySubcategory 'Audit File Share (Failure) - Inclusion'
         {
              Name = 'File Share'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

          AuditPolicySubcategory 'Audit File Share (Success) - Inclusion'
         {
              Name = 'File Share'
              Ensure = 'Absent'
              AuditFlag = 'Success'
         }

         AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
         {
              Name = 'Other Object Access Events'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
         {
              Name = 'Other Object Access Events'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
         {
              Name = 'Removable Storage'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
         {
              Name = 'Removable Storage'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
         {
              Name = 'Audit Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
         {
              Name = 'Audit Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
         {
              Name = 'Authentication Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
         {
              Name = 'Authentication Policy Change'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
         {
              Name = 'Authorization Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
         {
              Name = 'Authorization Policy Change'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success) - Inclusion'
         {
              Name = 'MPSSVC Rule-Level Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure) - Inclusion'
         {
              Name = 'MPSSVC Rule-Level Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Other Policy Change Events (Failure) - Inclusion'
         {
              Name = 'Other Policy Change Events'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

          AuditPolicySubcategory 'Audit Other Policy Change Events (Success) - Inclusion'
         {
              Name = 'Other Policy Change Events'
              Ensure = 'Absent'
              AuditFlag = 'Success'
         }

         AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
         {
              Name = 'Sensitive Privilege Use'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
         {
              Name = 'Sensitive Privilege Use'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
         {
              Name = 'IPsec Driver'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
         {
              Name = 'IPsec Driver'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
         {
              Name = 'Other System Events'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
         {
              Name = 'Other System Events'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
         {
              Name = 'Security State Change'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
         {
              Name = 'Security State Change'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
         {
              Name = 'Security System Extension'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
         {
              Name = 'Security System Extension'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
         {
              Name = 'System Integrity'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
         {
              Name = 'System Integrity'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
         {
              Policy = 'Load_and_unload_device_drivers'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
         {
              Policy = 'Impersonate_a_client_after_authentication'
              Force = $True
              Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Change_the_system_time'
         {
              Policy = 'Change_the_system_time'
              Force = $True
              Identity = @('*S-1-5-19', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
         {
              Policy = 'Take_ownership_of_files_or_other_objects'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
         {
              Policy = 'Deny_log_on_locally'
              Force = $True
              Identity = @('*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
         {
              Policy = 'Deny_log_on_as_a_batch_job'
              Force = $True
              Identity = @('*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
         {
              Policy = 'Back_up_files_and_directories'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Modify_an_object_label'
         {
              Policy = 'Modify_an_object_label'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
         {
              Policy = 'Create_symbolic_links'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
         {
              Policy = 'Manage_auditing_and_security_log'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
         {
              Policy = 'Debug_programs'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
         {
              Policy = 'Lock_pages_in_memory'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
         {
              Policy = 'Increase_scheduling_priority'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Shut_down_the_system'
         {
              Policy = 'Shut_down_the_system'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Change_the_time_zone'
         {
              Policy = 'Change_the_time_zone'
              Force = $True
              Identity = @('*S-1-5-19', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
         {
              Policy = 'Profile_single_process'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
         {
              Policy = 'Allow_log_on_locally'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
         {
              Policy = 'Create_a_pagefile'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
         {
              Policy = 'Restore_files_and_directories'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
         {
              Policy = 'Create_a_token_object'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
         {
              Policy = 'Create_permanent_shared_objects'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
         {
              Policy = 'Create_global_objects'
              Force = $True
              Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Adjust_memory_quotas_for_a_process'
         {
              Policy = 'Adjust_memory_quotas_for_a_process'
              Force = $True
              Identity = @('*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
         {
              Policy = 'Deny_log_on_as_a_service'
              Force = $True
              Identity = @('*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Replace_a_process_level_token'
         {
              Policy = 'Replace_a_process_level_token'
              Force = $True
              Identity = @('*S-1-5-20', '*S-1-5-19')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
         {
              Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
         {
              Policy = 'Force_shutdown_from_a_remote_system'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
         {
              Policy = 'Perform_volume_maintenance_tasks'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
         {
              Policy = 'Act_as_part_of_the_operating_system'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
         {
              Policy = 'Generate_security_audits'
              Force = $True
              Identity = @('*S-1-5-20', '*S-1-5-19')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
         {
              Policy = 'Access_Credential_Manager_as_a_trusted_caller'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
         {
              Policy = 'Modify_firmware_environment_values'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         SecurityOption 'SecuritySetting(INF): NewGuestName'
         {
              Accounts_Rename_guest_account = 'Visitor'
              Name = 'Accounts_Rename_guest_account'
         }

         AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
         {
              Name = 'Enforce_password_history'
              Enforce_password_history = 24
         }

         AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
         {
              Name = 'Minimum_Password_Length'
              Minimum_Password_Length = 14
         }

         AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
         {
              Minimum_Password_Age = 1
              Name = 'Minimum_Password_Age'
         }

         SecurityOption 'SecuritySetting(INF): ForceLogoffWhenHourExpire'
         {
              Name = 'Network_security_Force_logoff_when_logon_hours_expire'
              Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'
         }

         SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
         {
              Name = 'Network_access_Allow_anonymous_SID_Name_translation'
              Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
         }

         AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
         {
              Reset_account_lockout_counter_after = 15
              Name = 'Reset_account_lockout_counter_after'
         }

         AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
         {
              Name = 'Maximum_Password_Age'
              Maximum_Password_Age = 60
         }

         AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
         {
              Name = 'Store_passwords_using_reversible_encryption'
              Store_passwords_using_reversible_encryption = 'Disabled'
         }

         AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
         {
              Name = 'Account_lockout_threshold'
              Account_lockout_threshold = 3
         }

         AccountPolicy 'SecuritySetting(INF): LockoutDuration'
         {
              Name = 'Account_lockout_duration'
              Account_lockout_duration = 15
         }

         SecurityOption 'SecuritySetting(INF): NewAdministratorName'
         {
              Accounts_Rename_administrator_account = 'X_Admin'
              Name = 'Accounts_Rename_administrator_account'
         }

         SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
         {
              Accounts_Guest_account_status = 'Disabled'
              Name = 'Accounts_Guest_account_status'
         }

         AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
         {
              Name = 'Password_must_meet_complexity_requirements'
              Password_must_meet_complexity_requirements = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
         {
              Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
              Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
         {
              Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
              Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
         {
              Name = 'Interactive_logon_Smart_card_removal_behavior'
              Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
         {
              User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
              Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
         {
              Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
              Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Prompt_user_to_change_password_before_expiration'
         {
              Name = 'Interactive_logon_Prompt_user_to_change_password_before_expiration'
              Interactive_logon_Prompt_user_to_change_password_before_expiration = '14'
         }

         SecurityOption 'SecurityRegistry(INF): Audit_Shut_down_system_immediately_if_unable_to_log_security_audits'
         {
              Name = 'Audit_Shut_down_system_immediately_if_unable_to_log_security_audits'
              Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
         {
              System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
              Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
         {
              User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
              Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
         {
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
         {
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
         }

         SecurityOption 'SecurityRegistry(INF): System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
         {
              System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled'
              Name = 'System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
         {
              Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
              Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
         {
              User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
              Name = 'User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
         }

         SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
         {
              Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
              Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
         {
              Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
              Interactive_logon_Message_title_for_users_attempting_to_log_on = 'MS Amlin Assurance Warning Statement'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
         {
              Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
              Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
         {
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
         {
              Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
              Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
         {
              Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
              Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
         {
              Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
              Name = 'Network_security_LAN_Manager_authentication_level'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_display_last_user_name'
         {
              Interactive_logon_Do_not_display_last_user_name = 'Enabled'
              Name = 'Interactive_logon_Do_not_display_last_user_name'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
         {
              Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
         {
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
         }

         SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
         {
              Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
              Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Sharing_and_security_model_for_local_accounts'
         {
              Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'
              Name = 'Network_access_Sharing_and_security_model_for_local_accounts'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
         {
              Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
              Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
         {
              Name = 'Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
              Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
         {
              Name = 'Microsoft_network_server_Digitally_sign_communications_always'
              Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
         {
              Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_always'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_require_CTRL_ALT_DEL'
         {
              Name = 'Interactive_logon_Do_not_require_CTRL_ALT_DEL'
              Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
         {
              Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
              Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Accounts_Block_Microsoft_accounts'
         {
              Accounts_Block_Microsoft_accounts = 'Users cant add or log on with Microsoft accounts'
              Name = 'Accounts_Block_Microsoft_accounts'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
         {
              Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
              User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
         {
              Name = 'Network_security_LDAP_client_signing_requirements'
              Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
         {
              Name = 'Domain_member_Maximum_machine_account_password_age'
              Domain_member_Maximum_machine_account_password_age = '30'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
         {
              Name = 'Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
              Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
         {
              Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
              User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
         {
              System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
              Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
         }

         SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
         {
              Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
              Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
         {
              Name = 'Domain_member_Disable_machine_account_password_changes'
              Domain_member_Disable_machine_account_password_changes = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
         {
              Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
              User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
         {
              Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
              Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
         {
              Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
              Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a MS Amlin Assurance Information System (IS) that is provided for employees only.,By using this IS (which includes any device attached to this IS)"," you consent to the following conditions:,-The IT staff routinely intercepts and monitors communications on this IS for purposes including"," but not limited to"," penetration testing"," COMSEC monitoring"," network operations and defense"," personnel misconduct (PM)"," law enforcement (LE)"," and counterintelligence (CI) investigations.,-At any time"," the IT Staff may inspect and seize data stored on this IS.,-Communications using"," or data stored on"," this IS are not private"," are subject to routine monitoring"," interception"," and search"," and may be disclosed or used for any purpose.,-This IS includes security measures (e.g."," authentication and access controls) to protect interests--not for your personal benefit or privacy.,-Notwithstanding the above"," using this IS does not constitute consent to PM"," LE or CI investigative searching or monitoring of the content of privileged communications"," or work product"," related to personal representation or services by attorneys"," psychotherapists"," or clergy"," and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
         {
              Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
              Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
         {
              Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled'
              Name = 'Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
         }

         SecurityOption 'SecurityRegistry(INF): Devices_Prevent_users_from_installing_printer_drivers'
         {
              Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'
              Name = 'Devices_Prevent_users_from_installing_printer_drivers'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
         {
              Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
              Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
         {
              Interactive_logon_Machine_inactivity_limit = '900'
              Name = 'Interactive_logon_Machine_inactivity_limit'
         }
     }
}
DSCforDefaultSecurityBaseline -OutputPath 'C:\Users\Administrator\Output'
