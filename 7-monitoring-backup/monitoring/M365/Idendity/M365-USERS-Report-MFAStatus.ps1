Param (
    [Parameter(Mandatory = $false)]
    [switch]$PrivacyFlag,  # Must be true to output minimal MFA data. This is the default. If you want to see full MFA data in the report, set to $true
    
	[Parameter(Mandatory=$false)]
    [String]$Customer,
    
	[Parameter(Mandatory=$false)]
    [String]$TenantID,
	
    [Parameter(Mandatory=$false)]
    [String]$AppID,
    
    [Parameter(Mandatory=$false)]
    [String]$CertificateThumbprint
)
# ReportMFAStatusUsers.
 
# Connect to the Microsoft Graph SDK for PowerShell
Connect-MgGraph -ClientId $AppId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint

# Get user accounts (exclude guests)
Write-Host "Looking for Entra ID user accounts to check"
[array]$Users = Get-MgUser -All -Filter "UserType eq 'Member'"

If (!($Users)) { Write-Host "No accounts found for some reason... exiting" ; break}
    Else { Write-Host ("{0} Entra ID member accounts found (not all are user accounts which authenticate)" -f $Users.count ) }
$CheckedUsers = 0
$Report = [System.Collections.Generic.List[Object]]::new()
ForEach ($User in $Users) {
      # Try and find a sign in record for the user - this eliminates unused accounts 
      # Write-Host "Checking" $User.DisplayName
      [array]$LastSignIn = Get-MgAuditLogSignIn -Filter "UserId eq '$($User.Id)'" -Top 1
      If ($LastSignIn) {
            $CheckedUsers++
            Write-Host "Sign in found - checking authentication methods for" $User.DisplayName
            [array]$MfaData = Get-MgUserAuthenticationMethod -UserId $User.Id 
            # Process each of the authentication methods found for an account
            ForEach ($MfaMethod in $MfaData) {   
                  Switch ($MfaMethod.AdditionalProperties["@odata.type"]) {
                  "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"  { # Microsoft Authenticator App
                  $AuthType     = 'AuthenticatorApp'
                  $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] } 
                  "#microsoft.graph.phoneAuthenticationMethod"                  { # Phone authentication
                  $AuthType     = 'PhoneAuthentication'
                  $AuthTypeDetails = $MfaMethod.AdditionalProperties["phoneType", "phoneNumber"] -join ' '  } 
                  "#microsoft.graph.fido2AuthenticationMethod"                   { # FIDO2 key
                  $AuthType     = 'Fido2'
                  $AuthTypeDetails = $MfaMethod.AdditionalProperties["model"] }  
                  "#microsoft.graph.passwordAuthenticationMethod"                { # Password
                  $AuthType     = 'PasswordAuthentication'
                  $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] } 
                  "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" { # Windows Hello
                  $AuthType     = 'WindowsHelloForBusiness'
                  $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] }                        
                  "#microsoft.graph.emailAuthenticationMethod"                   { # Email Authentication
                  $AuthType     = 'EmailAuthentication'
                  $AuthTypeDetails = $MfaMethod.AdditionalProperties["emailAddress"] }               
                  "microsoft.graph.temporaryAccessPassAuthenticationMethod"    { # Temporary Access pass
                  $AuthType     = 'TemporaryAccessPass'
                  $AuthTypeDetails = 'Access pass lifetime (minutes): ' + $MfaMethod.AdditionalProperties["lifetimeInMinutes"] }
                  "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod" { # Passwordless
                  $AuthType     = 'Passwordless'
                  $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] }     
                  "#microsoft.graph.softwareOathAuthenticationMethod" { # Software Authenticator App
                  $AuthType = 'Third-party Authenticator App'
                  $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] }
                  } # End switch 
            # Note what we found
            $ReportLine  = [PSCustomObject][Ordered]@{
                  User            = $User.DisplayName
                  UPN             = $User.UserPrincipalName 
                  Method          = $AuthType
                  Details         = $AuthTypeDetails
                  LastSignIn      = $LastSignIn.CreatedDateTime
                  LastSignInApp   = $LastSignIn.AppDisplayName}
            $Report.Add($ReportLine) 
            } #End Foreach MfaMethod
      } # End if
} # End ForEach Users

# Take the report file and check each user to see if they use a strong authentication method 
$OutputFile = [System.Collections.Generic.List[Object]]::new()
[array]$AuthUsers = $Report | Sort-Object UPN -Unique | Select-Object UPN, User, LastSignIn, LastSignInApp
ForEach ($AuthUser in $AuthUsers) {
    $MFAStatus = $Null
    $Records = $Report | Where-Object {$_.UPN -eq $AuthUser.UPN}
    $Methods = $Records.Method | Sort-Object -Unique
    Switch ($Methods) {
      "Fido2"               { $MFAStatus = "Good" }
      "PhoneAuthentication" { $MFAStatus = "Good" }
      "AuthenticatorApp"    { $MFAStatus = "Good" }
      "Passwordless"        { $MFAStatus = "Good" }
       Default              { $MFAStatus = "Check!" }
    } # End Switch
    $ReportLine  = [PSCustomObject][Ordered]@{
         User            = $AuthUser.User
         UPN             = $AuthUser.UPN
         Methods         = $Methods -Join ", "
         MFAStatus       = $MFAStatus
          LastSignIn      = $AuthUser.LastSignIn
         LastSignInApp   = $AuthUser.LastSignInApp }
    $OutputFile.Add($ReportLine) 
} 
   
$OutputFile | ConvertTo-Json -Depth 10 | Out-File -FilePath "F:\HealthChecks\$Customer\M365\entraid-mfa-status.json"
