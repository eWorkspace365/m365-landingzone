[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [String]$AADClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$AADThumbprint,
  
    [Parameter(Mandatory=$false)]
    [String]$EXOMailFrom,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOMailTo,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOThumbprint,
    
    [Parameter(Mandatory=$false)]
    [String]$OrganizationDomain,
    
    [Parameter(Mandatory=$true)]
    [String]$CustomerID
)

# Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor DarkGray
Connect-MgGraph -ClientId $AADClientId -TenantId $TenantId -CertificateThumbprint $AADThumbprint

# Placeholder for compliance results
$outputObj = New-Object PSObject

# Compliance Check: 5.1.3.1 Ensure a dynamic group for guest users is created

Write-Host "Checking dynamic group for guest users..." -ForegroundColor DarkGray
try {
    $dynamicGroups = Get-MgGroup | Where-Object { $_.GroupTypes -contains "DynamicMembership" }
    $guestGroup = $dynamicGroups | Where-Object { $_.MembershipRule -like "*Guest*" }

    if (!$guestGroup) {
        $outputObj | Add-Member -MemberType NoteProperty -Name "RESULT-CHECK" -Value "&#x274C;" -Force
    } else {
        $outputObj | Add-Member -MemberType NoteProperty -Name "RESULT-CHECK" -Value "&#x2705;" -Force
    }
} catch {
    Write-Host "Error checking dynamic group for guest users: $_" -ForegroundColor Red
}

# Compliance Check: 5.1.3.1 Ensure a dynamic group for guest users is created

Write-Host "Checking dynamic group for guest users..." -ForegroundColor DarkGray
try {
    $dynamicGroups = Get-MgGroup | Where-Object { $_.GroupTypes -contains "DynamicMembership" }
    $guestGroup = $dynamicGroups | Where-Object { $_.MembershipRule -like "*qwert*" }

    if (!$guestGroup) {
        $outputObj | Add-Member -MemberType NoteProperty -Name "test" -Value "&#x274C;" -Force
    } else {
        $outputObj | Add-Member -MemberType NoteProperty -Name "test" -Value "&#x2705;" -Force
    }
} catch {
    Write-Host "Error checking dynamic group for guest users: $_" -ForegroundColor Red
}





# Secure Score Results
Write-Host "Retrieving secure score results..." -ForegroundColor DarkGray
try {
    $getYesterday = Get-Date((Get-Date).AddDays(-1)) -Format "yyyy-MM-dd"
    $getTime = "T18:09:31Z"
    $combineTime = $getYesterday + $getTime

    $url = "https://graph.microsoft.com/beta/security/secureScores?`$filter=createdDateTime ge $combineTime"
    $secureScoreResponse = Invoke-MgGraphRequest -Uri $url -Method Get

    # Save secure score results to file
    $secureScoreDumpFile = "C:\SecureScoreDump.json"
    $secureScoreResponse | ConvertTo-Json -Depth 100 | Out-File -FilePath $secureScoreDumpFile
} catch {
    Write-Host "Error retrieving secure score: $_" -ForegroundColor Red
}

# Compliance Checks Based on Secure Score Dump
Write-Host "Processing secure score dump for compliance checks..." -ForegroundColor DarkGray

function CheckSecureScore {
    param (
        [string]$Pattern,
        [string]$PropertyName
    )
    try {
        $getSpecificLine = Select-String -Pattern $Pattern -Path $secureScoreDumpFile | Select-Object -ExpandProperty LineNumber
        $getValue = (Get-Content -Path $secureScoreDumpFile) | Where-Object { $_.ReadCount -notin (0..$getSpecificLine) }
        $getValueLineTill = $getValue | Select-Object -First 11
        $getRequiredValue = $getValueLineTill -match '\bscoreInPercentage\b'

        if ($getRequiredValue -like "*100*") {
            $outputObj | Add-Member -MemberType NoteProperty -Name $PropertyName -Value "&#x2705;" -Force
        } else {
            $outputObj | Add-Member -MemberType NoteProperty -Name $PropertyName -Value "&#x274C;" -Force
        }
    } catch {
        Write-Host 'Error processing $PropertyName: $_' -ForegroundColor Red
    }
}

# Secure Score Properties
CheckSecureScore -Pattern "AdminMFAV2" -PropertyName "5.1.1.1 Ensure Security Defaults is disabled"
CheckSecureScore -Pattern "MFARegistrationV2" -PropertyName "5.1.2.1 Ensure 'Per-user MFA' is disabled"
CheckSecureScore -Pattern "OneAdmin" -PropertyName "5.1.2.2 Ensure third-party integrated applications are not allowed"
CheckSecureScore -Pattern "SelfServicePasswordReset" -PropertyName "5.1.2.3 Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'"
CheckSecureScore -Pattern "BlockLegacyAuthentication" -PropertyName "5.1.2.4 Ensure access to the Entra admin center is restricted"
CheckSecureScore -Pattern "PWAgePolicyNew" -PropertyName "5.1.2.5 Ensure the option to remain signed in is hidden"
CheckSecureScore -Pattern "aad_admin_consent_workflow" -PropertyName "5.1.2.6 Ensure 'LinkedIn account connections' is disabled"
CheckSecureScore -Pattern "aad_sign_in_freq_session_timeout" -PropertyName "5.1.5.1 Ensure user consent to apps accessing company data on their behalf is not allowed"
CheckSecureScore -Pattern "aad_third_party_apps" -PropertyName "5.1.5.2 Ensure the admin consent workflow is enabled"




# Building HTML Report
Write-Host "Building HTML report..." -ForegroundColor DarkGray
$htmlContent = "<!DOCTYPE html>
<html>
<head>
    <title>CIS Microsoft 365 Foundations Benchmark v4.0</title>
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: left;
            vertical-align: top; /* Ensures text is aligned to the top */
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
    </style>
</head>
<body>
<h1>CIS Compliance Report</h1>
<h2>Appendix: Summary Table</h2>
<table>"

# 1. Microsoft 365 Admin Center
$htmlContent += "
<tr>
    <th>1. Microsoft 365 Admin Center</th>
    <th>Category</th>
    <th>CIS Benchmark Recommendation</th>
    <th>Result</th>
</tr>
<tr>
    <td></td>
    <td>1.1 Users</td>
    <td>
        1.1.1 (L1) Ensure Administrative accounts are cloud-only<br>
        1.1.2 (L1) Ensure two emergency access accounts have been defined<br>
        1.1.3 (L1) Ensure that between two and four global admins are designated<br>
        1.1.4 (L1) Ensure administrative accounts use licenses with a reduced application footprint
    </td>
    <td>
    $($outputObj."RESULT-CHECK")<br>
    $($outputObj."RESULT-CHECK")<br>
    $($outputObj."RESULT-CHECK")<br>
    $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>1.2 Teams & Groups</td>
    <td>
        1.2.1 (L2) Ensure that only organizationally managed/approved public groups exist<br>
        1.2.2 (L1) Ensure sign-in to shared mailboxes is blocked
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>1.3 Settings</td>
    <td>
        1.3.1 (L1) Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)'<br>
        1.3.2 (L1) Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices<br>
        1.3.3 (L2) Ensure 'External sharing' of calendars is not available<br>
        1.3.4 (L1) Ensure 'User owned apps and services' is restricted<br>
        1.3.5 (L1) Ensure internal phishing protection for Forms is enabled<br>
        1.3.6 (L2) Ensure the customer lockbox feature is enabled<br>
        1.3.7 (L2) Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web'<br>
        1.3.8 (L2) Ensure that Sways cannot be shared with people outside of your organization
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>"

# 2. Microsoft 365 Defender
$htmlContent += "
<tr>
    <th>2. Microsoft 365 Defender</th>
    <th>Category</th>
    <th>CIS Benchmark Recommendation</th>
    <th>Result</th>
</tr>
<tr>
    <td></td>
    <td>2.1 Email & Collaboration</td>
    <td>
        2.1.1 (L2) Ensure Safe Links for Office Applications is Enabled<br>
        2.1.2 (L1) Ensure the Common Attachment Types Filter is enabled<br>
        2.1.3 (L1) Ensure notifications for internal users sending malware is Enabled<br>
        2.1.4 (L2) Ensure Safe Attachments policy is enabled<br>
        2.1.5 (L2) Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled<br>
        2.1.6 (L1) Ensure Exchange Online Spam Policies are set to notify administrators<br>
        2.1.7 (L2) Ensure that an anti-phishing policy has been created<br>
        2.1.8 (L1) Ensure that SPF records are published for all Exchange Domains<br>
        2.1.9 (L1) Ensure that DKIM is enabled for all Exchange Online Domains<br>
        2.1.10 (L1) Ensure DMARC Records for all Exchange Online domains are published<br>
        2.1.11 (L2) Ensure comprehensive attachment filtering is applied<br>
        2.1.12 (L1) Ensure the connection filter IP allow list is not used<br>
        2.1.13 (L1) Ensure the connection filter safe list is off<br>
        2.1.14 (L1) Ensure inbound anti-spam policies do not contain allowed domains
    </td>
    <td>
        $($outputObj."test")<br>
        $($outputObj."test")<br>
        $($outputObj."test")<br>
        $($outputObj."5.1.1.1 Ensure Security Defaults is disabled")<br>
        $($outputObj."5.1.1.1 Ensure Security Defaults is disabled")<br>
        $($outputObj."5.1.1.1 Ensure Security Defaults is disabled")<br>
        $($outputObj."5.1.1.1 Ensure Security Defaults is disabled")<br>
        $($outputObj."5.1.1.1 Ensure Security Defaults is disabled")<br>
        $($outputObj."5.1.1.1 Ensure Security Defaults is disabled")<br>
        $($outputObj."5.1.1.1 Ensure Security Defaults is disabled")<br>
        $($outputObj."5.1.1.1 Ensure Security Defaults is disabled")<br>
        $($outputObj."5.1.1.1 Ensure Security Defaults is disabled")<br>
        $($outputObj."5.1.1.1 Ensure Security Defaults is disabled")<br>
        $($outputObj."5.1.1.1 Ensure Security Defaults is disabled")
    </td>
</tr>"

# 3. Microsoft Purview
$htmlContent += "
<tr>
    <th>3. Microsoft Purview</th>
    <th>Category</th>
    <th>CIS Benchmark Recommendation</th>
    <th>Result</th>
</tr>
<tr>
    <td></td>
    <td>3.1 Audit</td>
    <td>
        3.1.1 (L1) Ensure Microsoft 365 audit log search is Enabled
    </td>
    <td>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>3.2 Data Loss Protection</td>
    <td>
        3.2.1 (L1) Ensure DLP policies are enabled<br>
        3.2.2 (L1) Ensure DLP policies are enabled for Microsoft Teams
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>3.3 Information Protection</td>
    <td>
        3.3.1 (L1) Ensure SharePoint Online Information Protection policies are set up and used
    </td>
    <td>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>"

# 4. Microsoft Intune
$htmlContent += "
<tr>
    <th>4. Microsoft Intune</th>
    <th>Category</th>
    <th>CIS Benchmark Recommendation</th>
    <th>Result</th>
</tr>
<tr>
    <td></td>
    <td>No specific controls listed</td>
    <td>
        No recommendations available for this category.
    </td>
    <td>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>"

# 5. Microsoft Entra Admin Center
$htmlContent += "
<tr>
    <th>5. Microsoft Entra Admin Center</th>
    <th>Category</th>
    <th>CIS Benchmark Recommendation</th>
    <th>Result</th>
</tr>
<tr>
    <td></td>
    <td>5.1 Users</td>
    <td>
        5.1.1.1 (L1) Ensure Security Defaults is disabled<br>
        5.1.2.1 (L1) Ensure 'Per-user MFA' is disabled<br>
        5.1.2.2 (L2) Ensure third-party integrated applications are not allowed<br>
        5.1.2.3 (L1) Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'<br>
        5.1.2.4 (L1) Ensure access to the Entra admin center is restricted<br>
        5.1.2.5 (L2) Ensure the option to remain signed in is hidden<br>
        5.1.2.6 (L2) Ensure 'LinkedIn account connections' is disabled
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>5.1 Groups</td>
    <td>
        5.1.3.1 (L1) Ensure a dynamic group for guest users is created
    </td>
    <td>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>5.1 Devices</td>
    <td>
        5.1.5.1 (L2) Ensure user consent to apps accessing company data on their behalf is not allowed<br>
        5.1.5.2 (L1) Ensure the admin consent workflow is enabled
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>5.1 External Identities</td>
    <td>
        5.1.6.1 (L2) Ensure that collaboration invitations are sent to allowed domains only<br>
        5.1.6.2 (L1) Ensure that guest user access is restricted<br>
        5.1.6.3 (L2) Ensure guest user invitations are limited to the Guest Inviter role
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>5.1 Hybrid Management</td>
    <td>
        5.1.8.1 (L1) Ensure that password hash sync is enabled for hybrid deployments
    </td>
    <td>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>5.2 Conditional Access</td>
    <td>
        5.2.2.1 (L1) Ensure multifactor authentication is enabled for all users in administrative roles<br>
        5.2.2.2 (L1) Ensure multifactor authentication is enabled for all users<br>
        5.2.2.3 (L1) Enable Conditional Access policies to block legacy authentication<br>
        5.2.2.4 (L1) Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users<br>
        5.2.2.5 (L2) Ensure 'Phishing-resistant MFA strength' is required for Administrators<br>
        5.2.2.6 (L1) Enable Identity Protection user risk policies<br>
        5.2.2.7 (L1) Enable Identity Protection sign-in risk policies<br>
        5.2.2.8 (L2) Ensure admin center access is limited to administrative roles<br>
        5.2.2.9 (L2) Ensure 'sign-in risk' is blocked for medium and high risk<br>
        5.2.2.10 (L1) Ensure a managed device is required for authentication<br>
        5.2.2.11 (L1) Ensure a managed device is required for MFA registration
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>5.2 Authentication Methods</td>
    <td>
        5.2.3.1 (L1) Ensure Microsoft Authenticator is configured to protect against MFA fatigue<br>
        5.2.3.2 (L1) Ensure custom banned passwords lists are used<br>
        5.2.3.3 (L1) Ensure password protection is enabled for on-prem Active Directory<br>
        5.2.3.4 (L1) Ensure all member users are 'MFA capable'<br>
        5.2.3.5 (L1) Ensure weak authentication methods are disabled
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>5.2 Password Reset</td>
    <td>
        5.2.4.1 (L1) Ensure 'Self service password reset enabled' is set to 'All'
    </td>
    <td>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>5.3 Identity Governance</td>
    <td>
        5.3.1 (L2) Ensure 'Privileged Identity Management' is used to manage roles<br>
        5.3.2 (L1) Ensure 'Access reviews' for Guest Users are configured<br>
        5.3.3 (L1) Ensure 'Access reviews' for privileged roles are configured<br>
        5.3.4 (L1) Ensure approval is required for Global Administrator role activation
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>"

# 6. Exchange Admin Center
$htmlContent += "
<tr>
    <th>6. Exchange Admin Center</th>
    <th>Category</th>
    <th>CIS Benchmark Recommendation</th>
    <th>Result</th>
</tr>
<tr>
    <td></td>
    <td>6.1 Audit</td>
    <td>
        6.1.1 (L1) Ensure 'AuditDisabled' organizationally is set to 'False'<br>
        6.1.2 (L1) Ensure mailbox auditing for E3 users is Enabled<br>
        6.1.3 (L1) Ensure mailbox auditing for E5 users is Enabled<br>
        6.1.4 (L1) Ensure 'AuditBypassEnabled' is not enabled on mailboxes
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>6.2 Mail Flow</td>
    <td>
        6.2.1 (L1) Ensure all forms of mail forwarding are blocked and/or disabled<br>
        6.2.2 (L1) Ensure mail transport rules do not whitelist specific domains<br>
        6.2.3 (L1) Ensure email from external senders is identified
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>6.3 Roles</td>
    <td>
        6.3.1 (L2) Ensure users installing Outlook add-ins is not allowed
    </td>
    <td>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>6.5 Settings</td>
    <td>
        6.5.1 (L1) Ensure modern authentication for Exchange Online is enabled<br>
        6.5.2 (L1) Ensure MailTips are enabled for end users<br>
        6.5.3 (L2) Ensure additional storage providers are restricted in Outlook on the web<br>
        6.5.4 (L1) Ensure SMTP AUTH is disabled
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>"

# 7. SharePoint Admin Center
$htmlContent += "
<tr>
    <th>7. SharePoint Admin Center</th>
    <th>Category</th>
    <th>CIS Benchmark Recommendation</th>
    <th>Result</th>
</tr>
<tr>
    <td></td>
    <td>7.2 Policies</td>
    <td>
        7.2.1 (L1) Ensure modern authentication for SharePoint applications is required<br>
        7.2.2 (L1) Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled<br>
        7.2.3 (L1) Ensure external content sharing is restricted<br>
        7.2.4 (L2) Ensure OneDrive content sharing is restricted<br>
        7.2.5 (L2) Ensure that SharePoint guest users cannot share items they don't own<br>
        7.2.6 (L2) Ensure SharePoint external sharing is managed through domain whitelist/blacklists<br>
        7.2.7 (L1) Ensure link sharing is restricted in SharePoint and OneDrive<br>
        7.2.8 (L2) Ensure external sharing is restricted by security group<br>
        7.2.9 (L1) Ensure guest access to a site or OneDrive will expire automatically<br>
        7.2.10 (L1) Ensure reauthentication with verification code is restricted<br>
        7.2.11 (L1) Ensure the SharePoint default sharing link permission is set
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>7.3 Settings</td>
    <td>
        7.3.1 (L2) Ensure Office 365 SharePoint infected files are disallowed for download<br>
        7.3.2 (L2) Ensure OneDrive sync is restricted for unmanaged devices<br>
        7.3.3 (L1) Ensure custom script execution is restricted on personal sites<br>
        7.3.4 (L1) Ensure custom script execution is restricted on site collections
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>"

# 8. Microsoft Teams Admin Center
$htmlContent += "
<tr>
    <th>8. Microsoft Teams Admin Center</th>
    <th>Category</th>
    <th>CIS Benchmark Recommendation</th>
    <th>Result</th>
</tr>
<tr>
    <td></td>
    <td>8.1 Teams</td>
    <td>
        8.1.1 (L2) Ensure external file sharing in Teams is enabled for only approved cloud storage services<br>
        8.1.2 (L1) Ensure users can't send emails to a channel email address
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>8.2 Users</td>
    <td>
        8.2.1 (L2) Ensure external domains are restricted in the Teams admin center<br>
        8.2.2 (L1) Ensure communication with unmanaged Teams users is disabled<br>
        8.2.3 (L1) Ensure external Teams users cannot initiate conversations<br>
        8.2.4 (L1) Ensure communication with Skype users is disabled
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>8.4 Teams Apps</td>
    <td>
        8.4.1 (L1) Ensure app permission policies are configured
    </td>
    <td>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>8.5 Meetings</td>
    <td>
        8.5.1 (L2) Ensure anonymous users can't join a meeting<br>
        8.5.2 (L1) Ensure anonymous users and dial-in callers can't start a meeting<br>
        8.5.3 (L1) Ensure only people in my org can bypass the lobby<br>
        8.5.4 (L1) Ensure users dialing in can't bypass the lobby<br>
        8.5.5 (L2) Ensure meeting chat does not allow anonymous users<br>
        8.5.6 (L2) Ensure only organizers and co-organizers can present<br>
        8.5.7 (L1) Ensure external participants can't give or request control<br>
        8.5.8 (L2) Ensure external meeting chat is off<br>
        8.5.9 (L2) Ensure meeting recording is off by default
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>
<tr>
    <td></td>
    <td>8.6 Messaging</td>
    <td>
        8.6.1 (L1) Ensure users can report security concerns in Teams
    </td>
    <td>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>"

# 9. Microsoft Fabric
$htmlContent += "
<tr>
    <th>9. Microsoft Fabric</th>
    <th>Category</th>
    <th>CIS Benchmark Recommendation</th>
    <th>Result</th>
</tr>
<tr>
    <td></td>
    <td>9.1 Tenant Settings</td>
    <td>
        9.1.1 (L1) Ensure guest user access is restricted<br>
        9.1.2 (L1) Ensure external user invitations are restricted<br>
        9.1.3 (L1) Ensure guest access to content is restricted<br>
        9.1.4 (L1) Ensure 'Publish to web' is restricted<br>
        9.1.5 (L2) Ensure 'Interact with and share R and Python' visuals is 'Disabled'<br>
        9.1.6 (L1) Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled'<br>
        9.1.7 (L1) Ensure shareable links are restricted<br>
        9.1.8 (L1) Ensure enabling of external data sharing is restricted<br>
        9.1.9 (L1) Ensure 'Block ResourceKey Authentication' is 'Enabled'<br>
        9.1.10 (L1) Ensure access to APIs by Service Principals is restricted<br>
        9.1.11 (L1) Ensure Service Principals cannot create and use profiles
    </td>
    <td>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")<br>
        $($outputObj."RESULT-CHECK")
    </td>
</tr>"


$htmlContent += "</table>
</body>
</html>"

# Output the HTML content
Write-Host "HTML report generated successfully."


# Export HTML Content to File
Write-Host "Exporting HTML report to file..." -ForegroundColor DarkGray
$htmlFilePath = "C:\ComplianceReport.html"
$htmlContent | Out-File -FilePath $htmlFilePath -Encoding UTF8

Write-Host "HTML report saved to $htmlFilePath" -ForegroundColor Green

# Send Email with HTML Report
Write-Host "Sending email with the report..." -ForegroundColor DarkGray
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

$params = @{
    message = @{
        subject = "CIS Compliance Report"
        body = @{
            contentType = "HTML"
            content = $htmlContent
        }
        toRecipients = @(
            @{
                emailAddress = @{
                    address = $EXOMailTo
                }
            }
        )
    }
}

Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

Write-Host "Email sent successfully!" -ForegroundColor Green

# Disconnect from Microsoft Graph
Disconnect-MgGraph

Write-Host "Compliance check completed successfully!" -ForegroundColor Green
