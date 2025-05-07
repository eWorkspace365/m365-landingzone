[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$Customer,
    
    [Parameter(Mandatory=$false)]
    [String]$TenantID,
    
    [Parameter(Mandatory=$false)]
    [String]$AppID,
    
    [Parameter(Mandatory=$false)]
    [String]$CertificateThumbprint,
    
    [Parameter(Mandatory=$false)]
    [String]$Organization,
    
    [Parameter(Mandatory=$false)]
    [String]$MailAppID,
    
    [Parameter(Mandatory=$false)]
    [String]$MailAppSecret

)

$MailSender = "rubicon-monitor@$Organization"
$DirectoryPath = "C:\Users\rubiadmin\AppData\Local\Microsoft\ORCA"
$Recipient = "a.bode@rubicon.nl"

# Empty the report folder
Get-ChildItem -Path "$($DirectoryPath)\*" | Remove-Item -Force

#region EXO
if ($null -eq $(Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module ExchangeOnlineManagement 
}

Import-Module ExchangeOnlineManagement

Connect-ExchangeOnline -CertificateThumbPrint $CertificateThumbprint -AppID $AppID -Organization $Organization

Get-ORCAReport

# Print current working directory
Write-Output "Current working directory: $(Get-Location)"

# Print the full path of the directory we're searching
Write-Output "Searching for HTML files in: $DirectoryPath"

# Check if the directory exists
if (Test-Path $DirectoryPath -PathType Container) {
    # Get all HTML files in the directory
    $HtmlFiles = Get-ChildItem -Path $DirectoryPath -Filter "*.html"

    if ($HtmlFiles.Count -gt 0) {
        foreach ($file in $HtmlFiles) {
            $FileName = $file.Name
            $FilePath = $file.FullName
            $base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($FilePath))
            
            Write-Output "File Name: $FileName"
            Write-Output "File Path: $FilePath"
            Write-Output "------------------------"
        }
    } else {
        Write-Output "Error: No HTML files found in the specified directory."
    }
} else {
    Write-Output "Error: The specified directory does not exist or is not accessible."
}

#Connect to GRAPH API
$tokenBody = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    Client_Id     = $MailAppID
    Client_Secret = $MailAppSecret
}
$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody
$headers = @{
    "Authorization" = "Bearer $($tokenResponse.access_token)"
    "Content-type"  = "application/json"
}

#Send Mail    
$URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"
$BodyJsonsend = @"
                    {
                        "message": {
                          "subject": "$Customer | M365 ORCA Report",
                          "body": {
                            "contentType": "HTML",
                            "content": "This mail is scheduled every month for detecting vulnerabilities in Exchange Online. Download the attachment<br>
                             <br>
                            <br>
                            <br>
                            "
                          },
                          
                          "toRecipients": [
                            {
                              "emailAddress": {
                                "address": "$Recipient"
                              }
                            }
                          ]
                          ,"attachments": [
                            {
                              "@odata.type": "#microsoft.graph.fileAttachment",
                              "name": "$FileName",
                              "contentType": "text/plain",
                              "contentBytes": "$base64string"
                            }
                          ]
                        },
                        "saveToSentItems": "false"
                      }
"@

Invoke-RestMethod -Method POST -Uri $URLsend -Headers $headers -Body $BodyJsonsend



