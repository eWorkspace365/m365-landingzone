[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$TenantID,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOMailFrom,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOMailTo,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOThumbprint,
    
    [Parameter(Mandatory=$false)]
    [String]$Organization
)

#region ORCA Module Installation
Write-Host "Checking for ORCA module..." -ForegroundColor Yellow
if ($null -eq $(Get-Module -ListAvailable -Name ORCA)) {
    Write-Host "ORCA module not found. Installing ORCA module..." -ForegroundColor Yellow
    try {
        Install-Module -Name ORCA -Force -ErrorAction Stop
        Write-Host "ORCA module installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "Error: Failed to install ORCA module. Please check your internet connection or permissions." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "ORCA module is already installed." -ForegroundColor Green
}

Import-Module ORCA
#endregion

#region EXO
if ($null -eq $(Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module ExchangeOnlineManagement 
}

Import-Module ExchangeOnlineManagement

Connect-ExchangeOnline -AppID $EXOClientId -CertificateThumbPrint $EXOThumbprint -Organization $Organization

# Generate ORCA report
Write-Host "Generating ORCA report..." -ForegroundColor Yellow
Get-ORCAReport

# Define the directory where the ORCA report is saved
$orcaDirectory = "$env:UserProfile\AppData\Local\Microsoft\ORCA"

# Find the most recent ORCA report file in the directory
$reportPath = Get-ChildItem -Path $orcaDirectory -Filter "*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $reportPath) {
    Write-Host "Error: No ORCA report HTML file found in the directory: $orcaDirectory" -ForegroundColor Red
    exit 1
}

Write-Host "ORCA report found at: $($reportPath.FullName)" -ForegroundColor Green

# Check if the HTML file exists
if (Test-Path $reportPath.FullName) {
    # Read the HTML content from the file
    $htmlContent = Get-Content -Path $reportPath.FullName -Raw

    # Embed CSS directly into the HTML
    $embeddedCSS = @"
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f8f9fa;
            }
            .container {
                max-width: 600px;
                margin: 20px auto;
                padding: 20px;
                background-color: #ffffff;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
            h1 {
                color: #333;
                font-size: 24px;
                text-align: center;
            }
            p {
                color: #555;
                font-size: 16px;
                line-height: 1.5;
            }
            .footer {
                text-align: center;
                font-size: 12px;
                color: #aaa;
                margin-top: 20px;
            }
        </style>
"@

    # Embed the CSS into the HTML content
    $htmlContent = $htmlContent -replace "<head>", "<head>`n$embeddedCSS"

    # Connect to Microsoft Graph for email operations
    Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantID -CertificateThumbPrint $EXOThumbprint

    # Define the email message
    $params = @{
        message = @{
            subject = "ORCA Report"
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

    # Send the email
    Write-Host "Sending email with the ORCA report..." -ForegroundColor Yellow
    Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

    # Disconnect from Microsoft Graph
    Disconnect-MgGraph

    Write-Host "Email sent successfully!" -ForegroundColor Green

    # Remove the original report file
    Remove-Item -Path $reportPath.FullName -Force
    Write-Host "Temporary file removed: $($reportPath.FullName)" -ForegroundColor Green
} else {
    Write-Host "Error: ORCA report HTML file not found at the specified path!" -ForegroundColor Red
}

#endregion
