[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [String]$Tag, # Single tag to filter by
    
    [Parameter(Mandatory=$false)]
    [String]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOMailFrom,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOMailTo,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOClientId,
    
    [Parameter(Mandatory=$false)]
    [String]$EXOThumbprint
)

# New Roadmap URL
$RoadmapURL = "https://www.microsoft.com/releasecommunications/api/v1/m365"

# Calculate the start and end dates for the previous month
$Now = Get-Date
$StartOfPreviousMonth = (Get-Date -Year $Now.Year -Month $Now.Month -Day 1).AddMonths(-1)
$EndOfPreviousMonth = (Get-Date -Year $Now.Year -Month $Now.Month -Day 1).AddDays(-1)

# Request data
$Result = Invoke-RestMethod -Method Get -Uri $RoadmapURL

# Filter data based on the tag and modified date in the previous month
$FilteredData = $Result | Where-Object {
    $_.TagsContainer.products.tagName -eq $Tag -and
    ([datetime]$_.modified -ge $StartOfPreviousMonth -and [datetime]$_.modified -le $EndOfPreviousMonth)
} | Sort-Object modified -Descending

# Generate HTML report
$CSSStyle = "<style>
table {font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%;}
table td, th {border: 1px solid #ddd; padding: 8px;}
table tr:nth-child(even){background-color: #F39C12;}
table tr:hover {background-color: #ddd;}
table th { padding-top: 10px; padding-bottom: 10px; text-align: left; background-color: #F39C12; color: white;}
</style>"

$HtmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Roadmap Updates Report</title>
    $CSSStyle
</head>
<body>
    <h2>Roadmap Updates Report</h2>
    <p>This report provides details about roadmap updates filtered by the tag '$Tag' and modified in the previous month.</p>
    <table>
        <thead>
            <tr>
                <th>Modified</th>
                <th>Status</th>
                <th>Public Disclosure Availability Date</th>
                <th>Title</th>
            </tr>
        </thead>
        <tbody>
"@

foreach ($item in $FilteredData) {
    $HtmlContent += @"
        <tr>
            <td>$($item.modified)</td>
            <td>$($item.status)</td>
            <td>$($item.publicDisclosureAvailabilityDate)</td>
            <td>$($item.Title)</td>
        </tr>
"@
}

$HtmlContent += @"
        </tbody>
    </table>
</body>
</html>
"@

# Connect to Microsoft Graph for email operations
Connect-MgGraph -ClientId $EXOClientId -TenantId $TenantId -CertificateThumbprint $EXOThumbprint

# Define the email message
$params = @{
    message = @{
        subject = "Roadmap Updates Report"
        body = @{
            contentType = "HTML"
            content = $HtmlContent
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
Write-Verbose "Sending email with the report"
Send-MgUserMail -UserId $EXOMailFrom -BodyParameter $params

Write-Verbose "Email sent successfully"

# Disconnect from Microsoft Graph
Disconnect-MgGraph
