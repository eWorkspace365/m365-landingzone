# Connect to SharePoint site
# Connect-PnPOnline -Url "https://yoursharepointsiteurl" -UseWebLogin

# Get all items in the "Site Pages" library
$pages = Get-PnPListItem -List "SitePages" -Fields "File"

# Debug: Check if we got any items
if ($pages.Count -eq 0) {
    Write-Host "No pages found in the Site Pages library."
} else {
    Write-Host "$($pages.Count) pages found."
}

# Loop through each page and list the file names using ServerRelativeUrl
foreach ($page in $pages) {
    # Get the file's server relative URL
    $fileRelativeUrl = $page["FileRef"]
    
    # Extract the file name from the relative URL
    $fileName = [System.IO.Path]::GetFileName($fileRelativeUrl)
    
    Write-Host "Found file: $fileName"
}

# Disconnect from SharePoint
# Disconnect-PnPOnline
