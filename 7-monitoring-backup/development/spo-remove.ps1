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

# Loop through each page, list the file names, and process them
foreach ($page in $pages) {
    # Get the file's server relative URL and name
    $fileRelativeUrl = $page["FileRef"]
    $fileName = [System.IO.Path]::GetFileName($fileRelativeUrl)

    Write-Host "`nFound file: $fileName"
    
    # Only process files that end with "Approved.aspx"
    if ($fileName -like "*Approved*") {
        # Remove the part like (2f)Approved, (3f3f)Approved using the regex
        $newName = $fileName -replace "\([^\)]+\)Approved", ""  # Remove "(2f)Approved" part from the name
        $newName = $newName -replace "Approved", "" # Remove the "Approved" part from the page name

        # Display the old name in red and the new name in green
        Write-Host "Old name: $fileName" -ForegroundColor Red
        Write-Host "New name: $newName" -ForegroundColor Green

        try {
            # Rename the file
            Rename-PnPFile -ServerRelativeUrl $fileRelativeUrl -TargetFileName $newName
            Write-Host "Renamed '$fileName' to '$newName'" -ForegroundColor Green
        } catch {
            Write-Host "Error renaming '$fileName'. Error: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipping '$fileName' as it does not contain 'Approved'." -ForegroundColor Yellow
    }
}

# Disconnect from SharePoint
# Disconnect-PnPOnline
