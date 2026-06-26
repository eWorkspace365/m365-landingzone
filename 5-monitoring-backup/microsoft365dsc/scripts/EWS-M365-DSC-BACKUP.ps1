[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$Customer
)

# haal de huidige datum op  
$date = Get-Date

$day = $date.day
$month = $date.Month
$year = $date.Year
 
# formaat de maand met een voorloopnul
if ($month -lt 10) {
    $month = "0$month"
}

# Create the folder in the container using azcopy
Copy-Item -Path "C:\DevOps\$Customer\Current\M365" -Destination "C:\DevOps\$Customer\Backup\M365\$year\$month\$day" -Recurse



