[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$Customer
)

try {
    . "./GeneralFunctions.ps1"
}
catch {
    Write-Output "Error while loading supporting PowerShell Scripts $error"
    exit
}

$globalSettings = GetGlobalSettings
$Localfolder = $globalSettings.LocalFolder
$KlantNaam = $Customer
$CmcSettings = $globalSettings.CMC

Write-Output "SaveToCMCBlob path $Localfolder klantnaam $KlantNaam"
   
# Connect naar CMC
Disconnect-AzAccount
ConnectAzAccount -Klant $CmcSettings

# haal de huidige datum op en bepaal de juiste maand en jaar  
$date = Get-Date    
$month = $date.AddMonths(-1).Month
$year = $date.AddMonths(-1).Year    
if ($date.Day -ge 15) {
    $month = $date.Month
    $year = $date.Year
}
if ($month -lt 10) {
    $month = "0$month"
}

# Haal SAS token van het storage account en connect      
$StorageSASToken = Get-AzKeyVaultSecret -VaultName $CmcSettings.KeyVaultName -Name "StorageSASToken" -AsPlainText        
$storcontext = New-AzStorageContext -StorageAccountName $CmcSettings.StorageAccountName  -SasToken $StorageSASToken 
     
# Bepaal lokale files die naar de storage account moeten worden gekopieerd
$saveFolder = Join-Path -Path $Localfolder -ChildPath $KlantNaam        
$saveFolder = Join-Path -Path $saveFolder -ChildPath "Microsoft 365"

# Loop door de bestanden en kopieer deze naar de storage account
Get-ChildItem $saveFolder -Filter *.json | 
Foreach-Object {
    $filename = $_.FullName
    Write-Output "SaveToCMCBlob filename $filename"     
    $blobfile = $KlantNaam + "/" + "Microsoft 365" + "/" + $year + "/" + $month + "/" + $_.Name          
    Write-output "Voor save $filename en $blobfile"          
    Set-AzStorageBlobContent -Container $CmcSettings.StorageAccountContainer -File $filename -Blob $blobfile -Context $storcontext -Force
}