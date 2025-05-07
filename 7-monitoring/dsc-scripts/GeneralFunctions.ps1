$FilePathGlobalSetting = "..\globalsettings.json"

Function ConnectAzAccount {
  param (
    [Parameter(Mandatory = $true)]
    $Klant,            
    [Parameter(Mandatory = $false)]
    [string] $SubscriptionId
  )  
  if ($Klant.ClientSecret) {
    Write-Output "Clientsecret1 connect"
    $SecureClientSecret = ConvertTo-SecureString -String $Klant.ClientSecret -AsPlainText -Force
    $Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Klant.ClientId, $SecureClientSecret
    Connect-AzAccount -ServicePrincipal -Credential $Credential -Tenant $Klant.TenantId    
  }
  elseif ($Klant.Thumbprint) {
    Write-Output "Thumbprint1 connect"
    Connect-AzAccount -CertificateThumbprint $Klant.Thumbprint -ApplicationId $Klant.ClientId -Tenant $Klant.TenantId -ServicePrincipal 
  }    
  else {  
    $context = Get-AzContext  
    if (!$context) { 
      Write-Output "No valid credentials provided, so just login manually"
      Connect-AzAccount -Subscription $SubscriptionId -Tenant $klant.TenantId
    }
  }
}

Function SaveObjectToJsonFile {    
  param (    
    [string] $klantnaam,
    [string] $filename,
    [PSCustomObject] $itemToSave,
    [bool] $asArray = $false
  )

  $globalSettings = GetGlobalSettings
  
  $folder = $globalSettings.LocalFolder

  Write-Output "SaveObjectToJsonFile folder $folder klantnaam $klantnaam filename $filename"

  $saveFolder = Join-Path -Path $folder -ChildPath $klantnaam
  
  if (-Not(Test-Path -Path $saveFolder)) {
    New-Item -ItemType Directory -Path $saveFolder
  }

  $saveFolder = Join-Path -Path $saveFolder -ChildPath "Microsoft 365"
  
  if (-Not(Test-Path -Path $saveFolder)) {
    New-Item -ItemType Directory -Path $saveFolder
  }
           
  $file = Join-Path -Path $saveFolder -ChildPath $filename   
   
  if ($asArray) {
    $itemToSave | ConvertTo-Json -AsArray -Depth 100 | Out-File -FilePath $file -Force  
  }
  else {
    $itemToSave | ConvertTo-Json -Depth 100 | Out-File -FilePath $file -Force  
  }   
}

function GetGlobalSettings() {
  $PowerShellObject = Get-Content -Path $FilePathGlobalSetting | ConvertFrom-Json
  return $PowerShellObject
}










