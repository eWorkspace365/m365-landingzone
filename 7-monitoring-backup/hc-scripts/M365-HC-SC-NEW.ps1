############################################################################
#
# TOELICHTING
#
############################################################################

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [String]$Customer,
    
    [Parameter(Mandatory=$true)]
    [String]$TenantID,
    
    [Parameter(Mandatory=$true)]
    [String]$ClientID,
    
    [Parameter(Mandatory=$true)]
    [String]$CertificateThumbprint

)


#region Header
#--------------------------------------------------
# HEADER - SAME FOR ALL SCRIPTS
#--------------------------------------------------

set-strictmode -version Latest
$ErrorActionPreference = "stop"


# Ability to run scripts based on relative path
If ($myInvocation.MyCommand.CommandType -ne [System.Management.Automation.CommandTypes]::Script)
{
    $scriptfolder = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
    #the output below returns the parent of the scriptfolder (normally where also \modules and \logs are located )
    #$Global:WorkingDir = $($(Get-Item $scriptfolder).Parent).FullName
    $Global:WorkingDir = $($(Get-Item $scriptfolder).FullName)
}
Else
{
    $scriptfolder = [System.IO.Path]::GetDirectoryName($psISE.CurrentFile.FullPath)
    #the output below returns the parent of the scriptfolder (normally where also \modules and \logs are located )
    #$Global:WorkingDir = $($(Get-Item $scriptfolder).Parent).FullName
    $Global:WorkingDir = $($(Get-Item $scriptfolder).FullName)
}
###############
# The section above only works when the script is run if it is SAVED on any given location!!! Otherwise the parentfolder location cannot be retrieved!
# MAKE SURE TO SAVE THE FILE BEFORE RUNNING THE SCRIPT
###############
    
#endregion

############################################################################

#First create the file output
Write-Output "Creating output object"
$timestamp = Get-Date -Format "dd/MM/yyyy"
$scriptVersion = "1.0"

$outputObj = New-Object -TypeName psobject
$outputObj | Add-Member -MemberType NoteProperty -Name version -Value $scriptVersion
$outputObj | Add-Member -MemberType NoteProperty -Name timestamp -Value $timestamp


################################################################################

#Enter the app registration details for the CIS / Graph scan

#app registration heeft de volgende rechten nodig (Microsoft APIs)
#SecurityActions.Read.All
#SecurityAlert.Read.All
#SecurityEvents.Read.All
#SecurityIncident.Read.Al
#ThreatIntelligence.Read.All

##voor het health check deel
#IdentityRiskEvent.Read.All
#IdentityRiskyUser.Read.All
#Application.Read.All #gebruikt voor controle op verloop van certificaten

#app registration heeft de volgende rechten nodig voor Endpoint en Defender zaken (LET OP: App registration > API permissions > APIs my organization uses > Zoek op windowsdefenderatp > selecteer nu)

#Alert.Read.All
#Score.Read.All
#SecurityConfiguration.Read.All
#SecurityRecommendation.Read.All
#Software.Read.All
#Vulnerability.Read.All
#Machine.Read.All


################################################################################

<# CIAOPS
Script provided as is. Use at own risk. No guarantees or warranty provided.

Description - Connect to the Microsoft Graph and retrieve all the items in Secure Score for the last 90 days
Source - https://github.com/directorcia/Office365/blob/master/mggraph-sscore-get.ps1

Prerequisites = 1
1. Microsoft Graph module installed - https://www.powershellgallery.com/packages/Microsoft.Graph/

#>

## Variables
$systemmessagecolor = "cyan"
$processmessagecolor = "green"
$errormessagecolor ="red"
$warningmessagecolor = "yellow"

## If you have running scripts that don't have a certificate, run this command once to disable that level of security
##  set-executionpolicy -executionpolicy bypass -scope currentuser -force



<#  ----- [Start] Graph PowerShell module check -----   #>
if (get-module -listavailable -name Microsoft.Graph.Authentication) {    ## Has the Graph import module been installed?
    write-host -ForegroundColor $processmessagecolor "Graph authentication module found"
}
else {
    write-host -ForegroundColor $warningmessagecolor -backgroundcolor $errormessagecolor "[001] - Graph PowerShell module not installed. Please install and re-run script - ", $_.Exception.Message
    if ($debug) {
        Stop-Transcript                 ## Terminate transcription
    }
    exit 1                              ## Terminate script
}

Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint


# 1. START HET OPHALEN SECURE SCORE ITEMS M365

Write-Verbose "Running script with verbose output enabled"

Write-Verbose "Setting Graph API URIs"
$secureScoresUri = "https://graph.microsoft.com/beta/security/securescores?`$top=1" 
$secureScoreControlProfileUri = "https://graph.microsoft.com/beta/security/secureScoreControlProfiles"



#Build table objects for final scores and final reports 
Write-Verbose "Creating Objects for final report"
$DetailedControlScoresTable = New-Object 'System.Collections.Generic.List[System.Object]'
$FinalSecureScoreReport = New-Object 'System.Collections.Generic.List[System.Object]'

# Get latest secure score from Graph Api
Write-Verbose "Getting latest Secure Score from Graph API"
$secureScoreLatest = (Invoke-MgGraphRequest -Uri $secureScoresUri -Method Get).value

#Set secure score values for my tenant score, maximum score for my tenant, and the avergae score for all tenants and tenants with similar seats
Write-Verbose "Extracting and calculating secure score data"
$myCurrentScore = $secureScoreLatest.CurrentScore


$myMaxScore = $secureScoreLatest.MaxScore
$myCurrentScorePercentage = (($myCurrentScore / $myMaxScore) * 100)
$allTenantsAverageScore = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "AllTenants" }).AverageScore
$allTenantsAverageIdentity = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "AllTenants" }).identityScore
$allTenantsAverageApps = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "AllTenants" }).appsScore
$allTenantsAverageDevice = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "AllTenants" }).deviceScore
$allTenantsAverageData = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "AllTenants" }).dataScore
$TotalSeatsAverageScore = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "TotalSeats" }).AverageScore
$TotalSeatsAverageIdentity = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "TotalSeats" }).identityScore
$TotalSeatsAverageApps = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "TotalSeats" }).appsScore
$TotalSeatsAverageDevice = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "TotalSeats" }).deviceScore
$TotalSeatsAverageData = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "TotalSeats" }).dataScore



#Add combined secure score data to final report
Write-Verbose "Generating overall secure score data"
$finalView = [PSCustomObject]@{
    'Description'         = "OverallScore"
    'myScore'             = $myCurrentScore 
    'maxScore'            = $myMaxScore
    'percentageScore'     = [math]::Round($myCurrentScorePercentage, 2)
    'allTenantAverage'    = [math]::Round($allTenantsAverageScore, 2)
    'similarSeatsAverage' = [math]::Round($TotalSeatsAverageScore, 2)
}
Write-Verbose "Writing overall secure score data to final report"    
$FinalSecureScoreReport.Add($finalView)

#Loop through each Control score and add the details to the control scores table. Also query the control profile for the maximum available score. 
Write-Verbose "Looping through each control profile to obtain maximum scores" 
foreach ($_ in ($secureScoreLatest).ControlScores) {
    $stopLoop = $false
    [int]$Retries = "0"
 
    do {
        try {
            $controlProfileMaxScore = ((Invoke-MgGraphRequest -Uri "$secureScoreControlProfileUri/$($_.ControlName)" -Method Get)).MaxScore
            Write-Verbose "Successully obtained max score for control profile id $($_.ControlName) ($($controlProfileMaxScore))"
            $stopLoop = $true
        }
        catch {
            if ($Retries -gt 2) {
                Write-Verbose "Unable to obtain max score for control profile id $($_.ControlName)"
                $stopLoop = $true
            }
            else {
                Write-Verbose "Unable to obtain max score. Retrying in 2 seconds for control profile id $($_.ControlName)"
                Start-Sleep -Seconds 2
                $Retries = $Retries + 1
            }
        }
    }
    While ($stopLoop -eq $false)
    
    #Add details for each object to a table
    Write-Verbose "Adding details to table for profile id $($_.ControlName)"
    $DetailedControlScores = [PSCustomObject]@{
        'controlProfile'               = $_.ControlName
        'controlCategory'              = $_.ControlCategory
        'myControlItemScore'           = $_.Score
        'maxControlItemScore'          = $controlProfileMaxScore
    }

    #Add all objects to the combined table
    $DetailedControlScoresTable.Add($DetailedControlScores)
}

#Get the combined score for each Control Category (Identity, Device, Apps, Data etc.). This is in points. 
Write-Verbose "Grouping secure scores by category"
$controlCategoryTable = $DetailedControlScoresTable | Group-Object ControlCategory | % {
    Write-Verbose "Calculating score in points for $($_.Name)"
    New-Object psobject -Property @{
        Category            = $_.Name
        mySumCategoryScore  = ($_.Group | Measure-Object myControlItemScore -Sum).Sum
        maxSumCategoryScore = ($_.Group | Measure-Object maxControlItemScore -Sum).Sum
    }
}
    
#Get the percentage score for each control category. If any score is 0, set average to 0. 
Write-Verbose "Calculating secure scores in percentage"
$report = foreach ($_ in $controlCategoryTable) {
    if ($_.mySumCategoryScore -eq "0") {
        $controlCategoryPercentage = "0"
    }

    else {
        $controlCategoryPercentage = (($_.mySumCategoryScore / $_.maxSumCategoryScore) * 100)
    }

    Write-Verbose "Setting other tenant averages for comparison"
    #Set the average values for all tenants and similar seats
    if ($_.Category -eq "Identity") {
        Write-Verbose "Setting other tenant averages for Identity comparison"
        $allTenantAverage = $allTenantsAverageIdentity
        $similarSeatAverage = $TotalSeatsAverageIdentity
    }
    elseif ($_.Category -eq "Apps") {
        Write-Verbose "Setting other tenant averages for Apps comparison"
        $allTenantAverage = $allTenantsAverageApps
        $similarSeatAverage = $TotalSeatsAverageApps
    }
    elseif ($_.Category -eq "Device") {
        Write-Verbose "Setting other tenant averages for Device comparison"
        $allTenantAverage = $allTenantsAverageDevice
        $similarSeatAverage = $TotalSeatsAverageDevice
    }
    elseif ($_.Category -eq "Data") {
        Write-Verbose "Setting other tenant averages for Data comparison"
        $allTenantAverage = $allTenantsAverageData
        $similarSeatAverage = $TotalSeatsAverageData
    }
    else {
        $allTenantAverage = $null
        $similarSeatAverage = $null
    }

    #Build the final report details
    Write-Verbose "Building final view"
    $finalView = [PSCustomObject]@{
        'Description'         = $_.Category
        'myScore'             = $_.mySumCategoryScore 
        'maxScore'            = $_.maxSumCategoryScore
        'percentageScore'     = [math]::Round($controlCategoryPercentage, 2)
        'allTenantAverage'    = [math]::Round($allTenantAverage, 2)
        'similarSeatsAverage' = [math]::Round($similarSeatAverage, 2)
    }

    #Add Data to final report   
    Write-Verbose "Appending final view to final report" 
    $FinalSecureScoreReport.Add($finalView)
}



#TOON TABLE MET SCORE EN VERGELIJKING
Write-Verbose "Displaying secure score final report" 
$FinalSecureScoreReport | Format-Table

#Specificeer per onderdeel
#Overall score
$OverallScore_MyScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Identity"} | Select-Object -ExpandProperty myScore
$OverallScore_maxScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Identity"} | Select-Object -ExpandProperty maxScore
$OverallScore_percentageScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Identity"} | Select-Object -ExpandProperty percentageScore
$OverallScore_allTenantAverage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Identity"} | Select-Object -ExpandProperty allTenantAverage
$OverallScore_similarSeatsAverage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Identity"} | Select-Object -ExpandProperty similarSeatsAverage

#Apps score
$AppsScore_MyScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Apps"} | Select-Object -ExpandProperty myScore
$AppsScore_maxScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Apps"} | Select-Object -ExpandProperty maxScore
$AppsScore_percentageScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Apps"} | Select-Object -ExpandProperty percentageScore
$AppsScore_allTenantAverage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Apps"} | Select-Object -ExpandProperty allTenantAverage
$AppsScore_similarSeatsAverage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Apps"} | Select-Object -ExpandProperty similarSeatsAverage

#Devices score
$DeviceScore_MyScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Device"} | Select-Object -ExpandProperty myScore
$DeviceScore_maxScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Device"} | Select-Object -ExpandProperty maxScore
$DeviceScore_percentageScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Device"} | Select-Object -ExpandProperty percentageScore
$DeviceScore_allTenantAverage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Device"} | Select-Object -ExpandProperty allTenantAverage
$DeviceScore_similarSeatsAverage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Device"} | Select-Object -ExpandProperty similarSeatsAverage

#Data score
$DataScore_MyScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Data"} | Select-Object -ExpandProperty myScore
$DataScore_maxScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Data"} | Select-Object -ExpandProperty maxScore
$DataScore_percentageScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Data"} | Select-Object -ExpandProperty percentageScore
$DataScore_allTenantAverage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Data"} | Select-Object -ExpandProperty allTenantAverage
$DataScore_similarSeatsAverage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Data"} | Select-Object -ExpandProperty similarSeatsAverage

#Identity score
$IdentityScore_MyScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Identity"} | Select-Object -ExpandProperty myScore
$IdentityScore_maxScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Identity"} | Select-Object -ExpandProperty maxScore
$IdentityScore_percentageScore = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Identity"} | Select-Object -ExpandProperty percentageScore
$IdentityScore_allTenantAverage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Identity"} | Select-Object -ExpandProperty allTenantAverage
$IdentityScore_similarSeatsAverage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Identity"} | Select-Object -ExpandProperty similarSeatsAverage




#SPECIFICEER WAARDES VOOR RAPPORTAGE

## Overall secure score score
$overallScorePercentage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "OverallScore"} | Select-Object -ExpandProperty percentageScore
Write-Output $overallScorePercentage

## Identity score
$IdentityScorePercentage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Identity"} | Select-Object -ExpandProperty percentageScore
Write-Output $IdentityScorePercentage

## Apps score
$AppsScorePercentage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Apps"} | Select-Object -ExpandProperty percentageScore
Write-Output $AppsScorePercentage

## Device score
$DeviceScorePercentage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Device"} | Select-Object -ExpandProperty percentageScore
Write-Output $DeviceScorePercentage

## Data score
$DataScorePercentage = $FinalSecureScoreReport | Where-Object {$_.Description -eq "Data"} | Select-Object -ExpandProperty percentageScore
Write-Output $DataScorePercentage




#TOON ALLE LOSSE RESULTATEN EN MY EN MAX SCORE
Write-Verbose "Displaying secure score full details report" 
$DetailedControlScoresTable

#Count results

# Controleer of de variabele `$DetailedControlScoresTable` bestaat
if ($DetailedControlScoresTable -eq $null) {
    Write-Host "De variabele `$DetailedControlScoresTable` bestaat niet."
    return
}

# Bereken het aantal resultaten
$aantalResultatenSecureScore = $DetailedControlScoresTable.Count





######################################################


### BOUW JSON ONDERDELEN OP

$OverallScores = New-Object PSCustomObject

# Voeg OverallScore toe aan "scores" object
$OverallScores | Add-Member -MemberType NoteProperty -Name MyScore -Value $myCurrentScore -force
$OverallScores | Add-Member -MemberType NoteProperty -Name MaxScore -Value $myMaxScore -force
$OverallScores | Add-Member -MemberType NoteProperty -Name PercentageScore -Value $myCurrentScorePercentage -force
$OverallScores | Add-Member -MemberType NoteProperty -Name AllTenantAverage -Value $allTenantsAverageScore -force
$OverallScores | Add-Member -MemberType NoteProperty -Name SimilarSeatsAverage -Value $TotalSeatsAverageScore -force

$AppsScores = New-Object PSCustomObject

$AppsScores | Add-Member -MemberType NoteProperty -Name MyScore -Value $AppsScore_MyScore -force
$AppsScores | Add-Member -MemberType NoteProperty -Name MaxScore -Value $AppsScore_maxScore -force
$AppsScores | Add-Member -MemberType NoteProperty -Name PercentageScore -Value $AppsScore_percentageScore -force
$AppsScores | Add-Member -MemberType NoteProperty -Name AllTenantAverage -Value $AppsScore_allTenantAverage -force
$AppsScores | Add-Member -MemberType NoteProperty -Name SimilarSeatsAverage -Value $AppsScore_similarSeatsAverage -force

$DeviceScores = New-Object PSCustomObject

$DeviceScores | Add-Member -MemberType NoteProperty -Name MyScore -Value $DeviceScore_MyScore -force
$DeviceScores | Add-Member -MemberType NoteProperty -Name MaxScore -Value $DeviceScore_maxScore -force
$DeviceScores | Add-Member -MemberType NoteProperty -Name PercentageScore -Value $DeviceScore_percentageScore -force
$DeviceScores | Add-Member -MemberType NoteProperty -Name AllTenantAverage -Value $DeviceScore_allTenantAverage -force
$DeviceScores | Add-Member -MemberType NoteProperty -Name SimilarSeatsAverage -Value $DeviceScore_similarSeatsAverage -force

$DataScores = New-Object PSCustomObject

$DataScores | Add-Member -MemberType NoteProperty -Name MyScore -Value $DataScore_MyScore -force
$DataScores | Add-Member -MemberType NoteProperty -Name MaxScore -Value $DataScore_maxScore -force
$DataScores | Add-Member -MemberType NoteProperty -Name PercentageScore -Value $DataScore_percentageScore -force
$DataScores | Add-Member -MemberType NoteProperty -Name AllTenantAverage -Value $DataScore_allTenantAverage -force
$DataScores | Add-Member -MemberType NoteProperty -Name SimilarSeatsAverage -Value $DataScore_similarSeatsAverage -force

$IdentityScores = New-Object PSCustomObject

$IdentityScores | Add-Member -MemberType NoteProperty -Name MyScore -Value $IdentityScore_MyScore -force
$IdentityScores | Add-Member -MemberType NoteProperty -Name MaxScore -Value $IdentityScore_maxScore -force
$IdentityScores | Add-Member -MemberType NoteProperty -Name PercentageScore -Value $IdentityScore_percentageScore -force
$IdentityScores | Add-Member -MemberType NoteProperty -Name AllTenantAverage -Value $IdentityScore_allTenantAverage -force
$IdentityScores | Add-Member -MemberType NoteProperty -Name SimilarSeatsAverage -Value $IdentityScore_similarSeatsAverage -force


### CREATE DUMP FILE
Write-Output "Creating local file"
SaveObjectToJsonFile -klantnaam $Customer -filename "secure-score.json" -itemToSave $outputObj




# Alternative Secure Score Dump
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

