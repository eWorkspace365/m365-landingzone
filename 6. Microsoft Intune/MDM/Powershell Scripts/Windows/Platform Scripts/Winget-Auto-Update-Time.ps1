# Define the trigger to run the task daily at 5:15 AM
$TaskName = "WinGet-AutoUpdate"
$Trigger = New-ScheduledTaskTrigger -Daily -At 5:15AM

# Check if the task exists
$TaskExists = Get-ScheduledTask | Where-Object {$_.TaskName -eq $TaskName}

# If the task exists, update it; otherwise, register it with the appropriate settings
if ($TaskExists) {
    Set-ScheduledTask -TaskName "\WAU\$TaskName" -Trigger $Trigger
} else {
    Exit
}
