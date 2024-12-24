Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Confirm:$false -Force:$true
Install-Script get-windowsautopilotinfo -Confirm:$false -Force:$true
get-windowsautopilotinfo -Online -TenantId "6631255-fc1d-2022-8d61-e0b56305bc9b" -AppId "3555381c6-bbaef-5e55-97d1-5gf3ch44afbb" -AppSecret "eru8Q~7.TsLwKsPItJKbLfX257XsamndDFf3cqala"




