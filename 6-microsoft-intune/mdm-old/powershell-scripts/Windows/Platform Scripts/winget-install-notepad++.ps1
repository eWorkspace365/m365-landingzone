$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
    if ($ResolveWingetPath){
           $WingetPath = $ResolveWingetPath[-1].Path
    }

$config
cd $wingetpath
.\winget.exe install -e --id Notepad++.Notepad++ --silent --accept-package-agreements --accept-source-agreements
