### Install chocolatey ###
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; 
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

### Install Chocolatey prereqs ###
choco install -y git 7zip python3 vt-cli
refreshenv
#RUN choco upgrade -y visualstudio2022-workload-vctools visualstudio2019-workload-vctools

### Install neo-ConfuserEx ###
$url = ('https://github.com/XenocodeRCE/neo-ConfuserEx/releases/download/v1.0.0/bin.7z')
Write-Host ('Downloading {0} ...' -f $url)
Invoke-WebRequest -Uri $url -OutFile 'confuser.7z'
Write-Host 'Installing ...'
# This is not a mistake, there can't be a space between '-o' and 'C:\confuser'
7z x -oC:\confuser .\confuser.7z -r
# Add ConfuserEx to PATH
[Environment]::SetEnvironmentVariable(
    "Path",
    [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine) + ";C:\confuser",
    [EnvironmentVariableTarget]::Machine)
$env:PATH = [Environment]::GetEnvironmentVariable('PATH', [EnvironmentVariableTarget]::Machine)

Copy-Item C:\confuser\Confuser.CLI.exe C:\confuser\confuser.exe
Write-Host 'Removing install files...'
Remove-Item confuser.7z -Force
Write-Host 'Complete.'

### Install InvisibilityCloak ###
$url = ('https://raw.githubusercontent.com/h4wkst3r/InvisibilityCloak/main/InvisibilityCloak.py')
Write-Host ('Downloading {0} ...' -f $url)
Invoke-WebRequest -Uri $url -OutFile 'InvisibilityCloak.py'
Write-Host 'Installing ...'
# Add script to PATH location
Copy-Item InvisibilityCloak.py C:\Python312\Scripts\InvisibilityCloak.py
Write-Host 'Removing install files...'
Remove-Item InvisibilityCloak.py -Force
Write-Host 'Complete'
