FROM mcr.microsoft.com/dotnet/framework/sdk:3.5-windowsservercore-ltsc2019
LABEL maintainer="0xC130D"

# Set default shell and working directory
SHELL [ "powershell", "-Command", "$ErrorActionPreference = 'stop'; $ProgressPreference = 'SilentlyContinue';" ]
RUN New-Item C:/temp -ItemType Directory
WORKDIR C:/temp

COPY install-requirements.ps1 .
RUN .\install-requirements.ps1
