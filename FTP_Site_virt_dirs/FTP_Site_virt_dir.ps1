<#

    .SYNOPSIS
    Installs a new FTP site with virtual directories. 
    
    .DESCRIPTION
    This script will create a new FTP site setup with Virtual Directories.
    Script can also be used to add additional users with virtual directories on the same site. 
    To customize site, update custom variables as desired. 
        
    .OUTPUTS  
    A new FTP site configured with Virtual Directories. 
     
    .NOTES
    Author: Michael Groff
    Minimum OS: 2012, 2012 R2
    PS Version: 4.0
    Date:  1/18/17

#>

###
###Variables Start: 
###
#FTPUsername
Write-Host "
The FTP Username is a Windows User
" -ForegroundColor Yellow
$FTPSiteUser = Read-host -prompt "Enter the FTP Username"
#FTP Password - NOTE: Must be UNDER 14 characters, also must have a capital letter and special character
Write-Host "
The FTP User Pasword must be UNDER 14 characters & must have a capital letter and special character
" -ForegroundColor Yellow
$FTPSiteUserPW = Read-host -prompt "Enter the FTP User Pasword"
#FTP Group
Write-Host "
The FTP Group is a Windows Group, suggested group name is: 'FTP_User_Group'
" -ForegroundColor Yellow
$FTPGroup = Read-host -prompt "Enter the FTP Group Name"
#FTP Site Name in IIS
Write-Host "
The FTP Site Name will be the site name in IIS
" -ForegroundColor Yellow
$FTPSiteName = Read-host -prompt "Enter the FTP Site name"
#FTP Site Path
Write-Host "
The standard FTP root directory is: 'C:\inetpub\ftproot'" -ForegroundColor Yellow
Write-Host "If you have run this once, use the same path as before unless your intentions are a new site" -ForegroundColor Red
$FTPSitePath = Read-host -prompt "Enter the root directory"
#FTP Site Virtual Directory Path
Write-Host "
This is the path for the site that already exists, the path you want FTP access to, ex: 'C:\inetpub\wwwroot'
" -ForegroundColor Yellow
$directoryPath = Read-host -prompt "Enter the root directory"
###
###Variables End: 
###

#Windows Roles & Features if they are not already installed
Function Install-WP-Web-Features {
IF ( Get-WindowsFeature -Name Web-Server, Web-Ftp-Server | Where {$_.InstallState -eq "Available"} )
        {
            Install-WindowsFeature -Name Web-Server, Web-Ftp-Server -IncludeManagementTools
        }
        ELSE
        {
            Return  Write-Host "
Necessary Windows Features are already installed!
            " -ForegroundColor Green
        }
}

Install-WP-Web-Features

#Create a new Website and AppPool for FTP Site

Import-Module WebAdministration

#Create FTP Group & User - Uses preset variables 
#Group Creation

IF (-not (Get-WmiObject -Class Win32_Group | Where-Object {$_.Name -eq "$FTPGroup"}))
{
    Write-Host "
Creating FTP User Group
    " -ForegroundColor Cyan
    Invoke-Command -ScriptBlock {net localgroup /add $FTPGroup}
}
ELSE
{
    Write-Host "
Local Group already exists
    " -ForegroundColor Yellow
}

#Users Creation

IF (-not (Get-WmiObject -Class Win32_UserAccount | Where-Object {$_.Name -eq "$FTPSiteUser"}))
{
    Write-Host "
Creating FTP User
    " -ForegroundColor Cyan
    Invoke-Command -ScriptBlock {net user /add $FTPSiteUser $FTPSiteUserPW} -ErrorAction SilentlyContinue
    Write-Host "
Adding user to FTP User Group
    " -ForegroundColor Cyan
    Invoke-Command -ScriptBlock {net localgroup $FTPGroup $FTPSiteUser /add }
}
ELSE
{
    Write-Host "
Local User already exists, cannot create user or add user to group!
    " -ForegroundColor Red
}

#Create FTP Site
$FTPSitePathLocUsr = "$FTPSitePath\LocalUser"

IF (-not (Test-Path -Path "$FTPSitePathLocUsr"))
{
    New-Item -Path $FTPSitePathLocUsr -ItemType Directory -ErrorAction SilentlyContinue
    New-Item -Path $FTPSitePath -ItemType Directory -ErrorAction SilentlyContinue
    New-WebFtpSite -Name $FTPSiteName -PhysicalPath $FTPSitePath -IPAddress * -Port 21
}
ELSE
{
    Write-Host "
FTP Site already exists in location: '$FTPSitePath'
Attempting to create virtual direcotry in FTP Site.
    " -ForegroundColor Yellow
} 

IF (-not (Get-WebVirtualDirectory -Name "*$FTPSiteUser*") )
{
    New-WebVirtualDirectory -Site "$FTPSiteName\LocalUser" -Name $FTPSiteUser -PhysicalPath $directoryPath -ErrorAction SilentlyContinue
    Write-Host "
FTP virtual direcotry has been created!
    " -ForegroundColor Green
}
ELSE
{
    Write-Host "
Virtual Directory for FTP Site already exists
    " -ForegroundColor Red 
}

#Setting User/Group Permissions for FTP User Group in IIS - Adding Authorization in IIS

#Giving Windows Group permissions to site for FTP
IF (-not((Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$FTPSiteName" -filter "system.ftpServer/security/authorization/add" -name ".").roles))
{
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$FTPSiteName" -filter "system.ftpServer/security/authorization" -name "." -value @{accessType='Allow';roles="$FTPGroup";permissions='Read,Write'}
}
ELSE
{
    Write-Host " 
FTP User Group has already been given proper permissions in IIS. 
    " -ForegroundColor Green 
}

#Enable Basic Auth for the FTP Site
Set-ItemProperty "IIS:\Sites\$FTPSiteName" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true

#Setup User Isolation
Set-ItemProperty "IIS:\Sites\$FTPSiteName" -Name ftpServer.userisolation.mode -Value IsolateAllDirectories

#Disable Require SSL on FTP Site
Set-ItemProperty "IIS:\Sites\$FTPSiteName" -Name ftpServer.security.ssl.controlChannelPolicy -Value SslAllow
Set-ItemProperty "IIS:\Sites\$FTPSiteName" -Name ftpServer.security.ssl.dataChannelPolicy -Value SslAllow

#Permission for FTP user to WP Directory
$FTPAcl = Get-Acl -Path "$directoryPath"
$FTPAclUser = New-Object system.security.accesscontrol.filesystemaccessrule("$FTPGroup","FullControl","ContainerInherit, ObjectInherit","None","Allow")
$FTPAcl.SetAccessRule($FTPAclUser)
Set-Acl -Path "$directoryPath" -AclObject $FTPAcl

Write-Host "
Done!
" -ForegroundColor Green 

Read-Host -Prompt "Press Enter to exit"