#This Script Installs and sets up a wordpress site from a new install (Server 2012 R2+)

#
##
###YOU MUST DROP THIS SCRIPT ON YOUR DESKTOP AND RUN FROM THERE!
##
#

###Variables to fill out:
#Site Name, must inclue the TLD (.com, .info, .net, etc.)
$iisAppName = "MyWordpressSite.com"
#IIS App Pool Name: 
$iisAppPoolName = "MyWordpressSite.com"
#Site Path
$directoryPath = "C:\inetpub\wwwroot\MyWordpressSite"
#Database Name
$dbn = "wordpressdb"
#Database Username
$dbun ="wordpressdbuser"
#Database User Password
$dbpw = "mydbusersecretpassword"
#MySQL root password
$MySQL = "mysqlrootpassword"
#Salt Keys - https://api.wordpress.org/secret-key/1.1/salt/ (NOTE: Replace any $ that you see with another character!)
#Authentication Key
$AuthKey = "Authentication Key"
#Secure Authentication Key
$SecAuthKey = "Secure Authentication Key"
#Logged In Key
$LogInKey = "Logged In Key"
#Nonce Key
$NKey = "Nonce Key"
#Authentication Salt
$AuthSalt = "Authentication Salt"
#Secure Authentication Salt
$SecAuthSalt = "Secure Authentication Salt"
#Logged In Salt
$LogInSalt = "Logged In Salt"
#Nonce Salt
$NSalt = "Nonce Salt"

###Variables to leave alone: 
$iisAppPoolDotNetVersion = "v4.0"

Write-Host "Installing Windows Roles & Features... be patient" -ForegroundColor Yellow

#Windows Roles & Features

Install-WindowsFeature -Name Web-Server, Web-Log-Libraries, Web-Request-Monitor, Web-App-Dev, Web-Net-Ext45, Web-CGI -IncludeManagementTools

#Create a new Website and AppPool for WP to live in

Import-Module WebAdministration

#navigate to the app pools root
cd IIS:\AppPools\

#check if the app pool exists
if (!(Test-Path $iisAppPoolName -pathType container))
{
    #create the app pool
    $appPool = New-Item $iisAppPoolName
    $appPool | Set-ItemProperty -Name "managedRuntimeVersion" -Value $iisAppPoolDotNetVersion
}

#navigate to the sites root
cd IIS:\Sites\

#check if the site exists
if (Test-Path $iisAppName -pathType container)
{
    return
}

#create the site
$iisApp = New-Item $iisAppName -bindings @{protocol="http";bindingInformation=":80:" + $iisAppName} -physicalPath $directoryPath
$iisApp | Set-ItemProperty -Name "applicationPool" -Value $iisAppPoolName

#Adds in hosts file entry for your new site: 
function add-hostfilecontent {            
 [CmdletBinding(SupportsShouldProcess=$true)]            
 param (            
  [parameter(Mandatory=$true)]            
  [ValidatePattern("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]            
  [string]$IPAddress,            
              
  [parameter(Mandatory=$true)]            
  [string]$computer            
 )            
 $file = Join-Path -Path $($env:windir) -ChildPath "system32\drivers\etc\hosts"            
 if (-not (Test-Path -Path $file)){            
   Throw "Hosts file not found"            
 }            
 $data = Get-Content -Path $file             
 $data += "$IPAddress  $computer"            
 Set-Content -Value $data -Path $file -Force -Encoding ASCII             
}

add-hostfilecontent -IPAddress 127.0.0.1 -computer $iisAppName

Write-Host "Installing Web Platform Installer... keep waiting" -ForegroundColor Yellow
Write-Host "Now for the fun part..." -ForegroundColor Yellow
#Install Web Platform Installer
msiexec.exe /package http://download.microsoft.com/download/C/F/F/CFF3A0B8-99D4-41A2-AE1A-496C08BEB904/WebPlatformInstaller_amd64_en-US.msi /passive | Out-Null

#The .app info
Write-Host "If the script stopped here, you need to fill out the provided variables!" -ForegroundColor Red

New-Item $env:USERPROFILE\Desktop\wp.app -ItemType file -value "AppPath[@]$iisAppName

DbServer[@]localhost

DbName[@]$dbn

DbUsername[@]$dbun

DbPassword[@]$dbpw

DbAdminUsername[@]root

DbAdminPassword[@]$MySQL

Authentication Key[@]$AuthKey

Secure Authentication Key[@]$SecAuthKey

Logged In Key[@]$LogInKey 

Nonce Key[@]$NKey

Authentication Salt[@]$AuthSalt

Secure Authentication Salt[@]$SecAuthSalt

Logged In Salt[@]$LogInSalt

Nonce Salt[@]$NSalt

"

#Reload Paths to understand WebPICMD.exe
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

#Install WP & all necessary modles

WebPICMD.exe /Install /Application:Wordpress@wp.app /AcceptEULA /MySQLPassword:$MySQL /Log:$env:HOMEDRIVE\WPIntsalllog.txt

Write-Host "Done! Now go open your site..." -ForegroundColor Green 

#Opening IE to your WP site
$url = "http://$iisAppName/"

$IEwp = New-Object -com internetexplorer.application;
$IEwp.visible = $true; 
$IEwp.navigate($url);

#Opening your new WP folder with File Explorer
Start-Process explorer.exe $directoryPath

Read-Host -Prompt "Press Enter to exit" 