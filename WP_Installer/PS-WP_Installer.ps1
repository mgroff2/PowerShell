<# 

    .SYNOPSIS
    Install a new WP site with all pre-reqs using pre-set variables. Can be used for additional sites.
    
    .DESCRIPTION
    This script will create a WordPress site with known-working configurations.
    Script can also be used to add additional sites as checks are in place. 
    To customize site, update custom variables as desired. 
    CAUTION - this script will overwrite a current site
        
    .OUTPUTS  
    A new wp site ready for your configuration! ;-)
     
    .NOTES
    Author: Michael Groff
    Minimum OS: 2012, 2012 R2
    PS Version: 5.0
    Date:  1/12/17
    
#>


###
###Variables to fill out BELOW this line  ____________________________________________________________________________
###
#Site Name, must inclue the TLD (.com, .info, .net, etc.)
$iisAppName = "MyWordpressSite.com"
#IIS App Pool Name: 
$iisAppPoolName = "MyWordpressSite.com"
#Site Path
$directoryPath = "C:\inetpub\wwwroot\MyWordpressSite"
#Database Name
$dbn = "wordpress612"
#Database Username
$dbun ="wordpressuser612"
#Database User Password
$dbpw = "mysecretpassword612"
#MySQL root password
$MySQL = "v9gvBhTG@*b6n#^!v"
#Salt Keys - https://api.wordpress.org/secret-key/1.1/salt/ (NOTE: Replace any $ that you see with another character!)
#Authentication Key
$AuthKey = "ry=,b*Gp,+1-voDYM`zq#:S_^ODN Lp9:_:&D5o6C%0SXsyi<k`Q .Z]NK3144ay"
#Secure Authentication Key
$SecAuthKey = "f5h-Ss+}97fG%m+yS5X,zh3)>B/_/^C0x:sJv7Cta0+Cy=X_{E>[RN+A=-(*%Z+t"
#Logged In Key
$LogInKey = "N-< +[doN4gwtyk?PZK>=~iU8]-oS)wPt6l~.qMES}<vr v.Px`d#4MxOb`e.&7-"
#Nonce Key
$NKey = ":!!Pu0e5a?ux,+P)C[|T~,:IN,+m0H.6.JT%Ov_;_.J9;<@dCNpu|+@;L{G)W%|3"
#Authentication Salt
$AuthSalt = "SlHw{qnL#.kN--|u+Rw|kTe#(QR=Ak`_MUO8!#]`3L7.L=X<nX3><w/}MuRu9w`J"
#Secure Authentication Salt
$SecAuthSalt = "a}4L-qvxEx~x(f_]YiBgP(18%r)IerB+e4-I6m+ZkzgW4//V?x:P&:IvjIxguJIX"
#Logged In Salt
$LogInSalt = "d-O >T]uyh:9?Pu`i8|222S|eY5lW8,`lPwG-b|^-|8z5]j(P+-T6c[^PO;4ZM2q"
#Nonce Salt
$NSalt = "pT[la{_E,yMHhMu|F1F|k7*q+PQ]u[e zdUjj5(%&gZnsxUGJgYsi?:h[d|o`5I)"
#FTPUsername
$FTPSiteUser = "FTPUser"
#FTP Password - NOTE: Must be UNDER 14 characters, also must have a capital letter and special character
$FTPSiteUserPW = "FTPPass123!"
#FTP Group
$FTPGroup = "FTP_User_Group"
###
###Variables to fill out ABOVE this line #######  ____________________________________________________________________________
###

###Variables to leave alone: 
$iisAppPoolDotNetVersion = "v4.0"
$sitelocation = "IIS:\sites\$iisAppName"

#Checking Powershell Version

$LocalPSVers = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine\").PowerShellVersion | Where-Object {$_ -gt "5"}

IF (-not$LocalPSVers)
{
    Write-Host "
You need to upgrade to atleast PS Verion 5 before running this script!
" -ForegroundColor Red
    Read-Host "Press enter to exit"
    BREAK
}
ELSE
{
    Write-Host "
Correct Powershell Version found, you are good to go!
    " -ForegroundColor Green
}

Write-Host "Installing Windows Roles & Features if necessary... be patient" -ForegroundColor Cyan

#Windows Roles & Features if they are not already installed
Function Install-WP-Web-Features {
IF ( Get-WindowsFeature -Name Web-Server, Web-Log-Libraries, Web-Request-Monitor, Web-App-Dev, Web-Net-Ext45, Web-CGI, Web-Ftp-Server, NET-Framework-Features | Where {$_.InstallState -eq "Available"} )
        {
            Install-WindowsFeature -Name Web-Server, Web-Log-Libraries, Web-Request-Monitor, Web-App-Dev, Web-Net-Ext45, Web-CGI, Web-Ftp-Server, NET-Framework-Features -IncludeManagementTools
        }
        ELSE
        {
            Return  Write-Host "Necessary Windows Features are already installed!" -ForegroundColor Green
        }
}

Install-WP-Web-Features

#Create a new Website and AppPool for WP to live in

Import-Module WebAdministration

Write-Host "
Creating site and App Pool in IIS
" -ForegroundColor Cyan 

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
if (!(Test-Path $iisAppName -pathType container))
{
    #create the site
    $iisApp = New-Item $iisAppName -bindings @{protocol="http";bindingInformation=":80:" + $iisAppName} -physicalPath $directoryPath
    $iisApp | Set-ItemProperty -Name "applicationPool" -Value $iisAppPoolName
}

Write-Host "
Adding in hosts file entry
" -ForegroundColor Cyan 

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

#add host file entries
add-hostfilecontent -IPAddress 127.0.0.1 -computer $iisAppName

Write-Host "
Installing Web Platform Installer
" -ForegroundColor Cyan

#Install Web Platform Installer if its not already installed
$WPIPath = Test-Path "C:\Program Files\Microsoft\Web Platform Installer\WebPlatformInstaller.exe"
Function Install-WPI {
        IF (-not$WPIPath)
        {
            msiexec.exe /package http://download.microsoft.com/download/C/F/F/CFF3A0B8-99D4-41A2-AE1A-496C08BEB904/WebPlatformInstaller_amd64_en-US.msi /passive | Out-Null
        }
        ELSE
        {
            Return Write-Host "Web Plaform Installer 5.0 is already installed!" -ForegroundColor Green
            break
        }
} 

Install-WPI

#The .app info
Write-Host "If the script stopped here..." -ForegroundColor Red
Write-Host "you did not fill out the variable information above... correctly" -ForegroundColor Yellow

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

Write-Host "
Starting the WP install
" -ForegroundColor Cyan 

#Install WP & all necessary modules
cd $env:USERPROFILE\Desktop
WebPICMD.exe /Install /Application:Wordpress@wp.app /Products:PHP54,PHPManager /AcceptEULA /MySQLPassword:$MySQL /Log:$env:HOMEDRIVE\WPIntsalllog.txt

#Configure URL Rewrite Rule 
Add-WebConfigurationProperty -pspath $sitelocation -filter "system.webServer/rewrite/rules" -name "." -value @{name='Wordpress';patternSyntax='Wildcard'}
Set-WebConfigurationProperty -pspath $sitelocation -filter "system.webServer/rewrite/rules/rule[@name='Wordpress']/match" -name "url" -value "*"
Add-WebConfigurationProperty -pspath $sitelocation -filter "system.webServer/rewrite/rules/rule[@name='Wordpress']/conditions" -name "." -value @{input='{REQUEST_FILENAME}';matchType='IsFile';negate='True'}
Add-WebConfigurationProperty -pspath $sitelocation -filter "system.webServer/rewrite/rules/rule[@name='Wordpress']/conditions" -name "." -value @{input='{REQUEST_FILENAME}';matchType='IsDirectory';negate='True'}
Set-WebConfigurationProperty -pspath $sitelocation -filter "system.webServer/rewrite/rules/rule[@name='Wordpress']/action" -name "url" -value "index.php"

#Remove unnecessary Default Docs: 
Remove-WebConfigurationProperty  -pspath $sitelocation -filter "system.webServer/defaultDocument/files" -name "." -AtElement @{value='Default.htm'}
Remove-WebConfigurationProperty  -pspath $sitelocation -filter "system.webServer/defaultDocument/files" -name "." -AtElement @{value='Default.asp'}
Remove-WebConfigurationProperty  -pspath $sitelocation -filter "system.webServer/defaultDocument/files" -name "." -AtElement @{value='index.htm'}
Remove-WebConfigurationProperty  -pspath $sitelocation -filter "system.webServer/defaultDocument/files" -name "." -AtElement @{value='index.html'}
Remove-WebConfigurationProperty  -pspath $sitelocation -filter "system.webServer/defaultDocument/files" -name "." -AtElement @{value='iisstart.htm'}

#Remove PHP 5.5 as WP only works with 5.4 afaik: 
$TestPHP55 =  Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/handlers/add[@name='PHP55_via_FastCGI']"  -Name "type"

IF ($TestPHP55)
{     
    Remove-WebConfigurationProperty  -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/handlers" -name "." -AtElement @{name='PHP55_via_FastCGI'}           
}
ELSE
{
    Write-Host "
    PHP 5.5 has already been removed!
    " -ForegroundColor Green
}

Write-Host "
Creating User and Group for FTP
" -ForegroundColor Cyan 
#Create FTP Group & User - Uses preset variables 

#Group Creation

IF (-not (Get-WmiObject -Class Win32_Group | Where-Object {$_.Name -eq "$FTPGroup"}))
{
    Invoke-Command -ScriptBlock {net localgroup /add $FTPGroup}
}
ELSE
{
    Write-Host "Local Group already exists" -ForegroundColor Red
}

#Users Creation

IF (-not (Get-WmiObject -Class Win32_UserAccount | Where-Object {$_.Name -eq "$FTPSiteUser"}))
{
    Invoke-Command -ScriptBlock {net user /add $FTPSiteUser $FTPSiteUserPW} -ErrorAction SilentlyContinue
}
ELSE
{
    Write-Host "Local User already exists" -ForegroundColor Red
}

#Add User to Group
$TestFTPGroupExist = (get-wmiobject Win32_GroupUser | where {$_.GroupComponent -like "*$FTPGroup*"}).partcomponent

IF (-not ($TestFTPGroupExist))
{
    Invoke-Command -ScriptBlock {net localgroup $FTPGroup $FTPSiteUser /add }
}
ELSE
{
    Write-Host "Local User had already been added to necessary group" -ForegroundColor Red
}

#Create FTP Site (To update Wordpress and Plugins)
$FTPSiteName = "Main FTP"
$FTPSitePath = "C:\inetpub\ftproot"
$FTPSitePathLocUsr = "C:\inetpub\ftproot\LocalUser"

IF (-not (Test-Path -Path "$FTPSitePathLocUsr"))
{
    New-Item -Path $FTPSitePathLocUsr -ItemType Directory -ErrorAction SilentlyContinue
    New-Item -Path $FTPSitePath -ItemType Directory -ErrorAction SilentlyContinue
    New-WebFtpSite -Name $FTPSiteName -PhysicalPath $FTPSitePath -IPAddress * -Port 21
}
ELSE
{
    Write-Host "
    FTP Site already exists in needed location: 'C:\inetpub\ftproot\LocalUser'
    Updating your WordPress site will not work as it should
    " -ForegroundColor Red
} 

IF (-not (Get-WebVirtualDirectory -Name "*$FTPSiteUser*") )
{
    New-WebVirtualDirectory -Site "$FTPSiteName\LocalUser" -Name $FTPSiteUser -PhysicalPath $directoryPath -ErrorAction SilentlyContinue
}
ELSE
{
   Write-Host "
    Virtual Directory for FTP Site already exists
    " -ForegroundColor Red 
}

#Setting User Permissions for FTP User Group in IIS - Adding Authorization in IIS

#Giving Windows Group permissions to site for FTP
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location 'Main FTP' -filter "system.ftpServer/security/authorization" -name "." -value @{accessType='Allow';roles="$FTPGroup";permissions='Read,Write'}

#Enable Basic Auth for the FTP Site
Set-ItemProperty "IIS:\Sites\$FTPSiteName" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true

#Setup User Isolation
Set-ItemProperty "IIS:\Sites\$FTPSiteName" -Name ftpServer.userisolation.mode -Value IsolateAllDirectories

#Disable Require SSL on FTP Site
Set-ItemProperty "IIS:\Sites\Main FTP" -Name ftpServer.security.ssl.controlChannelPolicy -Value SslAllow
Set-ItemProperty "IIS:\Sites\Main FTP" -Name ftpServer.security.ssl.dataChannelPolicy -Value SslAllow

#Permission for FTP user to WP Directory
$FTPAcl = Get-Acl -Path "$directoryPath"
$FTPAclUser = New-Object system.security.accesscontrol.filesystemaccessrule("$FTPGroup","FullControl","ContainerInherit, ObjectInherit","None","Allow")
$FTPAcl.SetAccessRule($FTPAclUser)
Set-Acl -Path "$directoryPath" -AclObject $FTPAcl

#Finishing up and loading your site
#Cleanup
Remove-Item $env:USERPROFILE\Desktop\wp.app -Force

#Disable IE Enhanced Security & UAC
function Disable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer
    Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
}
function Enable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 1
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 1
    Stop-Process -Name Explorer
    Write-Host "IE Enhanced Security Configuration (ESC) has been enabled." -ForegroundColor Green
}
function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000
    Write-Host "User Access Control (UAC) has been disabled." -ForegroundColor Green    
}

Disable-InternetExplorerESC
Write-Host ""
Disable-UserAccessControl
Write-Host "
Done! Now go configure your site" -ForegroundColor Green 
#Opening IE to your WP site
$url = "http://$iisAppName/"

$IEwp = New-Object -com internetexplorer.application;
$IEwp.visible = $true; 
$IEwp.navigate($url);

#Opening your new WP folder with File Explorer
Start-Process $directoryPath

#Openeing WP Install Log file for review
Start-Process $env:HOMEDRIVE\WPIntsalllog.txt

#Open IIS
Start-Process C:\Windows\system32\inetsrv\inetmgr.exe

Write-Host ""
Read-Host -Prompt "Press Enter to exit" 