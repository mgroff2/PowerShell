#FTP_Site_virt_dir

##Install an FTP site with a Powershell Script

This script was written with the intent to configure a new FTP site on a server from a "common" Golden Image. The FTP site is configured with virtual directories and a user to match that directory. 
After the first site has been created, this script can be run again to add more users matched to directories as you see fit. 



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



##Run the script with: 

	& .\FTP_Site_virt_dir.ps1