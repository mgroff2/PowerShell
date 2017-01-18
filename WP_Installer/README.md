# PS-WP_Installer

##Wordpress Installation with a Powershell Script

This script was written with the intent to configure WordPress on a server from a "common" Golden Image. 
After the first site has been created, this script can be run again to add more sites as you see fit. 



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
    Date:  1/18/17
	


##Run the script with: 

	& .\PS-WP_Installer.ps1