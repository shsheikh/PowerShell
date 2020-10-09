$applicationNameToSearch = "FortiClient SSLVPN v4.0.2303"
$applicationVersionToSearch = "4.0.2303"
$outputcode = 1

function Get-ApplicationVersion 
{
$my_check = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallDate | Where -property displayName -Match $applicationNameToSearch
    #If my_check is not null, check for version match
    if ($my_check) 
        {
        $versionNumber = $my_check.DisplayVersion
            if ($versionnumber.Equals($applicationVersionToSearch))
                {
                #write-output "Match found: $applicationNameToSearch version $applicationVersionToSearch found, calling uninstall function."
                Uninstall-Application
                }
#            else 
#                {
#                #write-output "Match failed: $applicationNameToSearch version $versionNumber was found, but wanted $applicationVersionToSearch."
#                }
        }
    else 
        {
        #writing success code for Intune to pick up
        write-output $outputcode
        Exit 0
        }
}

function Uninstall-Application
{
#Stopping the FortiClient service
Get-Service -DisplayName "FortiClient SSLVPN" | Stop-Service

#Force closing running programs
Stop-Process -Name "FortiSSLVPNclient" -Force
Stop-Process -Name "FortiSSLVPNdaemon" -Force

#This uninstalls 'FortiClient SSLVPN v4.0.2302'
Start-Process msiexec.exe -Wait -ArgumentList '/x {A34DCE59-0004-0000-2303-3F8A9926B752} /qn'

#Cleans up the directory in case it is left behind
#Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\ZOHO Corp\" -Confirm:$false -Recurse
Remove-Item -Path "C:\Program Files (x86)\Fortinet\" -Confirm:$false -Recurse
write-output $outputcode
Exit 0
}

#This starts the process. Checks for the application, and, if found, calls the uninstall script block. 
Get-ApplicationVersion