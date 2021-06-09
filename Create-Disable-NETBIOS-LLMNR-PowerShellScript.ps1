## Created by Sameer Sheikh
## getatme@ssheikh.com
## Version 1.0
## Purpose: Create a Powershell script from content within this Powershell script, then register it as a scheduled task. Created for EndPoint Manager deployment.
 
########################################
# Define PS Script Data to Create Here #
########################################
$PSScriptContent = @'
## Version 1.0 - Deployed 2021/06/08
## Run in system context

Function Test-RegistryValue
{
param([string]$RegKeyPath,[string]$Value)
$ValueExist = (Get-ItemProperty $RegKeyPath).$Value -ne $null
Return $ValueExist
}

## Disables NETBIOS on all adapters
set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip* -Name NetbiosOptions -Value 2

## Disable LLMNR
$regKeyDNSClient = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

if(Test-Path $regKeyDNSClient)
{
}
else
{
New-Item -Path $regKeyDNSClient -Force | Out-Null
}

if(Test-RegistryValue -RegKeyPath $regKeyDNSClient -Value "EnableMulticast")
{
set-ItemProperty -path $regKeyDNSClient -Name EnableMulticast -Value "0"
}
else
{
New-ItemProperty -path $regKeyDNSClient -Name EnableMulticast -PropertyType DWORD -Value "0"
}
'@

#####################################################
# Define Where to Locally Store Created Script Here #
#####################################################

$dirpath = $(Join-Path $env:ProgramData EndpointDeployment\Scripts)
$scriptname = "Disable-NETBIOS-LLMNR.ps1"
$scheduledtaskname = "EndpointManager-Disable-NETBIOS-LLMNR"

#######################################
# Creating the PowerShell Script Here #
#######################################

if (!(Test-Path $dirpath))
{
New-Item -Path $dirpath -ItemType Directory -Force -Confirm:$false
}
Out-File -FilePath $(Join-Path $dirpath $scriptname) -Encoding unicode -Force -InputObject $PSScriptContent -Confirm:$false

##################################################################################################################
# Register newly created PowerShell script as a scheduled task that runs at every logon under the SYSTEM context #
##################################################################################################################

$Time = New-ScheduledTaskTrigger -AtLogon
$User = "SYSTEM"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ex bypass -file ""$(Join-Path $dirpath $scriptname)"
Register-ScheduledTask -TaskName "$scheduledtaskname" -Trigger $Time -User $User -Action $Action -Force

##############################
# Immediately start the task #
##############################

Start-ScheduledTask -TaskName $scheduledtaskname
