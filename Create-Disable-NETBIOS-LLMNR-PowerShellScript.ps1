# Author: Sameer Sheikh
# Date: 2021/06/09
# Description: Create a Powershell script from content within this Powershell script, then register it as a scheduled task. Created for EndPoint Manager deployment.
 
########################################
# Define PS Script Data to Create Here #
########################################
$PSScriptContent = @'
## Version 1.1 - Deployed 2021/06/09
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

$FileDeploymentPath = $(Join-Path $env:ProgramData EndpointDeployment\Scripts)
$PSScriptName = "Disable-NETBIOS-LLMNR.ps1"
$SchTaskName = "EndpointManager-Disable-NETBIOS-LLMNR"

#######################################
# Creating the PowerShell Script Here #
#######################################

if (!(Test-Path $FileDeploymentPath))
{
New-Item -Path $FileDeploymentPath -ItemType Directory -Force -Confirm:$false
}
Out-File -FilePath $(Join-Path $FileDeploymentPath $PSScriptName) -Encoding unicode -Force -InputObject $PSScriptContent -Confirm:$false

#############################################################################
# Define your variables for the scheduled task to be created and registered #
#############################################################################

$SchTaskTrigger1 = New-ScheduledTaskTrigger -AtLogon
$SchTaskRunAsUser = "SYSTEM"
$SchTaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ex bypass -file ""$(Join-Path $FileDeploymentPath $PSScriptName)"
$SchTaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

########################################################################################
# Creating Scheduled Task using the above variables to run the PS Script created above #
########################################################################################

Register-ScheduledTask -TaskName "$SchTaskName" -Trigger $SchTaskTrigger1 -User $SchTaskRunAsUser -Action $SchTaskAction -Settings $SchTaskSettings -Force 

##############################
# Immediately start the task #
##############################

Start-ScheduledTask -TaskName $SchTaskName
