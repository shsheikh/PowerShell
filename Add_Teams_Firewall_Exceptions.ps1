## Created by Sameer Sheikh
## getatme@ssheikh.com
## Version 1.0

## This is a workaround for Microsoft's interesting coding choices for Teams.
## As a quick summary, Teams requires firewall rules that are specific to each user on the machine.
## If they aren't there, Teams pops up a prompt asking to add them.
## It's an elevated prompt which reults in helpdesk ticket if they aren't admins (and they should not be!)
## Uservoice for more info: https://microsoftteams.uservoice.com/forums/555103-public/suggestions/33697582-microsoft-teams-windows-firewall-pop-up

## As a basic rundown, this script:
## Gets the user that triggered the script by looking at the Task Scheduler log
## Trims the domain from the result to give just the username
## To get the root path (99% of the time it's C:\Users\), it looks up where #env:public points to and uses that
## Then it takes a few variables and builds the path to the Teams.exe file.
## With the user file path built (whew.), it checks to see Teams has already created the TCP\UDP block rules. If it finds them, it deletes them (I like consistency). 
## With a clean slate, it then checks to see if the rules have been added before, and if not, creates them.

## To set up, modify the variables in the first section below.
## With the changes made, copy the script somewhere local on the machine, then create a Scheduled Task that triggers on user logon and executes this script.
## I do the above with a GPO, but other methods will work as long as the end result is the same.

#-----------------------------#
#   Set your variables here!  #
#-----------------------------#

## First, set the program location that exists under the user's profile. The rest of the script builds the beginning of the path.
$pathtoexe = '\AppData\Local\Microsoft\Teams\current\teams.exe'
## Set the name you want the rule to be called in Windows Defender Advanced Firewall.
$firewallRuleName = 'teams.exe'
## The script searches the scheduled task logs. Set the Scheduled Task name you intend to use here.
$scheduledtaskname = 'Teams_Firewall_Rules_All_Users'
## Set the domain you want this to work in. To see what this value should be, run 'whoami' from a logged in user and look for the name before the \.
$domainname = "CONTOSO"
## Set where you want your log file to save
$logfilepath = 'C:\Install_Log\TeamsFWRules.log'

#-----------------------------#
# Here's the actual code part #
#-----------------------------#

function Get-TimeStamp
{
return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)         
}

Write-Output "$(Get-TimeStamp) Script triggered due to login." | out-file -filepath $logfilepath -append
# Sleeping for 2 seconds to allow log to be written. This value can be tweaked for slower\faster systems, but it should exist.
Start-Sleep 2
# Searching the Task Scheduler log in the last minute to see who triggered the script, returns the first hit only, then captures the DOMAIN\USERNAME value only.
$LastLoggedOnUserFull = Get-WinEvent -FilterHashtable @{logname=”Microsoft-Windows-TaskScheduler/Operational”;ID=119;starttime=((Get-Date).AddMinutes(-1))} | Where {$_.Message -match $scheduledtaskname} | select -first 1 @{N='User';E={$_.Properties[1].Value}} | select -expand User

if (!$LastLoggedOnUserFull)
{
Write-Output "$(Get-TimeStamp) Script ending due to no user found." | out-file -filepath $logfilepath -append
exit
}

Write-Output "$(Get-TimeStamp) $LastLoggedOnUserFull found in event log" | out-file -filepath $logfilepath -append

## Trim the domain out of the username
$LastLoggedOnUser = $LastLoggedOnUserFull.Trim("$domainname\")

# Couldn't find a variable for the general users directory (since it's not always C:\Users), so instead I use the Public environment and trim the folder from the result.
$PrimaryUserFolders = $env:public.Trim("\Public")

# Combine everything to make a file path for the user to the requested program.
$ProgramLoc = $PrimaryUserFolders + "\$LastLoggedOnUser" + $pathtoexe

# Now taking the file path created above to search existing firewall rules. 

$TCPRuleAddedByTeamsBlocked = Get-NetFirewallRule -Name TCP*$ProgramLoc -ErrorAction SilentlyContinue | select name, action
$UDPRuleAddedByTeamsBlocked = Get-NetFirewallRule -Name UDP*$ProgramLoc -ErrorAction SilentlyContinue | select name, action

$TCPRuleAlreadyAdded = Get-NetFirewallRule -Name "$firewallRuleName TCP Allow for $LastLoggedOnUser via script" -ErrorAction SilentlyContinue | select name, action
$UDPRuleAlreadyAdded = Get-NetFirewallRule -Name "$firewallRuleName UDP Allow for $LastLoggedOnUser via script" -ErrorAction SilentlyContinue | select name, action

# Delete existing block rule if it exists, build the proper rules if they don't exist.
 
if(!$TCPRuleAddedByTeamsBlocked)
{
Write-Output "$(Get-TimeStamp) Nothing to do. Existing block TCP firewall rule for $lastloggedonuser does not exist." | out-file -filepath $logfilepath -append
}
elseif($TCPRuleAddedByTeamsBlocked.action = "Block")
{
Remove-NetFirewallRule -name $TCPRuleAddedByTeamsBlocked.name
Write-Output "$(Get-TimeStamp) TCP Block rule for $lastloggedonuser removed." | out-file -filepath $logfilepath -append
}

if(!$UDPRuleAddedByTeamsBlocked)
{
Write-Output "$(Get-TimeStamp) Nothing to do. Existing block UDP firewall rule for $lastloggedonuser does not exist." | out-file -filepath $logfilepath -append
}
elseif($UDPRuleAddedByTeamsBlocked.action = "Block")
{
Remove-NetFirewallRule -name $UDPRuleAddedByTeamsBlocked.name
Write-Output "$(Get-TimeStamp) UDP Block rule for $lastloggedonuser removed." | out-file -filepath $logfilepath -append
}

if(!$TCPRuleAlreadyAdded)
{
New-NetfirewallRule -DisplayName $firewallRuleName -name "$firewallRuleName TCP Allow for $LastLoggedOnUser via script" -Direction Inbound -Protocol TCP -Profile Any -Program $ProgramLoc -Action Allow -EdgeTraversalPolicy DeferToUser
Write-Output "$(Get-TimeStamp) New TCP firewall rule added for $LastLoggedOnUser" | out-file -filepath $logfilepath -append
}
elseif($TCPRuleAlreadyAdded.action = 'Allow')
{
Write-Output "$(Get-TimeStamp) Nothing to do. Existing TCP firewall rule for $lastloggedonuser already set to allow." | out-file -filepath $logfilepath -append
}

if(!$UDPRuleAlreadyAdded)
{
New-NetfirewallRule -DisplayName $firewallRuleName -name "$firewallRuleName UDP Allow for $LastLoggedOnUser via script" -Direction Inbound -Protocol UDP -Profile Any -Program $ProgramLoc -Action Allow -EdgeTraversalPolicy DeferToUser
Write-Output "$(Get-TimeStamp) New UDP firewall rule added for $LastLoggedOnUser" | out-file -filepath $logfilepath -append
}
elseif($UDPRuleAlreadyAdded.action = 'Allow')
{
Write-Output "$(Get-TimeStamp) Nothing to do. Existing UDP firewall rule for $lastloggedonuser already set to allow." | out-file -filepath $logfilepath -append
}
