<#
.SYNOPSIS
	Get information about lockout events for a user

.DESCRIPTION
	This script will return a list of account lockout events (ID 4740) for a certain user

.NOTES
	Name: Get-ADLockoutEvents
	Author: Andy
	

.EXAMPLE
	Get-ADLockoutEvents -Username testuser

	Description:
	Gets lockout events for the user "testuser"

.PARAMETER Username
	Domain user name for which the lockout events are being searched.

#>
Param(
	[Parameter(Mandatory = $True, HelpMessage = "User name to check")]
	[string]$Username
)

$DCs=Get-ADDomainController -Filter *

$tableEvents=@()
foreach ($DC in $DCs)
{
	$User=Get-ADUser -Identity $Username -Server $DC -Properties SamAccountName
	if($($User|measure).count -eq 0){break} #If user is not present on that domain controller, break loop
	$Events=Get-WinEvent -ComputerName $DC -FilterHashtable @{Logname='Security';ID=4740} -ErrorAction SilentlyContinue
	Foreach($Event in $Events)
	{
		$eventXML = [xml]$Event.ToXml()
		if ($eventXML.Event.EventData.Data[0].'#Text' -eq $Username){
			$row = New-Object PSObject
			$row | Add-Member -MemberType NoteProperty -Name "DomainController" -Value $DC
			$row | Add-Member NoteProperty "Time" $Event.timecreated
			$row | Add-Member NoteProperty "Client" $eventXML.Event.EventData.Data[1].'#Text'
			$tableEvents+=$row
		}
	
	}
}
Write-Host ($tableEvents | Format-Table | Out-String)