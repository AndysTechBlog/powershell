<#
.SYNOPSIS
	Get information about locked out Active Directory accounts

.DESCRIPTION
	This script will return a list containing the lock status of a certain user account on all domain controllers. Additionally it queries for lockdown events (Event id 4740) for that user on all domain controller.

.NOTES
	Name: Get-ADLockoutStatus
	Author: Andy
	

.EXAMPLE
	Get-ADLockoutStatus -Username testuser

	Description:
	Gets lockout information for the user "testuser"

.PARAMETER Username
	Domain user name for which the lockout information are being searched.

#>
Param(
	[Parameter(Mandatory = $True, HelpMessage = "User name to check")]
	[string]$Username
)

$DCs=Get-ADDomainController -Filter *
$table=@()
$i=0
foreach ($DC in $DCs){
	$i++
	$Percent=[int]($i/$($DCs | measure).Count*100)
	Write-Progress -Activity "Querying DC $DC.Name" -Status "$Percent% done" -PercentComplete $Percent
	$User=Get-ADUser -Identity $Username -Server $DC -Properties SamAccountName,LockedOut,badPwdCount,badPasswordTime
	$BadPwdTime=[datetime]::FromFileTime($User.badPasswordTime)
	$LockedOut=$User.LockedOut
	$BadPwdCount=$User.BadPwdCount
	$row = New-Object PSObject
	$row | Add-Member NoteProperty "Username" $User.samaccountname
	$row | Add-Member NoteProperty "DomainController" $DC
	$row | Add-Member NoteProperty "Locked" $LockedOut
	$row | Add-Member NoteProperty "BadPwdCount" $BadPwdCount
	$row | Add-Member NoteProperty "BadPwdTime" $BadPwdTime
	$table+=$row	
}
Write-Host ($table | Format-Table | Out-String)