# This scripts lists all groups of which a user is a member or a manager.

$credential = Get-Credential
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $credential -Authentication Basic -AllowRedirection
Import-PSSession $session

$email = Read-Host "Enter the e-mail address of which you want to check group memberships"
$user = Get-User $email

Write-Host "The user is a member of the following groups:"
Get-Group -Filter "Members -eq '$($user.DistinguishedName)'" | Format-Table DisplayName, RecipientType

Write-Host "The user manages the following groups:"
Get-Group -Filter "ManagedBy -eq '$($user.DistinguishedName)'" | Format-Table DisplayName, RecipientType

Remove-PSSession $session
