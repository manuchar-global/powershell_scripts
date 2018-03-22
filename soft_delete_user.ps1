# This script deletes a Office365 user and stores it in the trash for 30 days.

Connect-MsolService
$email = Read-Host "Enter the e-mail address of the user you want to delete"
Remove-MsolUser -UserPrincipalName $email