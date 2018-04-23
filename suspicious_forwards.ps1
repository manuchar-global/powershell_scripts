function ConnectExchangeOnline {
	$UserCredential = Get-Credential
	$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
	Import-PSSession $Session
}

function GetForwardingAddresses() {
	Get-Mailbox -ResultSize Unlimited | select identity, forwardingSMTPAddress
}

function GetDomains() {
	[String[]] $domains = @()
	Get-AcceptedDomain | ForEach-Object {
		$domains = $domains + $_.DomainName	
	}
	return $domains
}

function isExternalAddress($email, $domains) {
	$external = $true
	If(-Not $domains) {
		$domains = getDomains
	}
	if(-Not $email) {
		return $false
	}
	$domains | ForEach-object {
		$domainMatch = "*" + $_ 
		If($email -And ($email -like $domainMatch) ) {
			$external = $false
		} 
	}
	return $external
}

function GetSuspiciousForwards() {
	$forwards = @()
	$domains = GetDomains
	$forwardingAddresses = getForwardingAddresses
	If($forwardingAddresses -ne $null) {
		$forwardingAddresses | ForEach-Object {
			$forward = $_
			$forwardingAddress = $forward.ForwardingSmtpAddress
			If($forwardingAddress -ne $null) {
				$forwardingAddress = $forwardingAddress.Replace("smtp:","")
				$suspicious = isExternalAddress $forwardingAddress $domains
				if($suspicious -eq $true) {
					$Object = New-Object -TypeName PSObject
					$Object | Add-Member -MemberType NoteProperty -Name Identity -Value $forward.Identity
					$Object | Add-Member -MemberType NoteProperty -Name ForwardingAddress -Value $forwardingAddress
					$forwards = $forwards + $Object
				}
			}
		}
	}
	return $forwards
}

function GetForwardingRules() {
	$FormatEnumerationLimit = -1
	$rules = @()
	Get-MailBox -ResultSize Unlimited| Foreach-Object {
		$mailbox = $_
		#Write-Host("Checking rules for " + $mailbox.PrimarySMTPAddress + "...")
		Get-InboxRule -Mailbox $_.PrimarySMTPAddress | where { ( $_.forwardAsAttachmentTo -ne $NULL  ) -or ( $_.forwardTo -ne $NULL ) -or ( $_.redirectTo -ne $NULL ) } | ForEach-Object {
			$rule = Get-InboxRule -Identity $_.Identity
			$rules = $rules + $rule
		}
	}
	return $rules
}

function CheckRuleComponent($component, $domains) {
	$component | select-string -pattern "\[(.*?)\]" -AllMatches | ForEach {
		If ($_.Matches.Groups[1].Value -like "SMTP:*") {
			$email = $_.Matches.Groups[1].Value.Replace("SMTP:","")
			If(isExternalAddress $email $domains) {
				$suspicious_forwards = $suspicious_forwards + $email
				return $suspicious_forwards
			}
		}
	}
}

function GetSuspiciousForwardingRules(){
	$domains = GetDomains
	$rules = GetForwardingRules
	$suspicious_rules = @()
	$rules | foreach-Object {
		$rule = $_
		$suspicious_forwards = @()
		If($rule.RedirectTo) {
			$suspicious_forwards = CheckRuleComponent $rule.RedirectTo $domains
		}
		If($rule.ForwardTo) {
			$suspicious_forwards = $suspicious_forwards + ( CheckRuleComponent $rule.ForwardTo $domains )
		}
		If($rule.ForwardAsAttachmentTo) {
			$suspicious_forwards = $suspicious_forwards + ( CheckRuleComponent $rule.ForwardAsAttachmentTo $domains )
		}
		if($suspicious_forwards) {
			$Object = New-Object -TypeName PSObject
			$Object | Add-Member -MemberType NoteProperty -Name Owner -Value $rule.identity.split("\")[0]
			$Object | Add-Member -MemberType NoteProperty -Name Name -Value $rule.name
			$Object | Add-Member -MemberType NoteProperty -Name Addresses -Value $suspicious_forwards
			$suspicious_rules = $suspicious_rules + $Object
		}
	}
	return $suspicious_rules
}

function CheckMemberships([String[]] $Groups) {
	If( -Not $Groups ){
		$Groups = GetMemberGroups
	}
	Get-Mailbox -ResultSize Unlimited | ForEach-Object {
		If ( ($_.IsShared -eq $false) -and ($_.AccountDisabled -eq $false) -and ($_.IsResource -eq $false) ) {
			$Memberships = ValidateMembership -Email $_.PrimarySMTPAddress -Groups $Groups
			$Object = New-Object -TypeName PSObject
			$Object | Add-Member -MemberType NoteProperty -Name Email -Value $_.PrimarySMTPAddress
			If ($Memberships) {
				$Object | Add-Member -MemberType NoteProperty -Name IsMember -Value $true
				$Object | Add-Member -MemberType NoteProperty -Name MembershipCount -Value $Memberships.Count
			} Else {
				$Object | Add-Member -MemberType NoteProperty -Name IsMember -Value $false
				$Object | Add-Member -MemberType NoteProperty -Name MembershipCount -Value 0
			}
			$Object | Add-Member -MemberType NoteProperty -Name Country -Value $_.UsageLocation
			$Object | Add-Member -MemberType NoteProperty -Name Memberships -Value $Memberships
			return $Object
		}
	}
}

function SuspiciousForwardsReport() {
	$suspicious_forwards = GetSuspiciousForwards
	$suspicious_rules = GetSuspiciousForwardingRules

	if ($suspicious_forwards) {
		"The following users have suspicious forwards:"
		$suspicious_forwards | ft
	} else {
		"No users have suspicious forwards."
	}

	""

	if ($suspicious_rules){
		"The following users have suspicious forwarding rules:"
		$suspicious_rules | ft
	} else {
		"No users have suspicious forwarding rules."
	}

}

ConnectExchangeOnline
SuspiciousForwardsReport