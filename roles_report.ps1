Connect-MsolService

function GetRoleMembers($name) {

	$Role = Get-MsolRole -RoleName $name
	Get-MsolRoleMember -RoleObjectId $Role.ObjectID | select DisplayName, EmailAddress | ft

}


function RoleMembersReport() {
	" "
	"The are the users with important roles in the Office 365 organization:"

	$Roles = Get-MsolRole

	ForEach ($Role in $Roles) {
		$Role.Name + ":"
		GetRoleMembers($Role.Name)
	}
}

RoleMembersReport
