package tokens

const (
	AdminRole      = "admin"
	UserRole       = "user"
	VerifyUserRole = "verify_user"
	ModeratorRole  = "moderator"
)

func IsSupportedRole(role string) bool {
	switch role {
	case AdminRole, UserRole, VerifyUserRole, ModeratorRole:
		return true
	}
	return false
}
