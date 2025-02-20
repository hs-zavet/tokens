package identity

import "fmt"

type IdnType string

const (
	Service   IdnType = "service"
	SuperUser IdnType = "super_user"
	Admin     IdnType = "admin"
	User      IdnType = "user"
)

func ParseIdentityType(i string) (IdnType, error) {
	switch i {
	case "service":
		return Service, nil
	case "super_user":
		return SuperUser, nil
	case "admin":
		return Admin, nil
	case "user":
		return User, nil
	default:
		return "", fmt.Errorf("incorect Identity type")
	}
}

//	1, if first role is higher priority
//
// -1, if second role is higher priority
//
//	0, if roles are equal
func CompareRolesUser(role1, role2 IdnType) int {
	priority := map[IdnType]int{
		SuperUser: 3,
		Service:   2,
		Admin:     2,
		User:      1,
	}

	p1, ok1 := priority[role1]
	p2, ok2 := priority[role2]

	if !ok1 || !ok2 {
		return -1
	}

	if p1 > p2 {
		return 1
	} else if p1 < p2 {
		return -1
	}
	return 0
}
