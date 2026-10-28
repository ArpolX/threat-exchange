package domain

type Category string

const (
	CategoryUnknown    Category = "unknown"
	CategoryTrojan     Category = "trojan"
	CategoryRansomware Category = "ransomware"
	CategorySpyware    Category = "spyware"
	CategoryAdware     Category = "adware"
	CategoryWorm       Category = "worm"
	CategoryVirus      Category = "virus"
	CategoryRootkit    Category = "rootkit"
	CategoryOther      Category = "other"
)

func (c Category) Valid() bool {
	switch c {
	case CategoryUnknown, CategoryTrojan, CategoryRansomware, CategorySpyware, CategoryAdware,
		CategoryWorm, CategoryVirus, CategoryRootkit, CategoryOther:
		return true
	default:
		return false
	}
}
