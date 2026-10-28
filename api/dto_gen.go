package api

import (
	"time"
)

const (
	CategoryAdware     Category = "adware"
	CategoryOther      Category = "other"
	CategoryRansomware Category = "ransomware"
	CategoryRootkit    Category = "rootkit"
	CategorySpyware    Category = "spyware"
	CategoryTrojan     Category = "trojan"
	CategoryUnknown    Category = "unknown"
	CategoryVirus      Category = "virus"
	CategoryWorm       Category = "worm"
)

func (e Category) Valid() bool {
	switch e {
	case CategoryAdware:
		return true
	case CategoryOther:
		return true
	case CategoryRansomware:
		return true
	case CategoryRootkit:
		return true
	case CategorySpyware:
		return true
	case CategoryTrojan:
		return true
	case CategoryUnknown:
		return true
	case CategoryVirus:
		return true
	case CategoryWorm:
		return true
	default:
		return false
	}
}

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityUnknown  Severity = "unknown"
)

func (e Severity) Valid() bool {
	switch e {
	case SeverityCritical:
		return true
	case SeverityHigh:
		return true
	case SeverityLow:
		return true
	case SeverityMedium:
		return true
	case SeverityUnknown:
		return true
	default:
		return false
	}
}

type Category string

type ErrorResponse struct {
	Details *string `json:"details,omitempty"`

	Message string `json:"message"`
}

type Severity string

type ThreatCreateRequest struct {
	Category *Category `json:"category,omitempty"`

	Description *string `json:"description,omitempty"`

	Md5 string `json:"md5"`

	Name string `json:"name"`

	Severity *Severity `json:"severity,omitempty"`

	Sha256 *string `json:"sha256,omitempty"`

	Source *string `json:"source,omitempty"`
}

type ThreatResponse struct {
	Category Category `json:"category"`

	CreatedAt *time.Time `json:"created_at,omitempty"`

	Description string `json:"description"`

	Md5 string `json:"md5"`

	Name string `json:"name"`

	Severity Severity `json:"severity"`

	Sha256 *string `json:"sha256"`

	Source string `json:"source"`

	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

type ThreatUpdateRequest struct {
	Category *Category `json:"category,omitempty"`

	Description *string `json:"description,omitempty"`

	Name string `json:"name"`

	Severity *Severity `json:"severity,omitempty"`

	Sha256 *string `json:"sha256,omitempty"`

	Source *string `json:"source,omitempty"`
}

type BadRequest = ErrorResponse

type Conflict = ErrorResponse

type InternalError = ErrorResponse

type NotFound = ErrorResponse

type ThreatFound = ThreatResponse

type TooLarge = ErrorResponse

type TooManyRequests = ErrorResponse

type Unauthorized = ErrorResponse

type UnsupportedMediaType = ErrorResponse

type CreateThreatJSONRequestBody = ThreatCreateRequest

type UpdateThreatJSONRequestBody = ThreatUpdateRequest
