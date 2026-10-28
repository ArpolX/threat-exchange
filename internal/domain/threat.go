package domain

import "time"

type ThreatInput struct {
	Name        string
	Description string
	Severity    Severity
	Category    Category
	Source      string
	SHA256      *string
}

type Threat struct {
	MD5 string
	ThreatInput
	CreatedAt time.Time
	UpdatedAt time.Time
}
