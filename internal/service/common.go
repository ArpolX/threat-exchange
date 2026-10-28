package service

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"threat-exchange/internal/apperror"
	"threat-exchange/internal/domain"
)

func normalizeMD5(value string) (string, error) {
	if !validHash(value, 32) {
		return "", fmt.Errorf("%w: MD5 must contain exactly 32 hexadecimal characters", apperror.ErrInvalidInput)
	}
	return strings.ToLower(value), nil
}

func normalizeInput(input domain.ThreatInput) (domain.ThreatInput, error) {
	if strings.ContainsRune(input.Name, 0) || strings.ContainsRune(input.Description, 0) || strings.ContainsRune(input.Source, 0) {
		return domain.ThreatInput{}, fmt.Errorf("%w: text fields must not contain NUL", apperror.ErrInvalidInput)
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	input.Source = strings.TrimSpace(input.Source)
	if input.Name == "" || utf8.RuneCountInString(input.Name) > 255 {
		return domain.ThreatInput{}, fmt.Errorf("%w: name must contain from 1 to 255 characters", apperror.ErrInvalidInput)
	}
	if utf8.RuneCountInString(input.Description) > 4096 || utf8.RuneCountInString(input.Source) > 255 {
		return domain.ThreatInput{}, fmt.Errorf("%w: description is limited to 4096 and source to 255 characters", apperror.ErrInvalidInput)
	}
	if input.Severity == "" {
		input.Severity = domain.SeverityUnknown
	}
	if input.Category == "" {
		input.Category = domain.CategoryUnknown
	}
	if !input.Severity.Valid() || !input.Category.Valid() {
		return domain.ThreatInput{}, fmt.Errorf("%w: unsupported severity or category", apperror.ErrInvalidInput)
	}
	if input.SHA256 != nil {
		if !validHash(*input.SHA256, 64) {
			return domain.ThreatInput{}, fmt.Errorf("%w: SHA-256 must contain exactly 64 hexadecimal characters", apperror.ErrInvalidInput)
		}
		hash := strings.ToLower(*input.SHA256)
		input.SHA256 = &hash
	}
	return input, nil
}

func validHash(value string, length int) bool {
	if len(value) != length {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
