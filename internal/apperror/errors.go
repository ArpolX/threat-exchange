package apperror

import "errors"

var (
	ErrInvalidInput  = errors.New("invalid input")
	ErrNotFound      = errors.New("threat not found")
	ErrAlreadyExists = errors.New("threat with this MD5 already exists")
)
