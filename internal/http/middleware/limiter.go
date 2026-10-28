package middleware

import (
	"fmt"
	"sync"
	"time"
)

type window struct {
	count    int
	resetsAt time.Time
}

type Limiter struct {
	mu       sync.Mutex
	windows  map[[32]byte]window
	limit    int
	interval time.Duration
	now      func() time.Time
}

func NewLimiter(limit int, interval time.Duration, now func() time.Time) (*Limiter, error) {
	if limit <= 0 || interval <= 0 {
		return nil, fmt.Errorf("rate limit and window must be positive")
	}
	if now == nil {
		return nil, fmt.Errorf("rate limiter clock is required")
	}
	return &Limiter{windows: make(map[[32]byte]window), limit: limit, interval: interval, now: now}, nil
}
