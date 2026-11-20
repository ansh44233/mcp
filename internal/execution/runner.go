// Package execution provides bounded, cancellation-aware execution for platform operations.
package execution

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrNilOperation = errors.New("execution operation is required")

// Config bounds concurrent work and the duration of each operation.
type Config struct {
	MaxConcurrent int
	Timeout       time.Duration
	MaxRetries    int
}

// RetryPolicy describes when a failed operation may be attempted again.
// Retries are considered only when Idempotent is true.
type RetryPolicy struct {
	Idempotent bool
	MaxRetries int
	Retryable  func(error) bool
}

// Operation contains execution metadata that must be supplied by trusted
// server-side registration, never by tool-call arguments.
type Operation struct {
	ID          string
	RetryPolicy RetryPolicy
}

// Result contains metadata only; it deliberately excludes operation arguments.
type Result struct {
	Attempts int
	Duration time.Duration
}

// Runner enforces a concurrency bound and per-operation timeout.
type Runner struct {
	slots   chan struct{}
	timeout time.Duration
	retries int
}

// New creates a runner. Invalid or omitted limits receive conservative defaults.
func New(config Config) *Runner {
	if config.MaxConcurrent < 1 {
		config.MaxConcurrent = 8
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}
	if config.MaxRetries < 0 {
		config.MaxRetries = 0
	}
	if config.MaxRetries > 5 {
		config.MaxRetries = 5
	}
	return &Runner{
		slots:   make(chan struct{}, config.MaxConcurrent),
		timeout: config.Timeout,
		retries: config.MaxRetries,
	}
}

// Execute runs fn within the configured concurrency and time bounds.
// A retry requires all three: an idempotent operation, a retry budget,
// and a trusted Retryable classifier that accepts the returned error.
func (r *Runner) Execute(ctx context.Context, operation Operation, fn func(context.Context) error) (Result, error) {
	if r == nil {
		return Result{}, errors.New("execution runner is required")
	}
	if fn == nil {
		return Result{}, ErrNilOperation
	}
	if operation.ID == "" {
		return Result{}, errors.New("operation ID is required")
	}
	if ctx == nil {
		return Result{}, errors.New("execution context is required")
	}

	started := time.Now()
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-ctx.Done():
		return Result{Duration: time.Since(started)}, ctx.Err()
	}

	executionCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	retryBudget := 0
	if operation.RetryPolicy.Idempotent && operation.RetryPolicy.Retryable != nil {
		retryBudget = operation.RetryPolicy.MaxRetries
		if retryBudget > r.retries {
			retryBudget = r.retries
		}
		if retryBudget < 0 {
			retryBudget = 0
		}
	}

	result := Result{}
	for {
		result.Attempts++
		err := fn(executionCtx)
		if err == nil {
			result.Duration = time.Since(started)
			return result, nil
		}
		if executionCtx.Err() != nil {
			result.Duration = time.Since(started)
			return result, fmt.Errorf("operation %q: %w", operation.ID, executionCtx.Err())
		}
		if result.Attempts > retryBudget || operation.RetryPolicy.Retryable == nil ||
			!operation.RetryPolicy.Idempotent || !operation.RetryPolicy.Retryable(err) {
			result.Duration = time.Since(started)
			return result, fmt.Errorf("operation %q failed: %w", operation.ID, err)
		}
	}
}
