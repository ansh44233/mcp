package execution

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestExecuteBoundsConcurrency(t *testing.T) {
	runner := New(Config{MaxConcurrent: 2, Timeout: time.Second})
	var active, maximum atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := runner.Execute(context.Background(), Operation{ID: "read"}, func(context.Context) error {
				current := active.Add(1)
				for {
					old := maximum.Load()
					if current <= old || maximum.CompareAndSwap(old, current) {
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
				active.Add(-1)
				return nil
			})
			if err != nil {
				t.Errorf("Execute() error = %v", err)
			}
		}()
	}
	wg.Wait()
	if got := maximum.Load(); got > 2 || got < 1 {
		t.Fatalf("maximum concurrency = %d, want 1..2", got)
	}
}

func TestExecuteTimeout(t *testing.T) {
	runner := New(Config{MaxConcurrent: 1, Timeout: 20 * time.Millisecond})
	result, err := runner.Execute(context.Background(), Operation{ID: "slow"}, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	if result.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1", result.Attempts)
	}
}

func TestExecuteCancellationWhileWaitingForCapacity(t *testing.T) {
	runner := New(Config{MaxConcurrent: 1, Timeout: time.Second})
	entered := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_, _ = runner.Execute(context.Background(), Operation{ID: "first"}, func(context.Context) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := runner.Execute(ctx, Operation{ID: "second"}, func(context.Context) error {
		t.Fatal("cancelled operation must not execute")
		return nil
	})
	close(release)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
	if result.Attempts != 0 {
		t.Fatalf("attempts = %d, want 0", result.Attempts)
	}
}

func TestExecuteRetriesOnlyExplicitlyIdempotentOperations(t *testing.T) {
	runner := New(Config{MaxConcurrent: 1, Timeout: time.Second, MaxRetries: 3})
	transient := errors.New("temporary")
	var calls atomic.Int32
	result, err := runner.Execute(context.Background(), Operation{
		ID: "safe-read",
		RetryPolicy: RetryPolicy{
			Idempotent: true,
			MaxRetries: 2,
			Retryable:  func(err error) bool { return errors.Is(err, transient) },
		},
	}, func(context.Context) error {
		if calls.Add(1) < 3 {
			return transient
		}
		return nil
	})
	if err != nil || result.Attempts != 3 {
		t.Fatalf("result=%+v error=%v, want three attempts and success", result, err)
	}

	calls.Store(0)
	_, err = runner.Execute(context.Background(), Operation{ID: "write"}, func(context.Context) error {
		calls.Add(1)
		return transient
	})
	if err == nil || calls.Load() != 1 {
		t.Fatalf("non-idempotent operation calls=%d error=%v, want one attempt and error", calls.Load(), err)
	}
}

func TestExecuteDoesNotRetryWhenClassifierRejects(t *testing.T) {
	runner := New(Config{MaxConcurrent: 1, Timeout: time.Second, MaxRetries: 3})
	var calls atomic.Int32
	_, err := runner.Execute(context.Background(), Operation{
		ID: "read",
		RetryPolicy: RetryPolicy{
			Idempotent: true, MaxRetries: 3,
			Retryable: func(error) bool { return false },
		},
	}, func(context.Context) error {
		calls.Add(1)
		return errors.New("permanent")
	})
	if err == nil || calls.Load() != 1 {
		t.Fatalf("calls=%d error=%v, want one attempt and error", calls.Load(), err)
	}
}

func TestExecuteValidatesInputs(t *testing.T) {
	runner := New(Config{})
	if _, err := runner.Execute(context.Background(), Operation{ID: "x"}, nil); !errors.Is(err, ErrNilOperation) {
		t.Fatalf("nil function error = %v", err)
	}
	if _, err := runner.Execute(context.Background(), Operation{}, func(context.Context) error { return nil }); err == nil {
		t.Fatal("expected missing operation ID error")
	}
}

func TestExecuteUsesShorterTrustedOperationTimeout(t *testing.T) {
	runner := New(Config{MaxConcurrent: 1, Timeout: time.Second})
	started := time.Now()
	_, err := runner.Execute(context.Background(), Operation{ID: "short", Timeout: 20 * time.Millisecond}, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatalf("operation timeout took %v, expected approximately 20ms", elapsed)
	}
}

func TestExecuteOperationTimeoutCannotExceedRunnerMaximum(t *testing.T) {
	runner := New(Config{MaxConcurrent: 1, Timeout: 20 * time.Millisecond})
	_, err := runner.Execute(context.Background(), Operation{ID: "capped", Timeout: time.Second}, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want runner maximum deadline", err)
	}
}
