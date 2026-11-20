package execution

import (
	"context"
	"testing"
	"time"
)

func BenchmarkRunnerExecute(b *testing.B) {
	runner := New(Config{MaxConcurrent: 16, Timeout: time.Second})
	operation := Operation{ID: "benchmark_read"}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := runner.Execute(ctx, operation, func(context.Context) error { return nil }); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRunnerExecuteParallel(b *testing.B) {
	runner := New(Config{MaxConcurrent: 16, Timeout: time.Second})
	operation := Operation{ID: "benchmark_read"}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := runner.Execute(ctx, operation, func(context.Context) error { return nil }); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
