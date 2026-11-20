package tools

import (
	"encoding/json"
	"fmt"
	"testing"
)

func benchmarkRegistry(b *testing.B, size int) (*Registry, string) {
	b.Helper()
	registry := NewRegistry()
	schema := json.RawMessage(`{"type":"object","properties":{"owner":{"type":"string"}}}`)
	target := ""
	for i := 0; i < size; i++ {
		id := fmt.Sprintf("bench_tool_%05d", i)
		if err := registry.Register(Definition{
			ID: id, Provider: "benchmark", Name: "Benchmark tool",
			Description: "Synthetic definition for catalog benchmarks.",
			Risk: RiskRead, InputSchema: schema,
		}); err != nil {
			b.Fatal(err)
		}
		target = id
	}
	return registry, target
}

func BenchmarkRegistryGet(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("tools_%d", size), func(b *testing.B) {
			registry, target := benchmarkRegistry(b, size)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, ok := registry.Get(target); !ok {
					b.Fatal("registered tool not found")
				}
			}
		})
	}
}

func BenchmarkRegistryGetParallel(b *testing.B) {
	registry, target := benchmarkRegistry(b, 1000)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, ok := registry.Get(target); !ok {
				b.Fatal("registered tool not found")
			}
		}
	})
}

func BenchmarkRegistryList(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("tools_%d", size), func(b *testing.B) {
			registry, _ := benchmarkRegistry(b, size)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if got := registry.List(); len(got) != size {
					b.Fatalf("List() returned %d tools, want %d", len(got), size)
				}
			}
		})
	}
}
