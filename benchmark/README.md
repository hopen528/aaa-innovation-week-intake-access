# Policy Engine Benchmark: SpiceDB vs Custom vs CEL Evaluator

This benchmark compares performance characteristics of three approaches:
1. **SpiceDB with Caveats** - External authorization service with gRPC
2. **Custom CEL Evaluator** - In-process policy evaluation (compiles on each request)
3. **CEL Evaluator (Innovation Week)** - In-process with pre-compiled policies

## Setup

### Prerequisites

```bash
# Install SpiceDB
brew install authzed/tap/spicedb

# Or download from https://github.com/authzed/spicedb/releases
```

### Start SpiceDB (for benchmarks)

```bash
# Terminal 1: Run SpiceDB in memory mode
spicedb serve --grpc-preshared-key "benchmark-key" \
    --datastore-engine=memory \
    --grpc-addr=:50051 \
    --http-addr=:8443

# Terminal 2: Run benchmarks
go test -bench=. -benchmem -benchtime=10s
```

## Running Benchmarks

```bash
# All benchmarks
go test -bench=. -benchmem

# Just SpiceDB (requires SpiceDB running)
go test -bench=BenchmarkSpiceDB -benchmem

# Just Custom evaluator
go test -bench=BenchmarkCustom -benchmem

# Just CEL evaluator (Innovation Week approach)
go test -bench=BenchmarkCEL -benchmem

# Compare CEL and Custom (no SpiceDB required)
go test -bench="Benchmark(Custom|CEL)" -benchmem -benchtime=2s -run=^$

# With CPU profiling
go test -bench=. -benchmem -cpuprofile=cpu.prof

# With memory profiling
go test -bench=. -benchmem -memprofile=mem.prof
```

## Scenarios Tested

### All Approaches
1. **Simple IP Check** - Check if IP matches exactly or is in CIDR range
2. **API Key Scoping** - Check if API key can access product
3. **Complex Condition** - IP + API Key + Product + Time restrictions
4. **Cached vs Uncached** - Impact of pre-compilation on performance

### CEL Evaluator Specific
5. **Product Scoping** - `request.product == 'logs'`
6. **Multi-Product** - `request.product in ['logs', 'metrics']`
7. **IP + Product Combined** - Complex policies with multiple attributes
8. **Dry Run Mode** - Policy evaluation without enforcement

## Benchmark Results

Actual benchmark results on Apple M1 Max:

| Approach | Latency (ns/op) | Latency (μs) | Throughput | Memory/op |
|----------|-----------------|--------------|------------|-----------|
| **CEL (Pre-compiled)** | ~470 | 0.47μs | 2.1M req/s | 1,078 B |
| **Custom (Cached)** | ~415 | 0.42μs | 2.4M req/s | 902 B |
| **Custom (No Cache)** | ~35,000 | 35μs | 28K req/s | 27,697 B |
| **SpiceDB** | ~5-10ms | 5,000-10,000μs | 100-200 req/s | High (gRPC) |

### Key Findings

**✅ CEL Evaluator (Innovation Week) - RECOMMENDED**
- **Latency**: 0.47μs (400x under 200μs budget!)
- **Throughput**: 2M+ req/s per core
- **Flexibility**: Zero code changes to extend with new attributes
- **Policy modes**: disabled/dry_run/enforced built-in
- **Syntax**: Clean `ip().in_cidr()` and `request.product` expressions

**⚠️ Custom (Cached) - Similar Performance**
- Slightly faster (~13% better latency)
- Lower memory allocations
- Less flexible (needs code changes for new attributes)

**❌ SpiceDB - Not Suitable for Intake**
- 10,000-20,000x slower than CEL
- High network overhead (gRPC)
- Better for relationship-based authorization (ReBAC)

### Production Implications

For 7M requests/second intake:
- **Budget**: 200μs P99
- **CEL actual**: 0.47μs (only 0.25% of budget!)
- **Headroom**: 400x under budget

### When to Use Each

| Use Case | Recommendation |
|----------|----------------|
| **IP allowlisting** | ✅ CEL Evaluator |
| **Product scoping** | ✅ CEL Evaluator |
| **ABAC policies** | ✅ CEL Evaluator |
| **Team/User permissions** | SpiceDB (ReBAC) |
| **Resource hierarchies** | SpiceDB (relationships) |

## Detailed Analysis

See [BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md) for comprehensive analysis including:
- Detailed latency breakdown
- Memory allocation patterns
- Comparison of all three approaches
- Production recommendations
