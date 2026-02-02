# Policy Engine Benchmark: SpiceDB vs Custom Implementation

This benchmark compares performance characteristics of:
1. **SpiceDB with Caveats** - External authorization service
2. **Custom CEL Evaluator** - In-process policy evaluation

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

# Just SpiceDB
go test -bench=BenchmarkSpiceDB -benchmem

# Just Custom
go test -bench=BenchmarkCustom -benchmem

# With CPU profiling
go test -bench=. -benchmem -cpuprofile=cpu.prof

# With memory profiling
go test -bench=. -benchmem -memprofile=mem.prof
```

## Scenarios Tested

1. **Simple IP Allowlist** - Check if IP is in allowed list
2. **API Key Scoping** - Check if API key can access product
3. **Complex Condition** - IP + API Key + Product + Time restrictions
4. **Cached vs Uncached** - Impact of caching on performance

## Expected Results

Based on typical production deployments:

| Metric | SpiceDB | Custom | Winner |
|--------|---------|--------|--------|
| **Latency (p50)** | 5-10ms | <1ms | Custom |
| **Latency (p99)** | 15-25ms | 2ms | Custom |
| **Throughput** | 10K req/s | 100K req/s | Custom |
| **Memory/op** | High (gRPC) | Low (in-process) | Custom |
| **Cache Hit** | 0.5-1ms | 0.1ms | Custom |

SpiceDB advantages:
- Production-ready infrastructure
- Relationship graph support
- Distributed architecture

Custom advantages:
- Lower latency
- Higher throughput
- Simpler operations
- No network overhead
