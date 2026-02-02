# Benchmark Results: CEL vs Custom Evaluators

## Test Environment
- **Machine**: MacBook Pro (Apple M1 Max)
- **Go Version**: 1.25.5
- **Benchmark Time**: 2 seconds per test
- **Date**: February 2, 2026

## Summary

This benchmark compares three policy evaluation approaches:
1. **CEL Evaluator** (Innovation Week - with pre-compiled policies)
2. **Custom Evaluator** (compile on each request)
3. **Custom with Cache** (pre-compiled, similar to CEL)

## Key Findings

### ✅ CEL Evaluator Performance (Innovation Week Approach)

The CEL evaluator with `ip().in_cidr()` syntax and pre-compiled policies achieves **sub-microsecond latency**:

| Test Case | Latency (ns/op) | Memory (B/op) | Allocs/op |
|-----------|-----------------|---------------|-----------|
| **Simple IP Check** | 494 | 1,078 | 19 |
| **CIDR Check** | 445 | 1,078 | 19 |
| **Product Scoping** | 401 | 856 | 10 |
| **Multi-Product Scoping** | 440 | 1,017 | 15 |
| **Complex (IP + Product)** | 472 | 1,094 | 20 |
| **Very Complex** | 534 | 1,254 | 25 |
| **Dry Run Mode** | 530 | 1,241 | 22 |

**Average: ~470ns (0.47μs) per evaluation**

### 📊 Custom Evaluator Performance (No Caching)

The custom evaluator **compiles CEL on every request**:

| Test Case | Latency (ns/op) | Memory (B/op) | Allocs/op | vs CEL |
|-----------|-----------------|---------------|-----------|--------|
| **Simple IP Check** | 16,452 | 27,697 | 438 | **33x slower** |
| **API Key Check** | 31,257 | 38,591 | 610 | **63x slower** |
| **CIDR Check** | 20,962 | 30,717 | 468 | **47x slower** |
| **Complex Condition** | 72,537 | 79,227 | 1,308 | **154x slower** |

**Average: ~35,000ns (35μs) per evaluation**

### 🚀 Custom Evaluator with Caching

With pre-compiled policies (matching CEL approach):

| Metric | Value |
|--------|-------|
| **Latency** | 415 ns/op |
| **Memory** | 902 B/op |
| **Allocations** | 18 allocs/op |

**Performance: Nearly identical to CEL evaluator!**

## Comparison Analysis

### CEL (Innovation Week) vs Custom (No Cache)

```
CEL Evaluator:    ~470 ns/op   (0.47μs)
Custom (No Cache): ~35,000 ns/op (35μs)
Speedup:          74x faster
```

### CEL vs Custom (Both with Pre-compiled Policies)

```
CEL Evaluator:     ~470 ns/op
Custom with Cache: ~415 ns/op
Difference:        ~13% (negligible)
```

## Key Insights

### 1. **Pre-compilation is Critical**
The 74x performance difference between cached and non-cached shows that **pre-compiling policies is essential**:
- ✅ CEL approach automatically caches compiled programs per policy
- ✅ Custom with cache achieves similar performance
- ❌ Custom without cache is 74x slower (unusable for 7M req/s)

### 2. **CEL Evaluator Advantages**
- ✅ **Built-in caching** - policies compiled once and reused
- ✅ **Policy modes** - disabled/dry_run/enforced with no overhead
- ✅ **Flexible syntax** - `ip().in_cidr()` is clean and extensible
- ✅ **Easy extension** - add `request.product`, `request.country` with zero code changes

### 3. **Production Implications**

For 7M requests/second:
- **Budget**: 200μs P99
- **CEL actual**: ~0.5μs (400x under budget!)
- **Overhead**: <0.25% of latency budget

### 4. **Memory Efficiency**

CEL evaluator uses minimal memory:
- ~1KB per request for IP checks
- ~856 bytes for simple product scoping
- Very low allocation count (10-25 per request)

## Recommendations

### ✅ Use CEL Evaluator (Innovation Week Approach) Because:

1. **Performance**: Sub-microsecond latency (0.4-0.5μs)
2. **Scalability**: Can handle 2M+ evaluations/second per core
3. **Flexibility**: Zero code changes to add attributes (product, country, etc.)
4. **Policy Modes**: Built-in support for disabled/dry_run/enforced
5. **Maintainability**: Clean syntax (`ip().in_cidr()`) matches industry standards

### When to Use Custom (with Cache):
- If you need slightly lower allocations (18 vs 19-25)
- If you want to avoid CEL dependency
- Performance difference is negligible (<13%)

## Conclusion

The **CEL evaluator (Innovation Week approach) is the clear winner** for intake policies:

```
✅ 400x under latency budget (0.5μs vs 200μs)
✅ Handles 2M+ req/s per core
✅ Zero code changes to extend
✅ Production-ready with policy modes
✅ Clean, industry-standard syntax
```

Both approaches are **dramatically faster than SpiceDB** (5-10ms = 10,000-20,000x slower), confirming that in-process CEL evaluation is the right choice for intake's ABAC use case.

## Next Steps

1. ✅ Benchmark complete - CEL evaluator validated
2. → Implement CEL evaluator in authenticator-intake
3. → Test with production traffic (dry run mode)
4. → Gradual rollout with monitoring
5. → Document policy syntax for users

---

**Benchmark Command:**
```bash
go test -bench="Benchmark(Custom|CEL)" -benchmem -benchtime=2s -run=^$
```

**Full Results:** See `benchmark_results.txt`
