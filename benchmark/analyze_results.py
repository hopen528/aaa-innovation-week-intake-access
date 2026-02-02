#!/usr/bin/env python3
"""
Analyze and visualize benchmark results
"""

import re
import sys
from typing import Dict, List, Tuple

def parse_benchmark_results(filename: str) -> Dict[str, Dict[str, float]]:
    """Parse Go benchmark output"""
    results = {}

    with open(filename, 'r') as f:
        for line in f:
            if line.startswith('Benchmark'):
                parts = line.split()
                if len(parts) < 4:
                    continue

                name = parts[0].replace('Benchmark', '')
                # Extract iterations and ns/op
                iterations = int(parts[1])
                ns_per_op_str = parts[2]
                ns_per_op = float(ns_per_op_str)

                # Extract memory stats if present
                bytes_per_op = 0
                allocs_per_op = 0
                if len(parts) >= 5:
                    bytes_per_op = int(parts[3])
                if len(parts) >= 7:
                    allocs_per_op = int(parts[5])

                results[name] = {
                    'iterations': iterations,
                    'ns_per_op': ns_per_op,
                    'bytes_per_op': bytes_per_op,
                    'allocs_per_op': allocs_per_op
                }

    return results

def format_duration(ns: float) -> str:
    """Format nanoseconds into human-readable duration"""
    if ns < 1000:
        return f"{ns:.0f}ns"
    elif ns < 1_000_000:
        return f"{ns/1000:.2f}μs"
    elif ns < 1_000_000_000:
        return f"{ns/1_000_000:.2f}ms"
    else:
        return f"{ns/1_000_000_000:.2f}s"

def format_bytes(bytes: int) -> str:
    """Format bytes into human-readable size"""
    if bytes < 1024:
        return f"{bytes}B"
    elif bytes < 1024 * 1024:
        return f"{bytes/1024:.2f}KB"
    else:
        return f"{bytes/(1024*1024):.2f}MB"

def compare_results(spicedb: Dict[str, float], custom: Dict[str, float], test_name: str):
    """Compare SpiceDB vs Custom for a specific test"""
    speedup = spicedb['ns_per_op'] / custom['ns_per_op']

    print(f"\n{'='*60}")
    print(f"{test_name}")
    print(f"{'='*60}")
    print(f"{'Metric':<20} {'SpiceDB':>15} {'Custom':>15} {'Speedup':>10}")
    print(f"{'-'*60}")
    print(f"{'Latency':<20} {format_duration(spicedb['ns_per_op']):>15} "
          f"{format_duration(custom['ns_per_op']):>15} {speedup:>9.0f}x")
    print(f"{'Memory':<20} {format_bytes(spicedb['bytes_per_op']):>15} "
          f"{format_bytes(custom['bytes_per_op']):>15} "
          f"{spicedb['bytes_per_op']/max(custom['bytes_per_op'],1):>9.1f}x")
    print(f"{'Allocations':<20} {spicedb['allocs_per_op']:>15} "
          f"{custom['allocs_per_op']:>15} "
          f"{spicedb['allocs_per_op']/max(custom['allocs_per_op'],1):>9.1f}x")

def generate_summary(results: Dict[str, Dict[str, float]]):
    """Generate overall summary"""
    print(f"\n\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}\n")

    # Find matching test pairs
    tests = [
        ("SimpleIPCheck", "Simple IP Allowlist"),
        ("APIKeyCheck", "API Key Scoping"),
        ("ComplexCondition", "Complex Policy (IP+Key+Product+Time)"),
    ]

    for test_suffix, test_name in tests:
        spicedb_key = f"SpiceDB_{test_suffix}-10"
        custom_key = f"Custom_{test_suffix}-10"

        if spicedb_key in results and custom_key in results:
            compare_results(results[spicedb_key], results[custom_key], test_name)

    # Show cached performance
    cached_key = "Custom_WithCache-10"
    if cached_key in results:
        cached = results[cached_key]
        print(f"\n{'='*60}")
        print(f"Custom Implementation with Caching")
        print(f"{'='*60}")
        print(f"Latency:     {format_duration(cached['ns_per_op'])}")
        print(f"Memory:      {format_bytes(cached['bytes_per_op'])}")
        print(f"Allocations: {cached['allocs_per_op']}")
        print(f"\n✅ Cached evaluation is incredibly fast!")

    print(f"\n{'='*60}")
    print(f"RECOMMENDATION")
    print(f"{'='*60}\n")

    # Calculate average speedup
    speedups = []
    for test_suffix, _ in tests:
        spicedb_key = f"SpiceDB_{test_suffix}-10"
        custom_key = f"Custom_{test_suffix}-10"
        if spicedb_key in results and custom_key in results:
            speedup = results[spicedb_key]['ns_per_op'] / results[custom_key]['ns_per_op']
            speedups.append(speedup)

    if speedups:
        avg_speedup = sum(speedups) / len(speedups)
        print(f"Average speedup: {avg_speedup:.0f}x faster with Custom implementation")
        print()

        if avg_speedup > 100:
            print("✅ STRONG RECOMMENDATION: Use Custom Implementation")
            print("   - Orders of magnitude faster")
            print("   - Significantly lower memory usage")
            print("   - No network latency")
            print("   - Zero infrastructure cost")
        elif avg_speedup > 10:
            print("✅ RECOMMENDATION: Use Custom Implementation")
            print("   - Much faster performance")
            print("   - Lower resource usage")
        else:
            print("⚠️  CONSIDER: SpiceDB may be viable")
            print("   - Performance difference is small")
            print("   - Relationship graph may be valuable")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_results.py benchmark_results.txt")
        sys.exit(1)

    filename = sys.argv[1]

    try:
        results = parse_benchmark_results(filename)

        if not results:
            print("No benchmark results found in file")
            sys.exit(1)

        generate_summary(results)

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
