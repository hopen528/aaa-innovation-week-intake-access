#!/bin/bash

set -e

echo "==================================="
echo "Policy Engine Benchmark"
echo "==================================="
echo ""

# Check if SpiceDB is running
if ! nc -z localhost 50051 2>/dev/null; then
    echo "❌ SpiceDB is not running on localhost:50051"
    echo ""
    echo "Please start SpiceDB first:"
    echo "  spicedb serve --grpc-preshared-key 'benchmark-key' \\"
    echo "      --datastore-engine=memory \\"
    echo "      --grpc-addr=:50051 \\"
    echo "      --http-addr=:8443"
    echo ""
    exit 1
fi

echo "✅ SpiceDB is running"
echo ""

# Run benchmarks
echo "Running benchmarks..."
echo "This will take about 2-3 minutes"
echo ""

go test -bench=. -benchmem -benchtime=5s | tee benchmark_results.txt

echo ""
echo "==================================="
echo "Benchmark Complete!"
echo "==================================="
echo ""
echo "Results saved to: benchmark_results.txt"
echo ""

# Run latency percentile test
echo "Running latency percentile analysis..."
echo ""
go test -run=TestLatencyPercentiles -v

echo ""
echo "==================================="
echo "Analysis Complete!"
echo "==================================="
