package benchmark

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

// Test request represents an intake request
type IntakeRequest struct {
	OrgID      string
	IP         string
	KeyUUID    string
	Product    string
	Hour       int
	AllowedIPs []string
}

// Global clients for benchmarks
var (
	spicedbClient   *authzed.Client
	customEvaluator *CustomEvaluator
	celEvaluator    *CELEvaluator
	testRequest     = &IntakeRequest{
		OrgID:      "org-12345",
		IP:         "10.0.1.100",
		KeyUUID:    "key-abc-123",
		Product:    "logs",
		Hour:       14, // 2 PM
		AllowedIPs: []string{"10.0.0.0/16", "192.168.0.0/16"},
	}
	testOrgID int32 = 12345 // Numeric org ID for CEL evaluator
)

// Setup function - call this before benchmarks
func setupBenchmark(b *testing.B) {
	setupBenchmarkWithSpiceDB(b, false)
}

func setupBenchmarkWithSpiceDB(b *testing.B, needSpiceDB bool) {
	var err error

	// Setup SpiceDB client (only if needed)
	if needSpiceDB {
		spicedbClient, err = authzed.NewClient(
			"localhost:50051",
			grpcutil.WithInsecureBearerToken("benchmark-key"),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			b.Fatalf("Failed to create SpiceDB client: %v", err)
		}

		// Write SpiceDB schema
		if err := setupSpiceDBSchema(spicedbClient); err != nil {
			b.Fatalf("Failed to setup SpiceDB schema: %v", err)
		}

		// Write test relationships
		if err := setupSpiceDBRelationships(spicedbClient); err != nil {
			b.Fatalf("Failed to setup SpiceDB relationships: %v", err)
		}
	}

	// Setup custom evaluator
	if customEvaluator == nil {
		customEvaluator, err = NewCustomEvaluator()
		if err != nil {
			b.Fatalf("Failed to create custom evaluator: %v", err)
		}
	}

	// Setup CEL evaluator (innovation week approach)
	if celEvaluator == nil {
		celEvaluator, err = NewCELEvaluator()
		if err != nil {
			b.Fatalf("Failed to create CEL evaluator: %v", err)
		}
	}
}

func setupSpiceDBSchema(client *authzed.Client) error {
	ctx := context.Background()

	schema := `
	definition organization {}

	definition product {
		relation org: organization
		relation viewer: organization with intake_policy
	}

	caveat intake_policy(
		request_ip string,
		allowed_cidrs list<string>,
		api_key_uuid string,
		allowed_keys list<string>
	) {
		// Check if IP is in any allowed CIDR (simplified - real version would use proper CIDR check)
		(request_ip.startsWith(allowed_cidrs[0].split('/')[0].split('.')[0] + '.' +
								allowed_cidrs[0].split('/')[0].split('.')[1])) &&
		// Check if API key is allowed
		api_key_uuid in allowed_keys
	}

	caveat simple_ip_check(
		request_ip string,
		allowed_ip string
	) {
		request_ip == allowed_ip
	}

	caveat key_check(
		api_key_uuid string,
		allowed_keys list<string>
	) {
		api_key_uuid in allowed_keys
	}
	`

	_, err := client.WriteSchema(ctx, &v1.WriteSchemaRequest{
		Schema: schema,
	})
	return err
}

func setupSpiceDBRelationships(client *authzed.Client) error {
	ctx := context.Background()

	updates := []*v1.RelationshipUpdate{
		{
			Operation: v1.RelationshipUpdate_OPERATION_CREATE,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: "product",
					ObjectId:   "logs",
				},
				Relation: "viewer",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "organization",
						ObjectId:   "org-12345",
					},
				},
				OptionalCaveat: &v1.ContextualizedCaveat{
					CaveatName: "key_check",
				},
			},
		},
	}

	_, err := client.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: updates,
	})
	return err
}

// Benchmark: SpiceDB with simple IP check
func BenchmarkSpiceDB_SimpleIPCheck(b *testing.B) {
	setupBenchmarkWithSpiceDB(b, true)
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Create context for caveat
			caveatContext, _ := structpb.NewStruct(map[string]interface{}{
				"request_ip": testRequest.IP,
				"allowed_ip": "10.0.1.100",
			})

			resp, err := spicedbClient.CheckPermission(ctx, &v1.CheckPermissionRequest{
				Resource: &v1.ObjectReference{
					ObjectType: "product",
					ObjectId:   testRequest.Product,
				},
				Permission: "viewer",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "organization",
						ObjectId:   testRequest.OrgID,
					},
				},
				Context: caveatContext,
			})

			if err != nil {
				b.Fatalf("CheckPermission failed: %v", err)
			}
			_ = resp
		}
	})
}

// Benchmark: SpiceDB with API key check
func BenchmarkSpiceDB_APIKeyCheck(b *testing.B) {
	setupBenchmarkWithSpiceDB(b, true)
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			caveatContext, _ := structpb.NewStruct(map[string]interface{}{
				"api_key_uuid": testRequest.KeyUUID,
				"allowed_keys": []string{
					"key-abc-123",
					"key-def-456",
					"key-ghi-789",
				},
			})

			resp, err := spicedbClient.CheckPermission(ctx, &v1.CheckPermissionRequest{
				Resource: &v1.ObjectReference{
					ObjectType: "product",
					ObjectId:   testRequest.Product,
				},
				Permission: "viewer",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "organization",
						ObjectId:   testRequest.OrgID,
					},
				},
				Context: caveatContext,
			})

			if err != nil {
				b.Fatalf("CheckPermission failed: %v", err)
			}
			_ = resp
		}
	})
}

// Benchmark: SpiceDB with complex condition
func BenchmarkSpiceDB_ComplexCondition(b *testing.B) {
	setupBenchmarkWithSpiceDB(b, true)
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			caveatContext, _ := structpb.NewStruct(map[string]interface{}{
				"request_ip": testRequest.IP,
				"allowed_cidrs": []string{
					"10.0.0.0/16",
					"192.168.0.0/16",
				},
				"api_key_uuid": testRequest.KeyUUID,
				"allowed_keys": []string{
					"key-abc-123",
					"key-def-456",
				},
			})

			resp, err := spicedbClient.CheckPermission(ctx, &v1.CheckPermissionRequest{
				Resource: &v1.ObjectReference{
					ObjectType: "product",
					ObjectId:   testRequest.Product,
				},
				Permission: "viewer",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "organization",
						ObjectId:   testRequest.OrgID,
					},
				},
				Context: caveatContext,
			})

			if err != nil {
				b.Fatalf("CheckPermission failed: %v", err)
			}
			_ = resp
		}
	})
}

// Benchmark: Custom evaluator with simple IP check
func BenchmarkCustom_SimpleIPCheck(b *testing.B) {
	setupBenchmark(b)

	policy := &Policy{
		Bindings: []Binding{
			{
				ResourceType: "logs",
				Condition:    `request.ip == "10.0.1.100"`,
			},
		},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			allowed, err := customEvaluator.Evaluate(policy, testRequest)
			if err != nil {
				b.Fatalf("Evaluate failed: %v", err)
			}
			_ = allowed
		}
	})
}

// Benchmark: Custom evaluator with API key check
func BenchmarkCustom_APIKeyCheck(b *testing.B) {
	setupBenchmark(b)

	policy := &Policy{
		Bindings: []Binding{
			{
				ResourceType: "logs",
				Condition:    `request.key_uuid in ["key-abc-123", "key-def-456", "key-ghi-789"]`,
			},
		},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			allowed, err := customEvaluator.Evaluate(policy, testRequest)
			if err != nil {
				b.Fatalf("Evaluate failed: %v", err)
			}
			_ = allowed
		}
	})
}

// Benchmark: Custom evaluator with IP CIDR check
func BenchmarkCustom_IPCIDRCheck(b *testing.B) {
	setupBenchmark(b)

	policy := &Policy{
		Bindings: []Binding{
			{
				ResourceType: "logs",
				Condition:    `ipInRange(request.ip, "10.0.0.0/16")`,
			},
		},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			allowed, err := customEvaluator.Evaluate(policy, testRequest)
			if err != nil {
				b.Fatalf("Evaluate failed: %v", err)
			}
			_ = allowed
		}
	})
}

// Benchmark: Custom evaluator with complex condition
func BenchmarkCustom_ComplexCondition(b *testing.B) {
	setupBenchmark(b)

	policy := &Policy{
		Bindings: []Binding{
			{
				ResourceType: "logs",
				Condition: `
					ipInRange(request.ip, "10.0.0.0/16") &&
					request.key_uuid in ["key-abc-123", "key-def-456"] &&
					request.product == "logs" &&
					request.hour >= 9 && request.hour < 17
				`,
			},
		},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			allowed, err := customEvaluator.Evaluate(policy, testRequest)
			if err != nil {
				b.Fatalf("Evaluate failed: %v", err)
			}
			_ = allowed
		}
	})
}

// Benchmark: Custom evaluator with caching
func BenchmarkCustom_WithCache(b *testing.B) {
	setupBenchmark(b)

	policy := &Policy{
		UUID: "policy-123",
		Bindings: []Binding{
			{
				ResourceType: "logs",
				Condition:    `ipInRange(request.ip, "10.0.0.0/16") && request.key_uuid == "key-abc-123"`,
			},
		},
	}

	// Pre-compile and cache
	customEvaluator.CompileAndCache(policy)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			allowed, err := customEvaluator.EvaluateCached(policy.UUID, testRequest)
			if err != nil {
				b.Fatalf("EvaluateCached failed: %v", err)
			}
			_ = allowed
		}
	})
}

// Benchmark: CEL evaluator with simple IP check
func BenchmarkCEL_SimpleIPCheck(b *testing.B) {
	setupBenchmark(b)

	// Add policy with Kubernetes IP/CIDR library syntax (orgID:apiKeyUUID format)
	err := celEvaluator.AddPolicy(
		testOrgID,
		testRequest.KeyUUID,
		`cidr('10.0.1.100/32').containsIP(ip(request.source_ip))`,
		PolicyModeEnforced,
	)
	if err != nil {
		b.Fatalf("Failed to add policy: %v", err)
	}

	ctx := IntakeRequestToContext(testRequest)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			decision, err := celEvaluator.CheckAccess(testOrgID, testRequest.KeyUUID, ctx)
			if err != nil {
				b.Fatalf("CheckAccess failed: %v", err)
			}
			_ = decision
		}
	})
}

// Benchmark: CEL evaluator with CIDR check
func BenchmarkCEL_IPCIDRCheck(b *testing.B) {
	setupBenchmark(b)

	err := celEvaluator.AddPolicy(
		testOrgID,
		testRequest.KeyUUID,
		`cidr('10.0.0.0/16').containsIP(ip(request.source_ip))`,
		PolicyModeEnforced,
	)
	if err != nil {
		b.Fatalf("Failed to add policy: %v", err)
	}

	ctx := IntakeRequestToContext(testRequest)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			decision, err := celEvaluator.CheckAccess(testOrgID, testRequest.KeyUUID, ctx)
			if err != nil {
				b.Fatalf("CheckAccess failed: %v", err)
			}
			_ = decision
		}
	})
}

// Benchmark: CEL evaluator with product scoping
func BenchmarkCEL_ProductScoping(b *testing.B) {
	setupBenchmark(b)

	err := celEvaluator.AddPolicy(
		testOrgID,
		testRequest.KeyUUID,
		`request.product == 'logs'`,
		PolicyModeEnforced,
	)
	if err != nil {
		b.Fatalf("Failed to add policy: %v", err)
	}

	ctx := IntakeRequestToContext(testRequest)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			decision, err := celEvaluator.CheckAccess(testOrgID, testRequest.KeyUUID, ctx)
			if err != nil {
				b.Fatalf("CheckAccess failed: %v", err)
			}
			_ = decision
		}
	})
}

// Benchmark: CEL evaluator with multiple products
func BenchmarkCEL_MultiProductScoping(b *testing.B) {
	setupBenchmark(b)

	err := celEvaluator.AddPolicy(
		testOrgID,
		testRequest.KeyUUID,
		`request.product in ['logs', 'metrics']`,
		PolicyModeEnforced,
	)
	if err != nil {
		b.Fatalf("Failed to add policy: %v", err)
	}

	ctx := IntakeRequestToContext(testRequest)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			decision, err := celEvaluator.CheckAccess(testOrgID, testRequest.KeyUUID, ctx)
			if err != nil {
				b.Fatalf("CheckAccess failed: %v", err)
			}
			_ = decision
		}
	})
}

// Benchmark: CEL evaluator with complex condition (IP + product)
func BenchmarkCEL_ComplexCondition(b *testing.B) {
	setupBenchmark(b)

	err := celEvaluator.AddPolicy(
		testOrgID,
		testRequest.KeyUUID,
		`request.product == 'logs' && cidr('10.0.0.0/16').containsIP(ip(request.source_ip))`,
		PolicyModeEnforced,
	)
	if err != nil {
		b.Fatalf("Failed to add policy: %v", err)
	}

	ctx := IntakeRequestToContext(testRequest)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			decision, err := celEvaluator.CheckAccess(testOrgID, testRequest.KeyUUID, ctx)
			if err != nil {
				b.Fatalf("CheckAccess failed: %v", err)
			}
			_ = decision
		}
	})
}

// Benchmark: CEL evaluator with very complex condition
func BenchmarkCEL_VeryComplexCondition(b *testing.B) {
	setupBenchmark(b)

	err := celEvaluator.AddPolicy(
		testOrgID,
		testRequest.KeyUUID,
		`request.product in ['logs', 'metrics'] && (cidr('10.0.0.0/16').containsIP(ip(request.source_ip)) || cidr('192.168.0.0/16').containsIP(ip(request.source_ip)))`,
		PolicyModeEnforced,
	)
	if err != nil {
		b.Fatalf("Failed to add policy: %v", err)
	}

	ctx := IntakeRequestToContext(testRequest)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			decision, err := celEvaluator.CheckAccess(testOrgID, testRequest.KeyUUID, ctx)
			if err != nil {
				b.Fatalf("CheckAccess failed: %v", err)
			}
			_ = decision
		}
	})
}

// Benchmark: CEL evaluator with dry run mode
func BenchmarkCEL_DryRunMode(b *testing.B) {
	setupBenchmark(b)

	err := celEvaluator.AddPolicy(
		testOrgID,
		testRequest.KeyUUID,
		`cidr('10.0.0.0/16').containsIP(ip(request.source_ip))`,
		PolicyModeDryRun,
	)
	if err != nil {
		b.Fatalf("Failed to add policy: %v", err)
	}

	ctx := IntakeRequestToContext(testRequest)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			decision, err := celEvaluator.CheckAccess(testOrgID, testRequest.KeyUUID, ctx)
			if err != nil {
				b.Fatalf("CheckAccess failed: %v", err)
			}
			_ = decision
		}
	})
}

// Benchmark: End-to-end latency comparison (All 3 approaches)
func BenchmarkE2E_AllThreeApproaches(b *testing.B) {
	setupBenchmark(b)
	ctx := context.Background()

	customPolicy := &Policy{
		Bindings: []Binding{
			{
				ResourceType: "logs",
				Condition:    `ipInRange(request.ip, "10.0.0.0/16") && request.key_uuid == "key-abc-123"`,
			},
		},
	}

	// Setup CEL policy
	celEvaluator.AddPolicy(
		testOrgID,
		testRequest.KeyUUID,
		`cidr('10.0.0.0/16').containsIP(ip(request.source_ip))`,
		PolicyModeEnforced,
	)
	celCtx := IntakeRequestToContext(testRequest)

	b.Run("SpiceDB", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			caveatContext, _ := structpb.NewStruct(map[string]interface{}{
				"request_ip":   testRequest.IP,
				"api_key_uuid": testRequest.KeyUUID,
				"allowed_keys": []string{"key-abc-123"},
			})

			resp, err := spicedbClient.CheckPermission(ctx, &v1.CheckPermissionRequest{
				Resource: &v1.ObjectReference{
					ObjectType: "product",
					ObjectId:   testRequest.Product,
				},
				Permission: "viewer",
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: "organization",
						ObjectId:   testRequest.OrgID,
					},
				},
				Context: caveatContext,
			})
			if err != nil {
				b.Fatalf("CheckPermission failed: %v", err)
			}
			_ = resp
		}
	})

	b.Run("Custom", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			allowed, err := customEvaluator.Evaluate(customPolicy, testRequest)
			if err != nil {
				b.Fatalf("Evaluate failed: %v", err)
			}
			_ = allowed
		}
	})

	b.Run("CEL", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decision, err := celEvaluator.CheckAccess(testOrgID, testRequest.KeyUUID, celCtx)
			if err != nil {
				b.Fatalf("CheckAccess failed: %v", err)
			}
			_ = decision
		}
	})
}

// Helper function to check if IP is in CIDR range
func ipInCIDR(ip, cidr string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return ipnet.Contains(parsedIP)
}

// Latency percentile test
func TestLatencyPercentiles(t *testing.T) {
	setupBenchmark(&testing.B{})

	iterations := 10000
	spicedbLatencies := make([]time.Duration, iterations)
	customLatencies := make([]time.Duration, iterations)
	celLatencies := make([]time.Duration, iterations)

	ctx := context.Background()
	customPolicy := &Policy{
		Bindings: []Binding{
			{
				ResourceType: "logs",
				Condition:    `ipInRange(request.ip, "10.0.0.0/16") && request.key_uuid == "key-abc-123"`,
			},
		},
	}

	// Setup CEL policy
	celEvaluator.AddPolicy(
		testOrgID,
		testRequest.KeyUUID,
		`cidr('10.0.0.0/16').containsIP(ip(request.source_ip))`,
		PolicyModeEnforced,
	)
	celCtx := IntakeRequestToContext(testRequest)

	// Measure SpiceDB latencies
	fmt.Println("Measuring SpiceDB latencies...")
	for i := 0; i < iterations; i++ {
		start := time.Now()

		caveatContext, _ := structpb.NewStruct(map[string]interface{}{
			"api_key_uuid": testRequest.KeyUUID,
			"allowed_keys": []string{"key-abc-123"},
		})

		_, _ = spicedbClient.CheckPermission(ctx, &v1.CheckPermissionRequest{
			Resource: &v1.ObjectReference{
				ObjectType: "product",
				ObjectId:   testRequest.Product,
			},
			Permission: "viewer",
			Subject: &v1.SubjectReference{
				Object: &v1.ObjectReference{
					ObjectType: "organization",
					ObjectId:   testRequest.OrgID,
				},
			},
			Context: caveatContext,
		})

		spicedbLatencies[i] = time.Since(start)
	}

	// Measure Custom latencies
	fmt.Println("Measuring Custom evaluator latencies...")
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, _ = customEvaluator.Evaluate(customPolicy, testRequest)
		customLatencies[i] = time.Since(start)
	}

	// Measure CEL latencies
	fmt.Println("Measuring CEL evaluator latencies...")
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, _ = celEvaluator.CheckAccess(testOrgID, testRequest.KeyUUID, celCtx)
		celLatencies[i] = time.Since(start)
	}

	// Calculate percentiles
	printPercentiles("SpiceDB", spicedbLatencies)
	printPercentiles("Custom", customLatencies)
	printPercentiles("CEL (Innovation Week)", celLatencies)
}

func printPercentiles(name string, latencies []time.Duration) {
	// Sort latencies
	for i := 0; i < len(latencies); i++ {
		for j := i + 1; j < len(latencies); j++ {
			if latencies[i] > latencies[j] {
				latencies[i], latencies[j] = latencies[j], latencies[i]
			}
		}
	}

	p50 := latencies[len(latencies)*50/100]
	p95 := latencies[len(latencies)*95/100]
	p99 := latencies[len(latencies)*99/100]
	max := latencies[len(latencies)-1]

	fmt.Printf("\n%s Latency Percentiles:\n", name)
	fmt.Printf("  p50: %v\n", p50)
	fmt.Printf("  p95: %v\n", p95)
	fmt.Printf("  p99: %v\n", p99)
	fmt.Printf("  max: %v\n", max)
}
