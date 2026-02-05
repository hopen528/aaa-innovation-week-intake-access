# IP-Based Restriction Policies - Innovation Week Implementation

## Goal

Build an **IP-based access control system** using CEL (Common Expression Language) for:
1. **Intake traffic access control** (IP blocking/allowlisting)
2. **Future extensibility** to country, user-agent, time-based rules

## Architecture Decision: CEL Evaluator

**Why CEL?**
- **Future-proof**: Extend to other attributes without code rewrites
- **Extremely fast**: ~0.3μs evaluation (600x under 200μs budget)
- **Battle-tested**: Using Kubernetes CEL IP/CIDR library (k8s.io/apiserver)
- **Industry standard**: Used by Kubernetes, Envoy, Google Cloud

**Key Insight:** Zoltron restriction policies already stream to FRAMES - we store CEL expressions in RelationTuples and evaluate them at the edge.

## Architecture

```
┌─────────────────── Edge / Data Plane ─────────────────────┐
│                                                            │
│  Envoy → AuthN Sidecar → Logs/Metrics Intake              │
│          │                                                 │
│          ├─ libcontext (local RocksDB)                    │
│          │  - Restriction policies via FRAMES             │
│          │  - Kubernetes CEL IP/CIDR library              │
│          │  - ~0.3μs evaluation                           │
│          └─ Check CEL expressions → 403 if blocked        │
│                                                            │
└────────────────────────┬───────────────────────────────────┘
                         │ (Zoltron → FRAMES - already exists)
                         ↓
┌──────────────────── Control Plane ────────────────────────┐
│  ┌──────────────────┐        ┌──────────────┐            │
│  │    Zoltron       │───────▶│    FRAMES    │            │
│  │  (policies)      │        │   Platform   │            │
│  └──────────────────┘        └──────────────┘            │
│         ▲                                                 │
│  ┌──────┴──────┐    ┌──────────┐                         │
│  │ rbac-public │    │    UI    │                         │
│  │    API      │    │          │                         │
│  └─────────────┘    └──────────┘                         │
└───────────────────────────────────────────────────────────┘
```

## Data Model

Policies stored as RelationTuples (existing Zoltron format):

```protobuf
message RelationTuple {
    string resource_type = 1;   // "api_key"
    string resource_id = 2;     // "*" (org-wide) or "key-uuid" (key-specific)
    string relation = 3;        // "access_policy"
    string principal_type = 4;  // "cel_expression"
    string principal_id = 5;    // "ip-policy-{disabled|dryrun|enforced}"
    string condition = 6;       // CEL expression
}
```

**Example:**
```
resource_type | resource_id | relation      | principal_type  | principal_id         | condition
--------------|-------------|---------------|-----------------|----------------------|------------------------------------------
api_key       | *           | access_policy | cel_expression  | ip-policy-enforced   | !cidr('192.168.1.0/24').containsIP(ip(request.source_ip))
api_key       | key-456     | access_policy | cel_expression  | ip-policy-dryrun     | cidr('10.0.0.0/8').containsIP(ip(request.source_ip))
```

## API

```
POST   /api/unstable/orgs/{org_uuid}/ip-policies              # Create
GET    /api/unstable/orgs/{org_uuid}/ip-policies              # List
PATCH  /api/unstable/orgs/{org_uuid}/ip-policies/{resource_id} # Update
DELETE /api/unstable/orgs/{org_uuid}/ip-policies/{resource_id} # Delete
```

**Request body:**
```json
{
  "resource_id": "*",
  "blocked_cidrs": ["192.168.1.0/24", "10.0.0.0/8"],
  "allowed_cidrs": ["8.8.8.0/24"],
  "mode": "enforced"
}
```

**Fields:**
- `resource_id`: `"*"` (org-wide) or specific API key UUID
- `blocked_cidrs`: CIDR blocks to deny
- `allowed_cidrs`: CIDR blocks to allow (optional)
- `mode`: `"disabled"` | `"dry_run"` | `"enforced"`

## Policy Modes

| Mode | Evaluates? | Blocks? | Use Case |
|------|-----------|---------|----------|
| `disabled` | No | No | Temporarily disable without deleting |
| `dry_run` | Yes | No | Test policy, see what would be blocked |
| `enforced` | Yes | Yes | Full enforcement |

---

## Implementation Plan

### Day 1: API + UI ✅ COMPLETED

#### Backend (dd-source: `ACCESSINT-1112-ip-policy-crud-endpoints`)

- [x] Add database enums: "api_key" resource type, "cel_expression" principal type, "access_policy" relation
- [x] Create 4 CRUD endpoints in rbac-public
- [x] Backend generates CEL expressions from CIDR lists
- [x] FRAMES notifier integration for policy changes
- [x] Policy mode encoded in `principal_id` field

#### Frontend (web-ui: `erica.zhong/ACCESSINT-1112-ip-policies-ui`)

**Main Page (`/organization-settings/ip-policies`):**
- [x] `PageIpPolicies.tsx` - Main page with table and audit trail link

**Table Components:**
- [x] `IpPoliciesTable` - Table with bulk operations, edit/delete actions
- [x] `IpPoliciesEmptyState` - Empty state with CTA
- [x] `IpPoliciesSkeleton` - Loading states

**Modal Components:**
- [x] `IpPolicyAddModal` - Create policies with CIDR validation and test IP preview
- [x] `IpPolicyEditModal` - Update policies with dry-run metrics placeholder
- [x] `DeletePolicyModal` - Confirmation modal with enforced mode warning

**Reusable Components:**
- [x] `ModeBadge` - Colored badge for mode display
- [x] `ModeSelector` - RadioButtons for mode selection
- [x] `CidrInput` - Multi-CIDR input with validation and IP range display
- [x] `CidrList` - Display CIDRs with copy button
- [x] `TestIpInput` - Test IP against policy rules
- [x] `DryRunMetrics` - Placeholder for dry-run stats

**API Key Integration:**
- [x] `ApiKeyIpPolicies` - Embedded in ViewApiKeyModal

**API Hooks:**
- [x] `useGetApiUnstableOrgsIpPolicies`, `usePostApiUnstableOrgsIpPolicies`
- [x] `usePatchApiUnstableOrgsIpPoliciesId`, `useDeleteApiUnstableOrgsIpPoliciesId`

---

### Day 2: Data Plane Implementation 🚧 IN PROGRESS

**Goal:** Integrate CEL policy evaluator into authenticator-intake service

**Implementation approach:** Self-contained in dd-go to avoid cross-repo dependency complexity

**PRs:**
- dd-go: https://github.com/DataDog/dd-go/pull/220294 (DRAFT - In Progress)
- dd-source (control plane): https://github.com/DataDog/dd-source/pull/351115 (Control plane endpoints)

#### 2.1 Policy Evaluator Package (dd-go/apps/authenticator-intake/policyeval)

Implemented directly in dd-go using existing FRAMES reader infrastructure from authdatastore.

```go
// Package: github.com/DataDog/dd-go/apps/authenticator-intake/policyeval

type PolicyEvaluator struct {
    env          *cel.Env                              // CEL environment with K8s IP/CIDR libs
    cache        map[string]*CachedPolicy              // Hash-based cache: "orgUUID:resourceID" → compiled
    cacheMu      sync.RWMutex                          // Protects cache map
    policyReader authdatastore.RestrictionPolicyReader // FRAMES reader for restriction policies
}

// NewPolicyEvaluator creates evaluator with CEL environment and FRAMES reader
func NewPolicyEvaluator(contextRootPath string) (*PolicyEvaluator, error)

// WaitReady blocks until FRAMES snapshot is loaded
func (e *PolicyEvaluator) WaitReady(ctx context.Context, timeout time.Duration) error

// CheckAccess evaluates restriction policies for a given org and API key
// Key-specific policies always take precedence over org-wide policies
func (e *PolicyEvaluator) CheckAccess(ctx context.Context, orgUUID uuid.UUID, apiKeyUUID string, reqCtx *RequestContext) (*AccessDecision, error)
```

#### 2.2 Policy Evaluation Logic (Actual Implementation)

```go
func (e *PolicyEvaluator) CheckAccess(...) (*AccessDecision, error) {
    // 1. Check key-specific policy first (orgUUID:apiKeyUUID) - it takes precedence
    keyDecision, err := e.evaluatePolicy(ctx, orgUUID, apiKeyUUID, reqCtx)
    if err != nil {
        return nil, fmt.Errorf("failed to evaluate key-specific policy: %w", err)
    }

    // 2. If key-specific policy exists, use it (overrides org-wide)
    if keyDecision != nil {
        return keyDecision, nil
    }

    // 3. Fall back to org-wide policy (orgUUID:*)
    orgWideDecision, err := e.evaluatePolicy(ctx, orgUUID, "*", reqCtx)
    if err != nil {
        return nil, fmt.Errorf("failed to evaluate org-wide policy: %w", err)
    }

    if orgWideDecision != nil {
        return orgWideDecision, nil
    }

    // 4. No policies found - allow by default
    return &AccessDecision{
        Allowed: true,
        Reason:  "no restriction policies configured",
    }, nil
}
```

**Key behavior:** Key-specific policies completely override org-wide policies when present.

#### 2.3 Integration in authenticator-intake (dd-go/apps/authenticator-intake)

The policy evaluator is integrated into the authenticator-intake service at the authorization check point:

```go
// apps/authenticator-intake/authzcheck/check.go
func Check(ctx context.Context, req *auth.CheckRequest, resolver *resolver.CredentialResolver, policyEvaluator *policyeval.PolicyEvaluator) (*auth.CheckResponse, error) {
    // 1. Extract and resolve API key
    apiKey, err := ExtractAPIKey(ctx, req, u)
    info := resolver.Resolve(ctx, apiKey)

    // 2. Add extensive observability logging
    observability_accumulator.AddBothLogAndMetricField(ctx, "path", sanitizedPath)
    observability_accumulator.AddBothLogAndMetricField(ctx, "product", product.String())
    observability_accumulator.AddLogField(ctx, log.String("client_ip", ip))
    observability_accumulator.AddLogField(ctx, log.Int32("org_id", info.OrgID))
    observability_accumulator.AddLogField(ctx, log.String("org_uuid", info.OrgUUID))
    observability_accumulator.AddLogField(ctx, log.String("credential_type", info.Type.String()))
    observability_accumulator.AddLogField(ctx, log.String("credential_uuid", info.UUID))

    // 3. Evaluate IP-based restriction policies if authenticated
    if info.Status == model.AuthenticatedAPIKey && policyEvaluator != nil && info.OrgUUID != "" {
        orgUUID, err := uuid.Parse(info.OrgUUID)
        if err == nil {
            // Extract source IP from x-client-ip header (set by Envoy from service-discovery-platform)
            sourceIP := httpReq.GetHeaders()["x-client-ip"]

            reqCtx := &policyeval.RequestContext{
                SourceIP: sourceIP,
                Product:  product.String(),
                Path:     path,
            }

            decision, err := policyEvaluator.CheckAccess(ctx, orgUUID, info.UUID, reqCtx)
            if err != nil {
                // Fail open - log error but allow request
                log.Error("Policy evaluation error", err)
            } else if decision != nil {
                // Log comprehensive policy evaluation metrics
                log.Info("Request evaluated by restriction policy",
                    log.Bool("decision", decision.Allowed),
                    log.String("policy_id", decision.PolicyID),
                    log.String("policy_scope", decision.PolicyScope),
                    log.String("mode", string(decision.Mode)),
                    log.String("reason", decision.Reason),
                    log.Int64("eval_time_us", decision.EvaluationTime.Microseconds()))

                if !decision.Allowed {
                    // Policy denies the request
                    info.Status = model.UnauthorizedAPIKey
                    statusCode = httpStatusCode(req, &info)
                    return generateResponse(&info, statusCode)
                }
            }
        }
    }

    // Log all incoming request details for monitoring
    log.Info("Incoming request details", observability_accumulator.GetLogFields(ctx)...)

    return generateResponse(&info, envoy_type.StatusCode_OK)
}
```

#### 2.4 PolicyEvaluator Initialization

```go
// apps/authenticator-intake/server/grpc_listener.go
func mustGRPCListener(cfg config.ExtendedConfig, r *resolver.CredentialResolver) *grpcListener {
    // Initialize PolicyEvaluator for IP-based restriction policies
    contextRootPath := cfg.GetDefault("dd.authenticator.policy", "context_root_path", "")
    policyEvaluator, err := policyeval.NewPolicyEvaluator(contextRootPath)
    if err != nil {
        log.Warn("Failed to create policy evaluator, policy evaluation will be disabled", err)
        policyEvaluator = nil
    } else {
        // Wait for FRAMES to be ready in background
        go func() {
            ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
            defer cancel()
            if err := policyEvaluator.WaitReady(ctx, 30*time.Second); err != nil {
                log.Error("Policy evaluator failed to become ready", err)
            }
        }()
    }

    gl := &grpcListener{srv, serviceName, listener, r, nil, policyEvaluator}
    // ...
}
```

#### 2.5 CEL Expression Compilation

Reads from FRAMES proto and compiles CEL with correct Kubernetes library syntax:

```go
func (e *PolicyEvaluator) compilePolicy(policy *framespb.RestrictionPolicyValue) (*CachedPolicy, error) {
    // Find "access_policy" relation with "cel_expression" subject
    for _, relation := range policy.GetRelations() {
        if relation.GetRelation() != "access_policy" {
            continue
        }
        for _, subject := range relation.GetSubjects() {
            if subject.GetSubjectType() == "cel_expression" {
                celExpr := subject.GetCondition()
                // Example CEL: cidr('192.168.1.0/24').containsIP(ip(request.source_ip))

                // Parse mode from subject_id: "ip-policy-{enforced|dryrun|disabled}"
                mode := parseModeFromSubjectID(subject.GetSubjectId())

                // Compile with K8s CEL libraries
                ast, issues := e.env.Compile(celExpr)
                if issues != nil && issues.Err() != nil {
                    return nil, fmt.Errorf("failed to compile CEL expression: %w", issues.Err())
                }

                program, err := e.env.Program(ast)
                if err != nil {
                    return nil, fmt.Errorf("failed to create CEL program: %w", err)
                }

                return &CachedPolicy{
                    Program:  program,
                    Mode:     mode,
                    PolicyID: subject.GetSubjectId(),
                }, nil
            }
        }
    }
}
```

#### 2.6 Cache Strategy

- SHA-256 hash of serialized proto for cache invalidation
- If hash matches → use cached program (~0.3μs)
- If hash differs → recompile (~35μs one-time cost)
- Cache key: `"orgUUID:resourceID"` (e.g., `"550e8400-e29b-41d4-a716-446655440000:*"`)

#### 2.7 Types

```go
type RequestContext struct {
    SourceIP string
    Product  string
    Path     string
}

type AccessDecision struct {
    Allowed        bool
    Reason         string
    PolicyID       string        // "ip-policy-enforced"
    PolicyScope    string        // "*" or "key-uuid"
    Mode           PolicyMode
    WouldBlock     bool          // For dry_run mode
    EvaluationTime time.Duration
}

type PolicyMode string
const (
    PolicyModeDisabled PolicyMode = "disabled"
    PolicyModeDryRun   PolicyMode = "dry_run"
    PolicyModeEnforced PolicyMode = "enforced"
)
```

#### 2.8 File Structure

```
dd-go/
├── apps/authenticator-intake/
│   ├── policyeval/
│   │   ├── evaluator.go          # PolicyEvaluator implementation (335 lines)
│   │   ├── evaluator_test.go     # Unit tests with mock FRAMES reader (550 lines)
│   │   └── types.go              # Public types (RequestContext, AccessDecision, etc.)
│   ├── authzcheck/
│   │   ├── check.go              # Integration point for policy evaluation (+62 lines)
│   │   └── check_policy_test.go  # Integration tests (260 lines)
│   ├── server/
│   │   └── grpc_listener.go      # PolicyEvaluator initialization (+30 lines)
│   └── shadow/
│       └── grpc_listener.go      # Shadow mode support (+42 lines)
├── pkg/authdatastore/
│   ├── restriction_policy_reader.go  # FRAMES reader for restriction policies (311 lines)
│   ├── restriction_policy_codec.go   # Key serialization for FRAMES (146 lines)
│   └── proto/
│       ├── restriction_policy.proto  # Proto definitions (27 lines)
│       └── restriction_policy.pb.go  # Generated proto for policy data (260 lines)
├── resolver/
│   └── context_resolver.go       # Updated to populate OrgUUID (+1 line)
└── model/
    └── api_key.go                # Added OrgUUID field to EdgeAuthResult (+1 line)
```

**Total additions:** 2,072 lines
**Total deletions:** 12 lines

#### 2.9 Testing Strategy

**Unit Tests (policyeval/evaluator_test.go - 13 test cases):**
- `TestPolicyEvaluator_IPAllowlist`: Tests IP allowlist with Kubernetes CEL syntax
- `TestPolicyEvaluator_IPBlocklist`: Tests IP blocklist functionality
- `TestPolicyEvaluator_DryRunMode`: Tests dry-run mode behavior
- `TestPolicyEvaluator_MultipleIPRanges`: Tests complex policies with multiple CIDRs
- `TestPolicyEvaluator_PolicyPrecedence`: Tests key-specific vs org-wide precedence
- `TestPolicyEvaluator_OrgWidePolicy`: Tests org-wide policy application
- `TestPolicyEvaluator_NoPolicy`: Tests default allow when no policy exists
- `TestPolicyEvaluator_PolicyCaching`: Tests hash-based cache invalidation
- `TestPolicyEvaluator_DisabledMode`: Tests disabled policy mode
- `TestPolicyEvaluator_InvalidCEL`: Tests error handling for invalid CEL
- `TestPolicyEvaluator_ComplexPolicy`: Tests product-scoped policies
- `TestPolicyEvaluator_EmptySourceIP`: Tests empty IP handling
- `TestPolicyEvaluator_InvalidIP`: Tests invalid IP format handling

**Integration Tests (authzcheck/check_policy_test.go - 7 test cases):**
- `TestGenerateResponse_Unauthorized`: Tests 403 response generation
- `TestGenerateResponse_Authenticated`: Tests 200 response with headers
- `TestGenerateResponse_MissingAPIKey`: Tests missing API key handling
- `TestPolicyIntegration_BlockedByPolicy`: Tests policy blocking flow
- `TestPolicyIntegration_AllowedByPolicy`: Tests policy allowing flow
- `TestExtractAPIKey_FromHeader`: Tests API key extraction
- `TestSanitizePathForMetrics`: Tests path sanitization logic

All tests use mock FRAMES reader to avoid external dependencies. Test coverage demonstrates comprehensive validation of all policy evaluation scenarios.

#### 2.10 Key Implementation Decisions

**1. Self-Contained in dd-go:**
- Avoided cross-repo dependency complexity with dd-source
- Cherry-picked FRAMES reader from existing PR (#220700)
- All code lives in dd-go for easier deployment and iteration

**2. Policy Precedence Model:**
- Key-specific policies completely override org-wide when present
- Simplifies mental model: "most specific policy wins"
- Org-wide acts as default when no key-specific policy exists

**3. Fail-Open Behavior:**
- On evaluation errors, requests are allowed
- Prioritizes availability over security
- All errors are logged for monitoring

**4. CEL Syntax:**
- Uses Kubernetes library syntax: `cidr('192.168.1.0/24').containsIP(ip(request.source_ip))`
- Consistent with industry standards
- Supports complex expressions with AND/OR logic

**5. Caching Strategy:**
- SHA-256 hash-based cache invalidation
- Compiled programs cached indefinitely until policy changes
- ~0.3μs cached evaluation vs ~35μs compilation

**6. Observability Integration:**
- Comprehensive logging with `observability_accumulator`
- Both log and metric fields tracked for all requests
- Detailed policy evaluation metrics including decision, mode, and evaluation time

**7. Shadow Mode Support:**
- Implemented shadow mode in `shadow/grpc_listener.go`
- Allows testing policy evaluation without affecting traffic
- Logs decisions without blocking requests

---

### Day 3: Staging Deployment & Validation

- [ ] Deploy to staging with dry_run policies
- [ ] Verify FRAMES propagation (~5s)
- [ ] Test policy updates and mode transitions
- [ ] Validate performance under load
- [ ] Demo preparation

---

## Performance

| Metric | Value |
|--------|-------|
| Traffic volume | 7M req/sec |
| Latency budget | 200μs P99 |
| CEL evaluation | ~0.3μs (cached) |
| CEL compilation | ~35μs (one-time) |
| **Result** | 600x under budget |

## Future Extensions

CEL expressions can be extended without code changes:

```javascript
// Add country blocking
!(cidr('1.2.3.0/24').containsIP(ip(request.source_ip)) || request.country == 'CN')

// Add time-based rules
cidr('10.0.0.0/8').containsIP(ip(request.source_ip)) && timestamp(request.timestamp).getHours() >= 9

// Add product scoping
request.product == 'logs' && cidr('10.0.0.0/8').containsIP(ip(request.source_ip))
```
