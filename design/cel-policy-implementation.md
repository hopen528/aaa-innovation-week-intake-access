# IP-Based Restriction Policies - Innovation Week Implementation

## Goal

Build an **IP-based access control system** using CEL (Common Expression Language) that works for:
1. **Intake traffic access control** (IP blocking/allowlisting - PRIMARY)
2. **Future: GRACE resource authorization** (can extend to other attributes easily)

## Architecture Decision: CEL Evaluator

**Chosen Approach**: CEL (Common Expression Language) for attribute-based access control

**Why CEL?**
- **Future-proof**: Can extend to country, user-agent, time-based rules without rewrites
- **Flexible**: Users can express complex attribute logic
- **Standard**: Industry-proven (Kubernetes, Envoy, Google Cloud)
- **Extremely fast**: ~0.3μs evaluation (600x under 200μs budget!)
- **Battle-tested**: Using Kubernetes CEL IP/CIDR library (k8s.io/apiserver)
- **No migration needed**: Start with IP, easily add more attributes later

**Why not hand-rolled or SpiceDB?**
- Hand-rolled has similar performance but requires rewrites when users want more attributes
- SpiceDB is for relationships (user→team→resource), not attributes (IP, country, etc.)

**Key Insight:** Zoltron restriction policies **already stream to FRAMES** - we just need to store CEL expressions in RelationTuples and evaluate them!

**Innovation Week Demo:**
1. Create IP block policy via rbac-public API (generates CEL expression)
2. Policy stored as RelationTuples in Zoltron → automatically streams to FRAMES
3. AuthN sidecar evaluates with Kubernetes CEL engine (~0.3μs)
4. Blocked request → 403 Forbidden

**Critical Performance Requirement:**
- **Traffic volume:** 7M requests/second
- **Latency budget:** 200μs P99
- **Benchmark results:**
  - CEL evaluation: **~0.3μs** (600x under budget!)
  - CEL compilation: ~35μs (one-time cost, amortized)
  - **Strategy:** Compile once on policy load, cache compiled programs, only recompile on FRAMES updates
  - **Library:** Using Kubernetes k8s.io/apiserver/pkg/cel/library (battle-tested)
- **Architecture:** Zoltron → FRAMES → CEL evaluation (blazingly fast & flexible!)

## Architecture

```
┌─────────────────── Edge / Data Plane ─────────────────────┐
│                                                            │
│  Envoy → AuthN Sidecar → Logs/Metrics Intake             │
│          │                                                 │
│          ├─ libcontext (local RocksDB)                    │
│          │  - Restriction policies via FRAMES             │
│          │  - Kubernetes CEL IP/CIDR library              │
│          │  - ~0.3μs evaluation (blazingly fast!)         │
│          │                                                 │
│          └─ Check CEL expressions → 403 if blocked        │
│                                                            │
└────────────────────────┬───────────────────────────────────┘
                         │ Already exists!
                         │ (Zoltron → FRAMES)
                         ↓
┌──────────────────── Control Plane ────────────────────────┐
│                                                            │
│  ┌──────────────────┐        ┌──────────────┐            │
│  │    Zoltron       │───────▶│    FRAMES    │            │
│  │  Restriction     │        │   Platform   │            │
│  │   Policies       │        │ (Kafka + S3) │            │
│  │                  │        │              │            │
│  │ - Manage         │        │              │            │
│  │   policies       │        │              │            │
│  │ - Stream to      │        │              │            │
│  │   FRAMES         │        │              │            │
│  └──────────────────┘        └──────────────┘            │
│         ▲                                                  │
│         │                                                  │
│  ┌──────┴──────┐    ┌──────────┐                         │
│  │   gRPC      │    │    UI    │                         │
│  │   API       │    │          │                         │
│  └─────────────┘    └──────────┘                         │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

## Reusing Existing Zoltron Infrastructure

**Key Insight**: Zoltron already has everything we need! No new protos required.

### Existing Proto (Already in Zoltron)

```protobuf
// This already exists in Zoltron!
message RelationTuple {
    string subject_type = 1;  // "api_key"
    string subject_id = 2;    // "key-123"
    string relation = 3;      // "access_policy"
    string object_type = 4;   // "cel_expression"
    string object_id = 5;     // "expr-uuid"
    string condition = 6;     // CEL expression: "!cidr('192.168.1.0/24').containsIP(ip(request.source_ip))"
}
```

**That's it!** This tuple format stores CEL expressions:
- ✅ Subject: Which API key
- ✅ Relation: "access_policy"
- ✅ Condition: CEL expression to evaluate

### Example Data

**Stored in Zoltron database:**
```sql
subject_type | subject_id | relation      | object_type     | object_id | condition
-------------|------------|---------------|-----------------|-----------|------------------------------------------
api_key      | key-123    | access_policy | cel_expression  | expr-1    | !cidr('192.168.1.0/24').containsIP(ip(request.source_ip))
api_key      | key-456    | access_policy | cel_expression  | expr-2    | request.country != 'CN' && !cidr('1.2.3.0/24').containsIP(ip(request.source_ip))
```

**Flows to FRAMES:** Same format, already streaming!

**Parsed by authenticator-intake:**
```go
// Read RelationTuple from FRAMES
tuple := &RelationTuple{
    SubjectType: "api_key",
    SubjectID:   "key-123",
    Relation:    "access_policy",
    ObjectType:  "cel_expression",
    ObjectID:    "expr-1",
    Condition:   "!cidr('192.168.1.0/24').containsIP(ip(request.source_ip))",
}

// Compile CEL expression (one-time cost: ~35μs)
ast, _ := celEnv.Compile(tuple.Condition)
prg, _ := celEnv.Program(ast)

// Store compiled program for fast evaluation (~0.3μs per request)
evaluator.programs[tuple.SubjectID] = prg
```

**No new protos needed!** ✅

## How Org ID Resolution Works

### authenticator-intake Already Has api_key → org Mapping!

**Key Discovery:** The authenticator-intake already resolves API keys to org IDs as part of normal authentication flow.

**From `dd-go/model/api_key.go`:**
```go
type EdgeAuthResult struct {
    OrgID          int32   // ✅ Org ID available here!
    Fingerprint    string
    UUID           string
    Status         APIKeyAuthenticationStatus
    Type           CredentialTypeEnum
    LastModifiedAt *time.Time
}
```

**Evaluation Flow:**
```go
func (s *AuthNSidecar) ValidateIntakeRequest(req *IntakeRequest) error {
    // Step 1: Resolve API key (existing authentication flow)
    authResult := s.credentialResolver.Resolve(ctx, req.APIKey)
    orgID := authResult.OrgID          // ✅ Org ID from existing auth!
    apiKeyID := req.APIKey.ID

    // Step 2: Load policies from FRAMES using org context
    // FRAMES is keyed by: RestrictionPolicyKey{OrgUUID, ResourceType, ResourceID}
    ctx := RequestContext{
        SourceIP: req.ClientIP,
    }

    // Step 3: CEL evaluator checks both org-wide and key-specific
    // The evaluator internally looks up:
    //   - (orgID, "api_key", "*")      → org-wide policy
    //   - (orgID, "api_key", apiKeyID) → key-specific policy
    decision, err := s.celEvaluator.CheckAccess(apiKeyID, &ctx)

    if !decision.Allowed {
        return &ForbiddenError{StatusCode: 403, Message: decision.Reason}
    }
    return nil
}
```

**FRAMES Context Structure:**
```go
RestrictionPolicyKey {
    OrgUUID:      orgID,        // From EdgeAuthResult
    ResourceType: "api_key",
    ResourceID:   "*" or "key-456"
}
```

**Benefits:**
- ✅ **No extra lookups needed** - org ID comes from existing auth flow
- ✅ **Zero additional latency** - already resolved before policy check
- ✅ **Natural integration** - fits perfectly with current architecture
- ✅ **Efficient FRAMES lookup** - can query policies by org context

## Implementation Plan - Innovation Week

### Day 1: API + UI Implementation ✅ COMPLETED
**Goal:** Create IP policy API and management UI

#### Backend (dd-source: `ACCESSINT-1112-ip-policy-crud-endpoints`)

- [x] Add "api_key" resource type, "cel_expression" principal type, and "access_policy" relation to database enums
  - Migration: `000107_add_ip_policy_types.up.sql`
- [x] Create 4 API endpoints in rbac-public (`/api/unstable/orgs/{org_uuid}/ip-policies`)
  - `POST` - Create IP policy with `{resource_id, blocked_cidrs, allowed_cidrs, mode}`
  - `GET` - List all policies or filter by `?resource_id=`
  - `PATCH /{resource_id}` - Update CIDRs and/or mode
  - `DELETE /{resource_id}` - Delete policy
- [x] Backend generates CEL expressions from CIDR lists
  - Blocked: `!(cidr('x.x.x.x/x').containsIP(ip(request.source_ip)) || ...)`
  - Allowed: `cidr('x.x.x.x/x').containsIP(ip(request.source_ip)) || ...`
  - Combined: allowlist AND NOT blocklist
- [x] FRAMES notifier integration for policy changes
  - New `frames.Notifier` implementation with async notifications
  - Notifies on create, update, and delete operations
- [x] Policy mode encoded in `principal_id` field (`ip-policy-{disabled|dryrun|enforced}`)

#### Frontend (web-ui: `erica.zhong/ACCESSINT-1112-ip-policies-ui`)

- [x] New page at `/organization-settings/ip-policies`
  - `PageIpPolicies.tsx` with title, info box, and table
  - Added to org settings navigation and routes
- [x] `IpPoliciesTable` component
  - Displays resource ID, blocked/allowed CIDRs, and mode badge
  - Edit and delete actions per row
  - Mode badge colors: enforced (danger), dry_run (warning), disabled (default)
- [x] `IpPolicyAddModal` for creating new policies
  - Resource ID input (org-wide `*` or specific key ID)
  - Blocked/allowed CIDRs input
  - Mode selector (disabled/dry_run/enforced)
- [x] `IpPolicyEditModal` for updating existing policies
- [x] API hooks using react-query
  - `useGetApiUnstableOrgsIpPolicies`
  - `usePostApiUnstableOrgsIpPolicies`
  - `useDeleteApiUnstableOrgsIpPoliciesId`
- [x] Feature flag: `ip_policies_ui`

**Deliverable:** End-to-end IP policy management (API + UI + FRAMES) ✅

### Day 2: Data Plane Implementation (CEL Evaluator + Integration)
**Goal:** Build policy reader, evaluator, and integrate into authenticator-intake

#### 2.1 Update EdgeAuthResult to Include Org UUID (dd-go/model/api_key.go)

**Add OrgUUID field to EdgeAuthResult:**

ApiKeyContext already has `OrgUuid` field (from `acepb.ApiKeyContext`), but it's not exposed in `EdgeAuthResult`. We just need to add it:

```go
// Location: ~/dd/newdd-go/dd-go/model/api_key.go

type EdgeAuthResult struct {
    OrgID          int32
    OrgUUID        string   // ✅ ADD THIS - comes from ApiKeyContext.OrgUuid
    Fingerprint    string
    UUID           string
    Status         APIKeyAuthenticationStatus
    Type           CredentialTypeEnum
    LastModifiedAt *time.Time
    Policies       []*acepb.Policy
}
```

**Update credential resolver to populate OrgUUID:**

```go
// Location: credential resolver that creates EdgeAuthResult
// When converting ApiKeyContext → EdgeAuthResult, add:

result := EdgeAuthResult{
    OrgID:          int32(apiKeyContext.OrgId),
    OrgUUID:        apiKeyContext.OrgUuid,  // ✅ Populate from ApiKeyContext
    Fingerprint:    apiKeyContext.Fingerprint,
    UUID:           apiKeyContext.Uuid,
    // ... rest of fields
}
```

**Code pointers:**
- ApiKeyContext proto: `~/dd/dd-source/domains/aaa/apps/ace-contexts/acepb/credential.pb.go` (has `OrgUuid string` field)
- EdgeAuthResult: `~/dd/newdd-go/dd-go/model/api_key.go` (needs `OrgUUID string` field added)

#### 2.2 Policy Context Infrastructure (dd-go/pkg/authdatastore)

**2.2.1 Restriction Policy Frames** (`restriction_policy_frames.go`)
Copy frame codec and proto from dd-source for innovation week:

```go
package authdatastore

// Copy from dd-source for innovation week (move to common later)
// RestrictionPolicyKey matches zoltron format
type RestrictionPolicyKey struct {
    OrgUUID      uuid.UUID
    ResourceType string  // "api_key"
    ResourceID   string  // "*" or "key-uuid"
}

type RestrictionPolicyCodec struct {
    resourceTypeValidator func(string) bool
}

func (c *RestrictionPolicyCodec) Serialize(key RestrictionPolicyKey) ([]byte, error)
func (c *RestrictionPolicyCodec) Deserialize(data []byte) (RestrictionPolicyKey, error)
func (c *RestrictionPolicyCodec) ByteSize() int
func (c *RestrictionPolicyCodec) ContextType() string  // "ZOLTRON_RESTRICTION_POLICIES_CONTEXT"
```

**Code to copy:**
- Source codec: `~/dd/dd-source/domains/aaa/apps/zoltron/internal/frames/codec.go:101-212`
- Source proto: `~/dd/dd-source/domains/aaa/apps/zoltron/internal/frames/proto/restriction_policy.proto`
- Frame reader pattern: `~/dd/dd-source/domains/aaa/apps/zoltron/internal/frames/reader.go:124-144`

**2.2.2 Policy Reader** (`restriction_policy_context.go`)
FRAMES reader wrapper for restriction policies (no org UUID conversion needed):

```go
package authdatastore

import (
    framespb "github.com/DataDog/dd-go/pkg/authdatastore/proto"  // Copied proto
    "go.ddbuild.io/dd-source/domains/event-platform/shared/libs/go/libcontext"
)

// PolicyReader provides lookup interface for restriction policies
// Accepts orgUUID directly from EdgeAuthResult (no conversion needed)
type PolicyReader interface {
    // Get looks up policy for given org UUID, resource type, and resource ID
    // Returns nil if no policy exists (not an error)
    Get(ctx context.Context, orgUUID uuid.UUID, resourceType, resourceID string) (*framespb.RestrictionPolicyValue, error)

    // WaitReady blocks until FRAMES snapshot is loaded
    WaitReady(ctx context.Context, timeout time.Duration) error

    // IsReady returns true if reader is ready
    IsReady() bool

    // Close cleans up resources
    Close() error
}

type policyReader struct {
    codec  *RestrictionPolicyCodec
    reader frames.Reader[RestrictionPolicyKey, *framespb.RestrictionPolicyValue]
}

func NewPolicyReader(contextRootPath string) (PolicyReader, error) {
    codec := &RestrictionPolicyCodec{
        resourceTypeValidator: func(rt string) bool {
            return rt == "api_key"  // Only support api_key for now
        },
    }

    reader := frames.NewReader[RestrictionPolicyKey, *framespb.RestrictionPolicyValue](
        codec,
        frames.WithContextRootPath(contextRootPath),
    )

    return &policyReader{
        codec:  codec,
        reader: reader,
    }, nil
}

func (r *policyReader) Get(ctx context.Context, orgUUID uuid.UUID, resourceType, resourceID string) (*framespb.RestrictionPolicyValue, error) {
    key := RestrictionPolicyKey{
        OrgUUID:      orgUUID,
        ResourceType: resourceType,
        ResourceID:   resourceID,
    }
    return r.reader.Get(ctx, key)
}
```

**Benefits:**
- ✅ No org UUID context needed - EdgeAuthResult already has it
- ✅ One fewer FRAMES lookup (eliminates orgID → orgUUID conversion)
- ✅ Simpler PolicyReader implementation
- ✅ Direct lookup using data we already have

**Code pointers:**
- FRAMES reader API: `~/dd/dd-source/domains/aaa/apps/zoltron/internal/frames/reader.go:35-47`
- Example usage: `~/dd/dd-source/domains/aaa/apps/zoltron/internal/frames/reader.go:78-95`

#### 2.3 Policy Evaluator (dd-go/apps/authenticator-intake/pkg/policyeval)

**2.3.1 Cache Structure with Hash-Based Invalidation**

```go
package policyeval

import (
    "crypto/sha256"
    "github.com/google/cel-go/cel"
    "k8s.io/apiserver/pkg/cel/library"
)

// CachedPolicy stores pre-compiled CEL program with hash for cache invalidation
type CachedPolicy struct {
    Program  cel.Program
    Hash     [32]byte  // SHA-256 hash of serialized proto
    Mode     PolicyMode
    PolicyID string
}

// PolicyEvaluator evaluates restriction policies with hash-based caching
type PolicyEvaluator struct {
    mu           sync.RWMutex
    env          *cel.Env
    cache        map[string]*CachedPolicy  // Key: "<orgID>:<apiKeyUUID>"
    policyReader authdatastore.PolicyReader  // Handles orgID → orgUUID internally
}
```

**2.3.2 Initialize Method**

```go
// Initialize creates evaluator with empty cache and CEL environment
func (e *PolicyEvaluator) Initialize(contextRootPath string) error {
    // Step 1: Create CEL environment with K8s libraries
    env, err := cel.NewEnv(
        cel.Variable("request", cel.MapType(cel.StringType, cel.AnyType)),
        library.IP(),    // Kubernetes IP library
        library.CIDR(),  // Kubernetes CIDR library
    )
    if err != nil {
        return fmt.Errorf("failed to create CEL environment: %w", err)
    }
    e.env = env

    // Step 2: Initialize empty cache
    e.cache = make(map[string]*CachedPolicy)

    // Step 3: Create policy reader (FRAMES)
    // No org UUID conversion needed - EdgeAuthResult already has orgUUID
    e.policyReader, err = authdatastore.NewPolicyReader(contextRootPath)
    if err != nil {
        return fmt.Errorf("failed to create policy reader: %w", err)
    }

    // Step 4: Wait for FRAMES to be ready
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := e.policyReader.WaitReady(ctx, 30*time.Second); err != nil {
        return fmt.Errorf("policy reader not ready: %w", err)
    }

    return nil
}
```

**2.3.3 CheckAccess Method with Hash-Based Caching**

```go
// CheckAccess evaluates policy with hash-based cache invalidation
// Flow:
// 1. Lookup policy from FRAMES reader using orgUUID (from EdgeAuthResult)
// 2. Calculate hash of policy proto
// 3. Check cache:
//    - Hash matches → use cached program
//    - Hash differs or missing → compile new program, update cache
// 4. Evaluate and return decision
func (e *PolicyEvaluator) CheckAccess(orgID int32, orgUUID uuid.UUID, apiKeyUUID string, ctx *RequestContext) (*AccessDecision, error) {
    startTime := time.Now()

    // Step 1: Check org-wide policy first (orgID:*)
    orgWideKey := fmt.Sprintf("%d:*", orgID)
    if decision, err := e.evaluateWithCache(orgID, orgUUID, "*", orgWideKey, ctx); err != nil {
        return nil, err
    } else if decision != nil && !decision.Allowed && decision.Mode == PolicyModeEnforced {
        decision.EvaluationTime = time.Since(startTime)
        return decision, nil
    }

    // Step 2: Check key-specific policy (orgID:apiKeyUUID)
    keySpecificKey := fmt.Sprintf("%d:%s", orgID, apiKeyUUID)
    decision, err := e.evaluateWithCache(orgID, orgUUID, apiKeyUUID, keySpecificKey, ctx)
    if err != nil {
        return nil, err
    }

    if decision == nil {
        // No policy exists - allow by default
        return &AccessDecision{
            Allowed:        true,
            EvaluationTime: time.Since(startTime),
        }, nil
    }

    decision.EvaluationTime = time.Since(startTime)
    return decision, nil
}

// evaluateWithCache handles hash-based cache check and compilation
func (e *PolicyEvaluator) evaluateWithCache(orgID int32, orgUUID uuid.UUID, resourceID, cacheKey string, ctx *RequestContext) (*AccessDecision, error) {
    // Step 1: Lookup policy from FRAMES using orgUUID (from EdgeAuthResult)
    policyProto, err := e.policyReader.Get(context.Background(), orgUUID, "api_key", resourceID)
    if err != nil {
        return nil, fmt.Errorf("failed to lookup policy: %w", err)
    }

    if policyProto == nil || policyProto.GetIsDeleted() {
        // No policy exists (tombstone or not found)
        return nil, nil
    }

    // Step 2: Calculate hash of serialized proto
    serialized, err := proto.Marshal(policyProto)
    if err != nil {
        return nil, fmt.Errorf("failed to serialize policy: %w", err)
    }
    policyHash := sha256.Sum256(serialized)

    // Step 3: Check cache with hash comparison
    e.mu.RLock()
    cached, exists := e.cache[cacheKey]
    e.mu.RUnlock()

    var program *CachedPolicy

    if exists && cached.Hash == policyHash {
        // Cache hit - hash matches, use cached program
        program = cached
    } else {
        // Cache miss or hash mismatch - compile new program
        compiled, err := e.compilePolicy(policyProto)
        if err != nil {
            return nil, fmt.Errorf("failed to compile policy: %w", err)
        }

        // Update cache with new program and hash
        e.mu.Lock()
        e.cache[cacheKey] = &CachedPolicy{
            Program:  compiled.Program,
            Hash:     policyHash,
            Mode:     compiled.Mode,
            PolicyID: compiled.PolicyID,
        }
        program = e.cache[cacheKey]
        e.mu.Unlock()
    }

    // Step 4: Evaluate policy
    return e.evaluateProgram(program, ctx)
}

// compilePolicy compiles RelationSubjects from proto into CEL program
func (e *PolicyEvaluator) compilePolicy(policyProto *framespb.RestrictionPolicyValue) (*CachedPolicy, error) {
    // Extract CEL expression from RelationSubjects
    // Format in proto:
    //   relations[0].relation = "access_policy"
    //   relations[0].subjects[0].condition = CEL expression
    //   relations[0].subjects[0].subject_id = mode suffix

    for _, rel := range policyProto.GetRelations() {
        if rel.GetRelation() != "access_policy" {
            continue
        }

        for _, subject := range rel.GetSubjects() {
            expression := subject.GetCondition()
            if expression == "" {
                continue
            }

            // Parse mode from subject_id
            mode := parsePolicyMode(subject.GetSubjectId())

            // Compile CEL expression (~35μs - one-time cost)
            ast, issues := e.env.Compile(expression)
            if issues != nil && issues.Err() != nil {
                return nil, issues.Err()
            }

            prg, err := e.env.Program(ast)
            if err != nil {
                return nil, err
            }

            return &CachedPolicy{
                Program:  prg,
                Mode:     mode,
                PolicyID: subject.GetSubjectId(),
            }, nil
        }
    }

    return nil, fmt.Errorf("no valid access_policy found in proto")
}
```

**Key insights:**
- Hash-based caching eliminates need to track FRAMES updates manually
- SHA-256 hash of serialized proto is the cache key
- If proto unchanged → hash matches → use cached program (no recompilation)
- If proto changed → hash differs → recompile and update cache
- Compilation cost (~35μs) only paid on cache miss
- No org UUID conversion needed - EdgeAuthResult already provides it (from ApiKeyContext)
- One fewer FRAMES lookup compared to orgID → orgUUID conversion approach

#### 2.4 Integration in AuthN Handler

Update authenticator-intake to use policy evaluator:

```go
// Location: dd-go/apps/authenticator-intake/authzcheck/check.go

func (s *AuthNSidecar) ValidateIntakeRequest(req *IntakeRequest) error {
    // Step 1: Authenticate API key (existing flow)
    authResult := s.credentialResolver.Resolve(ctx, req.APIKey)
    if authResult.Status != model.AuthenticatedAPIKey {
        return &UnauthorizedError{StatusCode: 401}
    }

    // Step 2: Extract identifiers from EdgeAuthResult
    orgID := authResult.OrgID          // int32 from EdgeAuthResult
    orgUUID, err := uuid.Parse(authResult.OrgUUID)  // ✅ Parse orgUUID from EdgeAuthResult
    if err != nil {
        return fmt.Errorf("invalid org UUID: %w", err)
    }
    apiKeyUUID := authResult.UUID      // string from EdgeAuthResult

    // Step 3: Build request context
    reqCtx := &policyeval.RequestContext{
        SourceIP:  req.ClientIP,
        Country:   req.GeoIP.Country,
        UserAgent: req.Headers.UserAgent,
    }

    // Step 4: Evaluate policy (checks org-wide and key-specific)
    // Pass both orgID (for cache key) and orgUUID (for FRAMES lookup)
    decision, err := s.policyEvaluator.CheckAccess(orgID, orgUUID, apiKeyUUID, reqCtx)
    if err != nil {
        // Log error, fail open
        s.metrics.IncrementPolicyEvalErrors()
        log.Warn("Policy evaluation error",
            log.Int32("org_id", orgID),
            log.String("api_key_uuid", apiKeyUUID),
            log.ErrorField(err))
        return nil  // Fail open
    }

    // Step 5: Handle decision
    if !decision.Allowed {
        s.metrics.IncrementBlockedRequests(orgID, apiKeyUUID, reqCtx.SourceIP)
        log.Info("Request blocked by policy",
            log.Int32("org_id", orgID),
            log.String("api_key_uuid", apiKeyUUID),
            log.String("policy_id", decision.PolicyID),
            log.String("ip", reqCtx.SourceIP),
            log.String("reason", decision.Reason),
            log.Duration("eval_time_us", decision.EvaluationTime))
        return &ForbiddenError{
            StatusCode: 403,
            Message:    decision.Reason,
        }
    }

    return nil
}
```

#### 2.5 Metrics and Logging

```go
// Policy evaluation metrics
policy_evaluation_duration_us{org_id, mode}  // Evaluation latency
policy_evaluations_total{org_id, mode, blocked}  // Evaluation counts
policy_cache_hits_total{org_id}  // Cache hit rate
policy_cache_misses_total{org_id}  // Cache miss rate (triggers compilation)
policy_compilation_duration_us{org_id}  // Compilation time on cache miss

// Logs
{"level": "info", "msg": "Policy evaluation",
 "org_id": 123, "api_key_uuid": "key-456",
 "policy_id": "expr-789", "mode": "enforced",
 "blocked": false, "eval_time_us": 0.35,
 "cache_hit": true}
```

#### 2.6 Testing Checklist

- [ ] **Unit tests:**
  - Policy reader lookup (org-wide, key-specific, not found)
  - Hash-based cache (hit, miss, invalidation)
  - CEL compilation and evaluation
  - All 3 modes (disabled, dry_run, enforced)

- [ ] **Integration tests:**
  - FRAMES reader initialization
  - Org UUID context lookup
  - End-to-end evaluation flow
  - Cache invalidation on policy update

- [ ] **Performance tests:**
  - Cache hit latency: <0.5μs
  - Cache miss latency: <35μs (compilation)
  - Memory usage: reasonable cache size

- [ ] **Local testing:**
  - Create test policy via UI
  - Verify FRAMES propagation
  - Test request blocked/allowed
  - Test mode transitions

**Deliverable:** Working policy evaluator with hash-based caching, ~0.4μs cache-hit latency, ~35μs cache-miss latency

#### 2.7 File Structure Summary

```
dd-go/
├── model/
│   └── api_key.go                       # ✅ Add OrgUUID field to EdgeAuthResult
│
├── pkg/authdatastore/
│   ├── restriction_policy_frames.go     # Copied codec from dd-source
│   ├── restriction_policy_context.go    # FRAMES reader wrapper (simple - no conversion)
│   └── proto/
│       └── restriction_policy.proto     # Copied from dd-source
│
└── apps/authenticator-intake/
    ├── pkg/policyeval/
    │   ├── evaluator.go                 # PolicyEvaluator with hash caching
    │   ├── types.go                     # PolicyMode, RequestContext, AccessDecision
    │   └── evaluator_test.go            # Unit tests
    └── authzcheck/
        └── check.go                     # Integration point (updated)
```

**Key changes:**
- ✅ EdgeAuthResult now has OrgUUID field (from ApiKeyContext.OrgUuid)
- ✅ No org UUID context needed - eliminates one FRAMES lookup
- ✅ PolicyReader is simpler - just wraps FRAMES reader, no conversion
- ✅ Evaluator receives orgUUID directly from EdgeAuthResult

#### 2.8 Code Pointer Reference

| Component | Source Reference | Target Location / Change |
|-----------|------------------|--------------------------|
| EdgeAuthResult OrgUUID | `~/dd/dd-source/domains/aaa/apps/ace-contexts/acepb/credential.pb.go` (ApiKeyContext.OrgUuid) | Add `OrgUUID string` field to `~/dd/newdd-go/dd-go/model/api_key.go` |
| RestrictionPolicy Codec | `~/dd/dd-source/domains/aaa/apps/zoltron/internal/frames/codec.go:101-212` | `dd-go/pkg/authdatastore/restriction_policy_frames.go` |
| RestrictionPolicy Proto | `~/dd/dd-source/domains/aaa/apps/zoltron/internal/frames/proto/restriction_policy.proto` | `dd-go/pkg/authdatastore/proto/restriction_policy.proto` |
| FRAMES Reader Pattern | `~/dd/dd-source/domains/aaa/apps/zoltron/internal/frames/reader.go:124-144` | `dd-go/pkg/authdatastore/restriction_policy_context.go` |
| CEL Evaluator Pattern | `~/dd/aaa-innovation-week-intake-access/benchmark/cel_evaluator.go` | `dd-go/apps/authenticator-intake/pkg/policyeval/evaluator.go` |

### Day 3: Staging Deployment & Validation
**Goal:** Deploy to staging and validate end-to-end

- [ ] Deploy to staging environment
  - Roll out to staging pods with dry_run policies
  - Monitor logs and metrics
- [ ] End-to-end validation
  - Create org-wide and key-specific policies
  - Verify FRAMES propagation (~5s)
  - Test policy updates and incremental changes
  - Validate performance under realistic load
- [ ] Edge case testing
  - Invalid CEL expressions (fail open)
  - Missing policies (default allow)
  - Policy conflicts (key-specific + org-wide)
- [ ] Dry run analysis
  - Review "would block" metrics
  - Identify false positives
  - Tune policies as needed
- [ ] Demo preparation
  - Create demo policy via UI
  - Show FRAMES propagation
  - Show request blocked in real-time
  - Demo mode transitions (disabled → dry_run → enforced)
  - Show metrics dashboard
  - Demo future flexibility (add country/time rules)

**Deliverable:** Validated in staging, demo ready

### Post-Innovation Week: Production Rollout
**Goal:** Deploy to production (out of scope for Innovation Week)

- [ ] Gradual production rollout
  - Deploy to 1% → 10% → 100% of pods
  - Start with dry_run mode policies
  - Monitor metrics at each stage
- [ ] Promote to enforcement
  - Update validated policies to `mode: "enforced"`
  - Monitor blocked request rates
  - Verify no false positives
- [ ] Documentation
  - Runbook for policy management
  - Troubleshooting guide
  - Metrics and alerting setup

**Deliverable:** Production IP blocking system

## Simplified API Implementation

### Domain-Specific Endpoint (Clean UX)

Instead of generic restriction policy format, create a simple IP policy endpoint that generates CEL expressions:

```go
// Implemented endpoints in rbac-public (unstable API)
POST   /api/unstable/orgs/{org_uuid}/ip-policies              // Create
GET    /api/unstable/orgs/{org_uuid}/ip-policies              // List (optional ?resource_id filter)
PATCH  /api/unstable/orgs/{org_uuid}/ip-policies/{resource_id} // Update
DELETE /api/unstable/orgs/{org_uuid}/ip-policies/{resource_id} // Delete

// Request body (simple!)
{
  "resource_id": "key-123",  // "*" for org-wide, "key-123" for key-specific
  "blocked_cidrs": ["192.168.1.0/24", "10.0.0.0/8"],
  "allowed_cidrs": ["8.8.8.0/24"],
  "mode": "enforced"  // Optional: "disabled" | "dry_run" | "enforced" (default: "enforced")
}
```

### Translation to RelationTuples with CEL (Backend)

```go
func (s *PolicyService) CreateIPPolicy(apiKeyID string, req *IPPolicyRequest) error {
    // Generate CEL expression from CIDRs
    var conditions []string

    // Block conditions (using Kubernetes library syntax)
    for _, cidr := range req.BlockedCIDRs {
        conditions = append(conditions, fmt.Sprintf("cidr('%s').containsIP(ip(request.source_ip))", cidr))
    }

    // Build final expression
    var celExpr string
    if len(conditions) > 0 {
        // Block if IP matches any blocked CIDR
        celExpr = fmt.Sprintf("!(%s)", strings.Join(conditions, " || "))
    }

    // Generate object_id with mode metadata embedded
    // Format: "expr-{uuid}-{mode}" where mode is: disabled | dryrun | enforced
    baseID := fmt.Sprintf("expr-%s", uuid.New().String())
    objectID := fmt.Sprintf("%s-%s", baseID, req.Mode)

    // Create RelationTuple with CEL expression
    tuple := RelationTuple{
        SubjectType: "api_key",
        SubjectID:   apiKeyID,
        Relation:    "access_policy",
        ObjectType:  "cel_expression",
        ObjectID:    objectID,  // Dry run metadata encoded here
        Condition:   celExpr,
    }

    // Store using existing RelationTuple service
    return s.tupleService.CreateTuple(ctx, tuple)
}
```

**Benefits:**
- ✅ Clean, domain-specific API for users
- ✅ Stores as RelationTuples (existing table) with CEL in condition field
- ✅ Flows through existing FRAMES provider
- ✅ No new infrastructure needed!
- ✅ Can easily extend to other attributes later (just modify CEL generation)

## How to Create IP Policies

### Consolidated API (4 Endpoints)

**All policies managed through single endpoint:**
```
POST   /api/unstable/orgs/{org_uuid}/ip-policies              # Create policy
GET    /api/unstable/orgs/{org_uuid}/ip-policies              # List policies
PATCH  /api/unstable/orgs/{org_uuid}/ip-policies/{resource_id} # Update CIDRs/mode
DELETE /api/unstable/orgs/{org_uuid}/ip-policies/{resource_id} # Delete policy
```

**Scope determined by `resource_id` in request body:**
- `"*"` - Creates org-wide policy (affects all API keys)
- `"key-123"` - Creates key-specific policy (affects only that key)

**When to use which:**
- Use **`resource_id: "*"`** for: blocking malicious IPs/ranges for entire org, enforcing corporate network requirements
- Use **`resource_id: "key-123"`** for: special exceptions, different requirements per service/team

### Request Format (Simple JSON)

```json
{
  "resource_id": "*",    // "*" for org-wide, "key-123" for key-specific
  "blocked_cidrs": [
    "192.168.1.0/24",
    "10.0.0.0/8"
  ],
  "allowed_cidrs": [
    "8.8.8.0/24"
  ],
  "mode": "enforced"
}
```

**Fields:**
- `resource_id`: Scope of policy - `"*"` (org-wide) or specific key ID
- `blocked_cidrs`: List of CIDR blocks to block
- `allowed_cidrs`: List of CIDR blocks to allow (optional)
- `mode`: Policy enforcement mode (optional, default: `"enforced"`)
  - `"disabled"` - Policy doesn't evaluate at all (dormant)
  - `"dry_run"` - Policy evaluates but never blocks (testing/shadow mode)
  - `"enforced"` - Policy evaluates and blocks (full enforcement)

**That's it!** Just list the CIDRs.

**What happens behind the scenes:**
1. API receives simple JSON
2. Backend generates CEL expression (using Kubernetes library syntax):
   ```javascript
   !(cidr('192.168.1.0/24').containsIP(ip(request.source_ip)) ||
     cidr('10.0.0.0/8').containsIP(ip(request.source_ip)))
   ```
3. Stores in RelationTuple condition field
4. FRAMES notified of context change
5. FRAMES streams to all pods
6. AuthN sidecar compiles and evaluates CEL with K8s library (~0.3μs)

**Benefits:**
- ✅ Extremely simple - just a list of CIDRs
- ✅ Backend handles CEL generation automatically
- ✅ Automatic FRAMES streaming
- ✅ Type-safe (validates CIDR format)
- ✅ Future-proof (easy to extend to other attributes)

### Example 1: Org-Wide Block (All API Keys)

Block a malicious IP range for the entire organization:

```bash
curl -X POST http://localhost:8080/api/v1/orgs/org-123/ip-policies \
  -H "Content-Type: application/json" \
  -H "DD-API-KEY: {org_api_key}" \
  -H "DD-APPLICATION-KEY: {app_key}" \
  -d '{
    "resource_id": "*",
    "blocked_cidrs": ["1.2.3.0/24"],
    "mode": "enforced"
  }'
```

**Creates:** `api_key:*` policy (applies to ALL keys in org-123)

**Generated CEL expression:**
```javascript
!(cidr('1.2.3.0/24').containsIP(ip(request.source_ip)))
```

### Example 2: Key-Specific Block (Single API Key)

Block IPs for one specific API key:

```bash
curl -X POST http://localhost:8080/api/unstable/orgs/org-123/ip-policies \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "key-456",
    "blocked_cidrs": ["10.0.0.0/8"],
    "mode": "enforced"
  }'
```

**Creates:** `api_key:key-456` policy (applies only to key-456)

**Generated CEL expression:**
```javascript
!(cidr('10.0.0.0/8').containsIP(ip(request.source_ip)))
```

### Example 3: Org-Wide Allowlist (Corporate Network Only)

Only allow requests from corporate network (all API keys):

```bash
curl -X POST http://localhost:8080/api/unstable/orgs/org-123/ip-policies \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "*",
    "allowed_cidrs": [
      "10.0.0.0/8",
      "172.16.0.0/12"
    ],
    "mode": "enforced"
  }'
```

**Creates:** `api_key:*` policy

**Generated CEL expression:**
```javascript
(cidr('10.0.0.0/8').containsIP(ip(request.source_ip)) ||
 cidr('172.16.0.0/12').containsIP(ip(request.source_ip)))
```

### Example 4: Combined Allowlist + Blocklist

Allow corporate network but block specific problem subnet:

```bash
curl -X POST http://localhost:8080/api/unstable/orgs/org-123/ip-policies \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "*",
    "allowed_cidrs": ["10.0.0.0/8"],
    "blocked_cidrs": ["10.0.1.0/24"],
    "mode": "enforced"
  }'
```

**Logic**: Allow 10.0.0.0/8 EXCEPT 10.0.1.0/24 (blocked takes precedence)

**Generated CEL expression:**
```javascript
(cidr('10.0.0.0/8').containsIP(ip(request.source_ip))) &&
!(cidr('10.0.1.0/24').containsIP(ip(request.source_ip)))
```

### Example 5: Hierarchical - Org-Wide + Key-Specific

**Scenario:** Org blocks 192.168.0.0/16 for all keys, but key-789 has additional restrictions

**Step 1: Org-wide policy**
```bash
POST /api/unstable/orgs/org-123/ip-policies
{
  "resource_id": "*",
  "blocked_cidrs": ["192.168.0.0/16"],
  "mode": "enforced"
}
```
→ Creates `api_key:*` - blocks 192.168.0.0/16 for ALL keys

**Step 2: Key-specific additional block**
```bash
POST /api/unstable/orgs/org-123/ip-policies
{
  "resource_id": "key-789",
  "blocked_cidrs": ["172.16.0.0/12"],
  "mode": "enforced"
}
```
→ Creates `api_key:key-789` - blocks 172.16.0.0/12 for only key-789

**Result for key-789:** Both 192.168.0.0/16 (org) AND 172.16.0.0/12 (key) are blocked
**Result for other keys:** Only 192.168.0.0/16 (org) is blocked

## Policy Enforcement Modes

### Three Enforcement States

Each policy has a `mode` that controls how it's evaluated:

| Mode | Evaluates? | Blocks? | Use Case |
|------|-----------|---------|----------|
| **`disabled`** | ❌ No | ❌ No | Temporarily turn off policy without deleting |
| **`dry_run`** | ✅ Yes | ❌ No | Test policy, see what would be blocked |
| **`enforced`** | ✅ Yes | ✅ Yes | Full enforcement |

**Benefits:**

✅ **Clear state transitions** - disabled → dry_run → enforced
✅ **Temporary disable** - Turn off policy without losing configuration
✅ **Testing without risk** - Validate policies before enforcement
✅ **Gradual rollout** - Some policies enforced, others in testing
✅ **Full observability** - Logs and metrics for each mode

### How It Works

The `mode` is embedded in the RelationTuple's `object_id`:
- **Disabled**: `object_id = "expr-{uuid}-disabled"`
- **Dry run**: `object_id = "expr-{uuid}-dryrun"`
- **Enforced**: `object_id = "expr-{uuid}-enforced"`

No proto changes needed! The CEL evaluator parses the suffix to determine mode.

### Example: Create Policy in Dry Run Mode

```bash
curl -X POST http://localhost:8080/api/unstable/orgs/org-123/ip-policies \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "my-api-key-123",
    "blocked_cidrs": ["192.168.1.0/24"],
    "mode": "dry_run"
  }'
```

**What happens:**
1. Policy created with `principal_id = "ip-policy-dryrun"`
2. FRAMES notified → streams to all pods
3. CEL evaluator compiles it as a dry run policy
4. Requests matching 192.168.1.0/24 are evaluated but **NOT blocked**
5. Logs show: `[DRY_RUN] Would have BLOCKED by policy ip-policy-dryrun`
6. Metrics track: `policy_evaluations{mode="dry_run", would_block="true"}`

**Policy Lifecycle (disabled → dry_run → enforced):**
```bash
# Step 1: Create disabled policy
POST /api/unstable/orgs/org-123/ip-policies {"resource_id": "key-123", "blocked_cidrs": ["192.168.1.0/24"], "mode": "disabled"}

# Step 2: Test in dry run
PATCH /api/unstable/orgs/org-123/ip-policies/key-123 {"mode": "dry_run"}

# Step 3: Promote to enforcement
PATCH /api/unstable/orgs/org-123/ip-policies/key-123 {"mode": "enforced"}

# Step 4: Temporarily disable
PATCH /api/unstable/orgs/org-123/ip-policies/key-123 {"mode": "disabled"}
```

### Metrics by Mode

```
# Policy evaluations by mode and result
policy_evaluations_total{api_key="key-123", policy_id="expr-abc", mode="disabled"} 0
policy_evaluations_total{api_key="key-123", policy_id="expr-abc", mode="dry_run", would_block="true"} 42
policy_evaluations_total{api_key="key-123", policy_id="expr-abc", mode="dry_run", would_block="false"} 158
policy_evaluations_total{api_key="key-123", policy_id="expr-abc", mode="enforced", blocked="true"} 38
policy_evaluations_total{api_key="key-123", policy_id="expr-abc", mode="enforced", blocked="false"} 162

# Policy evaluation time by mode
policy_evaluation_duration_us{api_key="key-123", mode="dry_run"} 18
policy_evaluation_duration_us{api_key="key-123", mode="enforced"} 18
```

### Logs by Mode

```json
// Dry run mode
{"level": "info", "mode": "dry_run", "would_block": true, "reason": "[DRY_RUN] Would have BLOCKED"}

// Enforced mode (blocked)
{"level": "warn", "mode": "enforced", "blocked": true, "reason": "Blocked by policy"}

// Disabled mode: no logs (not evaluated)
```

## AuthN Sidecar Implementation

### CEL Evaluator

```go
package authcheck

import (
    "fmt"
    "sync"
    "time"
    "github.com/google/cel-go/cel"
    "k8s.io/apiserver/pkg/cel/library"
    "github.com/DataDog/dd-source/domains/context-platform/libs/go/libcontext"
)

type PolicyMode string

const (
    PolicyModeDisabled PolicyMode = "disabled"
    PolicyModeDryRun   PolicyMode = "dry_run"
    PolicyModeEnforced PolicyMode = "enforced"
)

type PolicyProgram struct {
    Program  cel.Program
    Mode     PolicyMode  // Per-policy enforcement mode
    PolicyID string      // For logging and metrics
}

type CELEvaluator struct {
    mu       sync.RWMutex
    env      *cel.Env
    policies map[string]*PolicyProgram  // Map of "<orgID>:<apiKeyUUID>" → compiled program
                                         // "123:*" = org-wide for org 123
                                         // "123:uuid-456" = key-specific for org 123, key uuid-456
    metrics  *Metrics
}

type RequestContext struct {
    SourceIP  string
    Country   string  // Future extension
    UserAgent string  // Future extension
}

func NewCELEvaluator() (*CELEvaluator, error) {
    // Create CEL environment with Kubernetes IP/CIDR library
    env, err := cel.NewEnv(
        // Define request context type
        cel.Variable("request", cel.MapType(cel.StringType, cel.AnyType)),

        // Add Kubernetes IP library (provides ip() function and methods)
        library.IP(),

        // Add Kubernetes CIDR library (provides cidr() function and containsIP() method)
        library.CIDR(),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create CEL environment: %w", err)
    }

    return &CELEvaluator{
        env:      env,
        programs: make(map[string]cel.Program),
    }, nil
}

// LoadPolicies loads RelationTuples from FRAMES and compiles CEL expressions
// Called on startup and when FRAMES sends policy updates.
// Compilation (~35μs per policy) happens once here, then compiled programs
// are cached for fast evaluation (~0.3μs per request with K8s library).
// Note: FRAMES contexts are keyed by (orgID, resourceType, resourceID)
// The authenticator-intake knows the orgID from EdgeAuthResult and loads
// the appropriate policies for that org from FRAMES at startup.
// Each org's policies are loaded separately and stored with orgID prefix.
func (e *CELEvaluator) LoadPolicies(orgID int32, tuples []*RelationTuple) error {
    e.mu.Lock()
    defer e.mu.Unlock()

    for _, tuple := range tuples {
        if tuple.SubjectType != "api_key" {
            continue
        }
        if tuple.Relation != "access_policy" {
            continue
        }

        // SubjectID can be:
        // - "*" for org-wide policies (applies to all keys in org)
        // - "uuid-123" for key-specific policies (API key UUID)
        subjectID := tuple.SubjectID
        expression := tuple.Condition

        // Parse mode from object_id
        // Format: "expr-{uuid}-{mode}" where mode is: disabled | dryrun | enforced
        mode := parsePolicyMode(tuple.ObjectID)

        // Compile CEL expression (~35μs - one-time cost)
        // This expensive operation happens once here, then the compiled
        // program is cached for millions of fast evaluations (~0.3μs each with K8s library)
        ast, issues := e.env.Compile(expression)
        if issues != nil && issues.Err() != nil {
            return fmt.Errorf("failed to compile expression for api_key:%s: %w", subjectID, issues.Err())
        }

        // Create executable program
        prg, err := e.env.Program(ast)
        if err != nil {
            return fmt.Errorf("failed to create program for api_key:%s: %w", subjectID, err)
        }

        // Store with orgID:subjectID key format
        // Examples: "123:*" (org-wide), "123:uuid-456" (key-specific)
        policyKey := fmt.Sprintf("%d:%s", orgID, subjectID)
        e.policies[policyKey] = &PolicyProgram{
            Program:  prg,
            Mode:     mode,
            PolicyID: tuple.ObjectID,
        }
    }

    return nil
}

// parsePolicyMode extracts mode from object_id
// Format: "expr-{uuid}-{mode}" → "disabled" | "dry_run" | "enforced"
func parsePolicyMode(objectID string) PolicyMode {
    if strings.HasSuffix(objectID, "-disabled") {
        return PolicyModeDisabled
    }
    if strings.HasSuffix(objectID, "-dryrun") {
        return PolicyModeDryRun
    }
    if strings.HasSuffix(objectID, "-enforced") {
        return PolicyModeEnforced
    }
    // Default to enforced if no suffix (backward compatibility)
    return PolicyModeEnforced
}

type AccessDecision struct {
    Allowed        bool
    Reason         string
    PolicyID       string
    PolicyScope    string        // "*" (org-wide) or specific key ID
    Mode           PolicyMode
    WouldBlock     bool          // For dry_run mode: would this have blocked?
    EvaluationTime time.Duration
}

// CheckAccess evaluates CEL expression for API key
// Checks both org-wide and key-specific policies
// Policy keys format: "<orgID>:<apiKeyUUID>"
//   - "123:*" = org-wide for org 123
//   - "123:uuid-456" = key-specific for org 123, key uuid-456
func (e *CELEvaluator) CheckAccess(orgID int32, apiKeyUUID string, ctx *RequestContext) (*AccessDecision, error) {
    e.mu.RLock()
    defer e.mu.RUnlock()

    startTime := time.Now()

    // Construct policy keys
    orgWideKey := fmt.Sprintf("%d:*", orgID)
    keySpecificKey := fmt.Sprintf("%d:%s", orgID, apiKeyUUID)

    // Check org-wide policy first (orgID:*)
    if orgPolicy, exists := e.policies[orgWideKey]; exists {
        decision, err := e.evaluatePolicy(orgPolicy, orgWideKey, ctx)
        if err != nil {
            return nil, err
        }
        if !decision.Allowed && decision.Mode == PolicyModeEnforced {
            // Org-wide policy blocked in enforcement mode
            decision.Reason = fmt.Sprintf("[ORG-WIDE] %s", decision.Reason)
            decision.PolicyScope = orgWideKey
            decision.EvaluationTime = time.Since(startTime)
            return decision, nil
        }
        // Track dry_run blocks even if allowed
        if decision.WouldBlock && decision.Mode == PolicyModeDryRun {
            e.metrics.RecordEvaluation(orgWideKey, orgPolicy.PolicyID, orgPolicy.Mode, true, false)
        }
    }

    // Check API-key-specific policy (orgID:apiKeyUUID)
    keyPolicy, exists := e.policies[keySpecificKey]
    if !exists {
        // No key-specific policy, and org-wide passed (or doesn't exist) = allow
        return &AccessDecision{
            Allowed:        true,
            EvaluationTime: time.Since(startTime),
        }, nil
    }

    decision, err := e.evaluatePolicy(keyPolicy, keySpecificKey, ctx)
    if err != nil {
        return nil, err
    }

    decision.Reason = fmt.Sprintf("[API_KEY] %s", decision.Reason)
    decision.PolicyScope = keySpecificKey
    decision.EvaluationTime = time.Since(startTime)
    return decision, nil
}

// evaluatePolicy evaluates a single policy
func (e *CELEvaluator) evaluatePolicy(policy *PolicyProgram, subjectID string, ctx *RequestContext) (*AccessDecision, error) {
    decision := &AccessDecision{
        PolicyID: policy.PolicyID,
        Mode:     policy.Mode,
    }

    // Skip evaluation if policy is disabled
    if policy.Mode == PolicyModeDisabled {
        decision.Allowed = true
        decision.Reason = "Policy disabled"
        return decision, nil
    }

    // Build evaluation context
    evalCtx := map[string]interface{}{
        "request": map[string]interface{}{
            "source_ip":  ctx.SourceIP,
            "country":    ctx.Country,
            "user_agent": ctx.UserAgent,
        },
    }

    // Evaluate CEL expression
    out, _, err := policy.Program.Eval(evalCtx)
    if err != nil {
        decision.Allowed = true  // Fail open on error
        decision.Reason = "CEL evaluation error"
        return decision, err
    }

    // CEL expression returns true = ALLOW, false = DENY
    wouldAllow, ok := out.Value().(bool)
    if !ok {
        decision.Allowed = true
        decision.Reason = "CEL returned non-boolean"
        return decision, fmt.Errorf("unexpected return type")
    }

    // Handle different modes
    switch policy.Mode {
    case PolicyModeDryRun:
        // Dry run: always allow but log what would have happened
        decision.Allowed = true           // Always allow in dry run
        decision.WouldBlock = !wouldAllow // Track what would have happened
        if !wouldAllow {
            decision.Reason = fmt.Sprintf("[DRY_RUN] Would have BLOCKED by policy %s", policy.PolicyID)
        } else {
            decision.Reason = fmt.Sprintf("[DRY_RUN] Would have ALLOWED by policy %s", policy.PolicyID)
        }
        return decision, nil

    case PolicyModeEnforced:
        // Enforced: evaluate and block if needed
        if !wouldAllow {
            decision.Allowed = false
            decision.Reason = fmt.Sprintf("Blocked by policy %s", policy.PolicyID)
        } else {
            decision.Allowed = true
        }
        return decision, nil

    default:
        // Should not reach here (disabled handled above)
        decision.Allowed = true
        return decision, nil
    }
}

// AddPolicy adds or updates a single policy (for incremental FRAMES updates)
// Only compiles the changed policy (~35μs), not the entire set.
// This keeps the compilation cost minimal during updates.
func (e *CELEvaluator) AddPolicy(orgID int32, tuple *RelationTuple) error {
    e.mu.Lock()
    defer e.mu.Unlock()

    if tuple.SubjectType != "api_key" {
        return nil
    }

    subjectID := tuple.SubjectID  // Can be "*" or specific API key UUID
    expression := tuple.Condition

    // Parse mode from object_id
    mode := parsePolicyMode(tuple.ObjectID)

    // Compile CEL expression (~35μs for this one policy only)
    ast, issues := e.env.Compile(expression)
    if issues != nil && issues.Err() != nil {
        return issues.Err()
    }

    prg, err := e.env.Program(ast)
    if err != nil {
        return err
    }

    // Update cache with newly compiled program using orgID:subjectID key
    policyKey := fmt.Sprintf("%d:%s", orgID, subjectID)
    e.policies[policyKey] = &PolicyProgram{
        Program:  prg,
        Mode:     mode,
        PolicyID: tuple.ObjectID,
    }
    return nil
}
```

### Integration in AuthN Handler

```go
func (s *AuthNSidecar) ValidateIntakeRequest(req *IntakeRequest) error {
    // Step 1: Authenticate API key (existing flow)
    authResult := s.credentialResolver.Resolve(ctx, req.APIKey)
    if authResult.Status != model.AuthenticatedAPIKey {
        return &UnauthorizedError{StatusCode: 401}
    }

    // Extract org ID and API key UUID from auth result (already available!)
    orgID := authResult.OrgID       // ✅ From EdgeAuthResult
    apiKeyUUID := authResult.UUID   // ✅ API key UUID from EdgeAuthResult

    // Step 2: Extract request context
    ctx := &RequestContext{
        SourceIP:  req.ClientIP,
        Country:   req.GeoIP.Country,    // Future extension
        UserAgent: req.Headers.UserAgent, // Future extension
    }

    // Step 3: Evaluate CEL policy (checks both org-wide and key-specific)
    // Policy keys are in format: "<orgID>:<apiKeyUUID>"
    // - orgID:*           → org-wide policy (applies to all keys in org)
    // - orgID:apiKeyUUID  → key-specific policy (applies only to this key)
    decision, err := s.celEvaluator.CheckAccess(orgID, apiKeyUUID, ctx)

    if err != nil {
        // Log error, fail open for availability
        s.metrics.IncrementPolicyEvalErrors()
        log.Warn("CEL policy evaluation error",
            log.Int32("org_id", orgID),
            log.String("api_key_uuid", apiKeyUUID),
            log.String("ip", ctx.SourceIP),
            log.ErrorField(err))
        return nil // Fail open
    }

    // Log evaluation results based on mode
    if decision.Mode == PolicyModeDryRun {
        log.Info("Policy evaluation",
            log.Int32("org_id", orgID),
            log.String("api_key_uuid", apiKeyUUID),
            log.String("policy_id", decision.PolicyID),
            log.String("mode", string(decision.Mode)),
            log.String("ip", ctx.SourceIP),
            log.Bool("would_block", decision.WouldBlock),
            log.String("reason", decision.Reason),
            log.Duration("eval_time_us", decision.EvaluationTime))
    } else if decision.Mode == PolicyModeDisabled {
        // Don't log disabled policies (no evaluation)
    }

    if !decision.Allowed {
        s.metrics.IncrementBlockedRequests(orgID, apiKeyUUID, ctx.SourceIP)
        log.Info("Request blocked by policy",
            log.Int32("org_id", orgID),
            log.String("api_key_uuid", apiKeyUUID),
            log.String("policy_id", decision.PolicyID),
            log.String("ip", ctx.SourceIP),
            log.String("reason", decision.Reason),
            log.Duration("eval_time_us", decision.EvaluationTime))
        return &ForbiddenError{
            StatusCode: 403,
            Message:    decision.Reason,
            IP:         ctx.SourceIP,
        }
    }

    return nil
}
```

**Performance (Benchmarked with K8s library):**
- Map lookup: ~0.05μs
- CEL evaluation: **~0.3μs** (cached compiled program with K8s library)
- Context building: ~0.05μs
- **Total: ~0.4μs per request** (500x under 200μs budget!)
- **One-time cost:** CEL compilation ~35μs per policy (only on load/update)

**Flexibility:**
- ✅ Add country blocking: just change CEL expression
- ✅ Add time-based rules: just change CEL expression
- ✅ Add user-agent blocking: just change CEL expression
- ✅ **Zero code changes needed!**

## Trade-offs vs Other Approaches

| Aspect | CEL (K8s library) | Hand-Rolled | SpiceDB |
|--------|-----|-------------|---------|
| **Code complexity** | ✅ 200 lines | 200 lines | 800 lines |
| **Performance** | ✅ **0.4μs** (cached) | 0.5μs | 40μs |
| **Compilation** | 35μs one-time | N/A | N/A |
| **Dependencies** | cel-go + k8s lib | ✅ stdlib only | SpiceDB libs |
| **Memory** | 80MB | ✅ 50MB | 120MB |
| **Learning curve** | Medium | ✅ None | High |
| **Flexibility** | ✅ Unlimited attributes | Limited to IP | ✅ Relationships |
| **No rewrites** | ✅ Add attributes via expressions | ❌ Code changes needed | N/A (different use case) |
| **IP blocking** | ✅ Perfect | ✅ Perfect | Overkill |
| **Implementation time** | ✅ 1.5 days | 1 day | 2-3 days |
| **Future extension** | ✅ Trivial | ❌ Requires migration | ✅ Different use case |

**Recommendation**: Use CEL with Kubernetes library for Innovation Week - extremely fast (0.4μs), battle-tested, flexible, no future rewrites needed

**Key Insight from Benchmarks:** CEL with K8s library evaluation is extremely fast (~0.3μs). The compilation cost (~35μs) is paid once on startup/update, then cached programs are reused for millions of requests.

## Future Extension Benefits (CEL Advantage)

**Week 1+ - Add Product Scoping (Scoped API Keys):**
```javascript
// Just add product field to request context - zero code changes to evaluator!
request.product == 'logs'  // Only allow logs
// or
request.product in ['logs', 'metrics']  // Allow logs and metrics
// or combine with IP (using K8s library syntax)
request.product == 'logs' && cidr('10.0.0.0/8').containsIP(ip(request.source_ip))
```

**Week 2 - Add Country Blocking:**
```javascript
// Just change the expression - zero code changes! (K8s library syntax)
!(cidr('1.2.3.0/24').containsIP(ip(request.source_ip)) || request.country == 'CN')
```

**Week 3 - Add Time-Based Rules:**
```javascript
// Still no code changes! (K8s library syntax)
!cidr('1.2.3.0/24').containsIP(ip(request.source_ip)) &&
timestamp(request.timestamp).getHours() >= 9
```

**Week 4 - Complex Combination:**
```javascript
// All attributes work together seamlessly (K8s library syntax)
(request.country == 'US' || cidr('10.0.0.0/8').containsIP(ip(request.source_ip))) &&
!request.user_agent.contains('bot')
```

**This is why CEL wins:** No rewrites, no migrations, just update expressions!
