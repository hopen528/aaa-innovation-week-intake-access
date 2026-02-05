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

### Day 2: Data Plane Implementation ✅ COMPLETED

**Goal:** Build policy reader, CEL evaluator, export as standalone package

**PR:** https://github.com/DataDog/dd-source/pull/351115

#### 2.1 Policy Evaluator Package (dd-source/domains/aaa/apps/zoltron/policyeval)

Implemented as a standalone Go package in dd-source that can be imported by dd-go.

```go
// Package: go.ddbuild.io/dd-source/domains/aaa/apps/zoltron/policyeval

type PolicyEvaluator struct {
    env          *cel.Env                    // CEL environment with K8s IP/CIDR libs
    cache        map[string]*CachedPolicy    // Hash-based cache: "orgUUID:resourceID" → compiled
    policyReader frames.Reader               // FRAMES reader for restriction policies
}

// NewPolicyEvaluator creates evaluator with CEL environment and FRAMES reader
func NewPolicyEvaluator(contextRootPath string) (*PolicyEvaluator, error)

// WaitReady blocks until FRAMES snapshot is loaded
func (e *PolicyEvaluator) WaitReady(ctx context.Context, timeout time.Duration) error

// CheckAccess evaluates both org-wide and key-specific policies
// Both must pass - org-wide is baseline, key-specific adds restrictions
func (e *PolicyEvaluator) CheckAccess(ctx context.Context, orgUUID uuid.UUID, apiKeyUUID string, reqCtx *RequestContext) (*AccessDecision, error)
```

#### 2.2 Policy Evaluation Logic

```go
func (e *PolicyEvaluator) CheckAccess(...) (*AccessDecision, error) {
    // 1. Check org-wide policy first (orgUUID:*)
    orgWideDecision, err := e.evaluatePolicy(ctx, orgUUID, "*", reqCtx)
    
    // 2. If org-wide blocks (enforced mode), return immediately
    if orgWideDecision != nil && !orgWideDecision.Allowed && orgWideDecision.Mode == PolicyModeEnforced {
        return orgWideDecision, nil
    }
    
    // 3. Check key-specific policy (orgUUID:apiKeyUUID)
    keyDecision, err := e.evaluatePolicy(ctx, orgUUID, apiKeyUUID, reqCtx)
    if keyDecision != nil {
        return keyDecision, nil
    }
    
    // 4. Fall back to org-wide, or allow if no policies
    if orgWideDecision != nil {
        return orgWideDecision, nil
    }
    return &AccessDecision{Allowed: true, Reason: "no restriction policies configured"}, nil
}
```

**Key behavior:** Both policies must pass. Org-wide restrictions cannot be bypassed by key-specific policies.

#### 2.3 CEL Expression Parsing

Reads from FRAMES proto and compiles CEL:

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
                mode := parseModeFromSubjectID(subject.GetSubjectId())  // "ip-policy-{mode}"
                
                // Compile with K8s CEL libraries
                ast, _ := e.env.Compile(celExpr)
                program, _ := e.env.Program(ast)
                return &CachedPolicy{Program: program, Mode: mode}, nil
            }
        }
    }
}
```

#### 2.4 Cache Strategy

- SHA-256 hash of serialized proto for cache invalidation
- If hash matches → use cached program (~0.3μs)
- If hash differs → recompile (~35μs one-time cost)

#### 2.5 Types

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

#### 2.6 File Structure

```
dd-source/domains/aaa/apps/zoltron/
├── policyeval/
│   ├── BUILD.bazel           # dd_go_package for export
│   ├── evaluator.go          # PolicyEvaluator implementation
│   ├── evaluator_test.go     # Comprehensive tests
│   └── types.go              # Public types
└── internal/frames/
    ├── codec.go              # RestrictionPolicyCodec (existing)
    └── proto/restriction_policy.proto
```

#### 2.7 Integration in dd-go (TODO)

```go
import "go.ddbuild.io/dd-source/domains/aaa/apps/zoltron/policyeval"

func (s *AuthNSidecar) ValidateIntakeRequest(req *IntakeRequest) error {
    authResult := s.credentialResolver.Resolve(ctx, req.APIKey)
    orgUUID, _ := uuid.Parse(authResult.OrgUUID)
    
    decision, err := s.policyEvaluator.CheckAccess(
        ctx,
        orgUUID,
        authResult.UUID,
        &policyeval.RequestContext{SourceIP: req.ClientIP},
    )
    
    if err != nil {
        // Fail open
        return nil
    }
    if !decision.Allowed {
        return &ForbiddenError{StatusCode: 403, Message: decision.Reason}
    }
    return nil
}
```

---

### Day 3: UI Polish & Test Endpoint ✅ COMPLETED

- [x] Fixed TypeScript/DRUIDS component issues
- [x] Integrated test IP endpoint (`POST /ip-policies/test`)
- [x] Add/Edit modals use local testing, read-only view uses API testing
- [x] UX polish (smaller modals, loading states)

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
