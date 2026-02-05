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

**Goal:** Integrate CEL policy evaluator into authenticator-intake service

**Implementation approach:** Temporary self-contained implementation in dd-go for Innovation Week demo. Due to the complexity of consuming unmerged dd-source Go packages in dd-go (see [internal guide](https://datadoghq.atlassian.net/wiki/spaces/~712020bcc838af278c4c90bc8053559068faef/pages/6126764720/Consuming+dd-source+Go+packages+in+dd-go)), the evaluator is temporarily implemented directly in dd-go. For production deployment, the evaluator will be moved back to dd-source as a reusable package.

**PRs:**
- dd-go: https://github.com/DataDog/dd-go/pull/220294 (DRAFT - Innovation Week demo, will remain draft)
- dd-source: https://github.com/DataDog/dd-source/pull/351115 (Future home of evaluator package for production)

#### 2.1 PolicyEvaluator Package Design

The core evaluator uses CEL with Kubernetes libraries for IP/CIDR matching:

```go
// Package: go.ddbuild.io/dd-source/domains/aaa/apps/zoltron/policyeval

type PolicyEvaluator struct {
    env          *cel.Env         // CEL environment with K8s IP/CIDR libs
    cache        map[string]*CachedPolicy  // Hash-based cache by "orgUUID:resourceID"
    cacheMu      sync.RWMutex
    policyReader frames.Reader    // FRAMES reader for restriction policies
}

// CheckAccess evaluates policies with key-specific taking precedence over org-wide
func (e *PolicyEvaluator) CheckAccess(ctx context.Context, orgUUID uuid.UUID, apiKeyUUID string, reqCtx *RequestContext) (*AccessDecision, error) {
    // 1. Check key-specific policy first (takes precedence)
    keyDecision, err := e.evaluatePolicy(ctx, orgUUID, apiKeyUUID, reqCtx)
    if keyDecision != nil {
        return keyDecision, nil  // Key-specific overrides org-wide
    }

    // 2. Fall back to org-wide policy
    orgWideDecision, err := e.evaluatePolicy(ctx, orgUUID, "*", reqCtx)
    if orgWideDecision != nil {
        return orgWideDecision, nil
    }

    // 3. No policies - allow by default
    return &AccessDecision{Allowed: true, Reason: "no restriction policies"}, nil
}
```

**Key Design Decision:** Key-specific policies completely override org-wide policies when present, not additive. This simplifies the mental model: "most specific wins".

#### 2.2 Integration with Authenticator-Intake

Policy evaluation happens **after successful authentication**, using the resolved org and API key UUIDs:

```go
// authzcheck/check.go
func Check(ctx context.Context, req *auth.CheckRequest, resolver *resolver.CredentialResolver,
           policyEvaluator *policyeval.PolicyEvaluator) (*auth.CheckResponse, error) {

    // 1. Extract and authenticate API key
    apiKey, err := ExtractAPIKey(ctx, req, u)
    info := resolver.Resolve(ctx, apiKey)  // Returns OrgUUID, UUID, Status

    // 2. Policy evaluation ONLY after successful authentication
    if info.Status == model.AuthenticatedAPIKey && policyEvaluator != nil && info.OrgUUID != "" {
        orgUUID, _ := uuid.Parse(info.OrgUUID)

        // Build request context with IP from x-client-ip header
        reqCtx := &policyeval.RequestContext{
            SourceIP: httpReq.GetHeaders()["x-client-ip"],
            Product:  product.String(),
            Path:     path,
        }

        // Evaluate with org and key UUIDs from authentication
        decision, err := policyEvaluator.CheckAccess(ctx, orgUUID, info.UUID, reqCtx)
        if err != nil {
            // FAIL OPEN - log error but allow request
            log.Error("Policy evaluation error", err)
        } else if decision != nil && !decision.Allowed {
            // Policy blocks - return 403
            info.Status = model.UnauthorizedAPIKey
            return generateResponse(&info, envoy_type.StatusCode_Forbidden)
        }
    }

    // Continue with normal response
}
```

**Critical Design Points:**
- Policy evaluation **requires** successful authentication first (needs org/key UUIDs)
- Source IP extracted from `x-client-ip` header (set by Envoy)
- **Fail-open** on errors to maintain availability
- Returns same 403 as auth failures to avoid information leakage

#### 2.3 CEL Expression and Policy Modes

Policies stored in FRAMES use Kubernetes CEL syntax and encode mode in `principal_id`:

```go
// From FRAMES proto
Subject {
    SubjectType: "cel_expression"
    SubjectId:   "ip-policy-enforced"  // Mode encoded in ID
    Condition:   "cidr('192.168.1.0/24').containsIP(ip(request.source_ip))"
}

// Policy modes parsed from SubjectId
type PolicyMode string
const (
    PolicyModeDisabled PolicyMode = "disabled"  // Not evaluated
    PolicyModeDryRun   PolicyMode = "dry_run"   // Log only, don't block
    PolicyModeEnforced PolicyMode = "enforced"  // Actually block requests
)

// Dry-run handling
if cached.Mode == PolicyModeDryRun {
    decision.WouldBlock = !allowed
    decision.Allowed = true  // Always allow in dry-run
    decision.Reason = "dry-run: would have blocked"
}
```

**CEL Examples:**
```javascript
// IP allowlist
cidr('192.168.1.0/24').containsIP(ip(request.source_ip))

// IP blocklist
!cidr('10.0.0.0/8').containsIP(ip(request.source_ip))

// Multiple CIDRs
cidr('192.168.1.0/24').containsIP(ip(request.source_ip)) ||
cidr('10.0.0.0/8').containsIP(ip(request.source_ip))

// Future: product-specific policies
request.product == "logs" && cidr('192.168.1.0/24').containsIP(ip(request.source_ip))
```

#### 2.4 Caching and Performance

Hash-based cache invalidation ensures ~0.3μs evaluation:

```go
// Cache key: "orgUUID:resourceID" (e.g., "550e8400-e29b-41d4-a716-446655440000:*")
cacheKey := fmt.Sprintf("%s:%s", orgUUID.String(), resourceID)

// SHA-256 hash of serialized proto for invalidation
policyHash := sha256.Sum256(serialized)

if exists && cached.Hash == policyHash {
    // Cache hit - use cached program (~0.3μs)
} else {
    // Cache miss - compile CEL (~35μs one-time)
}
```

#### 2.5 Key Implementation Decisions

**1. Temporary Self-Containment in dd-go:**
- Innovation Week approach: evaluator directly in dd-go to avoid unmerged package dependency complexity
- Production approach: evaluator will move to dd-source as reusable package
- Cherry-picked FRAMES reader from PR #220700 for immediate use

**2. Policy Precedence Model:**
- Key-specific policies completely override org-wide when present
- Simplifies mental model: "most specific policy wins"
- Org-wide acts as default when no key-specific policy exists

**3. Fail-Open Behavior (Production-Ready):**
- **Non-blocking initialization**: Service starts even if PolicyEvaluator fails to create or FRAMES is unavailable
- **Graceful degradation**: Runs without policy evaluation if `policyEvaluator == nil`
- **Error handling at multiple levels**:
  - Initialization failures → Log warning, set evaluator to nil, continue service
  - FRAMES readiness timeout → Log error in background goroutine, service continues
  - Policy evaluation errors → Log error, allow request (fail-open)
  - CEL compilation/evaluation failures → Return `Allowed: true` with error reason
  - Invalid CEL results → Return `Allowed: true` with diagnostic reason
- **Comprehensive logging**: All failures logged for monitoring and alerting
- **No single point of failure**: Prioritizes availability over security enforcement

**4. CEL Syntax:**
- Uses Kubernetes library syntax: `cidr('192.168.1.0/24').containsIP(ip(request.source_ip))`
- Consistent with industry standards
- Supports complex expressions with AND/OR logic

**5. Caching Strategy:**
- SHA-256 hash-based cache invalidation
- Compiled programs cached indefinitely until policy changes
- ~0.3μs cached evaluation vs ~35μs compilation

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
