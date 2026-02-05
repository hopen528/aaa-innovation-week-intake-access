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

#### 2.1 Core Components

**PolicyEvaluator Package (`policyeval/`):**
- CEL environment with Kubernetes IP/CIDR libraries for expression evaluation
- Hash-based caching of compiled CEL programs for performance
- FRAMES integration via authdatastore for reading restriction policies
- Supports org-wide (`*`) and key-specific policies with proper precedence

**Key Design:** Key-specific policies completely override org-wide policies when present, simplifying the mental model.

#### 2.2 Integration Points

**Authorization Check (`authzcheck/check.go`):**
- Integrated after API key authentication succeeds
- Extracts source IP from `x-client-ip` header (set by Envoy)
- Evaluates policies with fail-open behavior for availability
- Returns 403 Forbidden when policy denies access

**Service Initialization:**
- PolicyEvaluator initialized on startup with FRAMES reader
- Waits for FRAMES snapshot in background (30s timeout)
- Graceful degradation if evaluator fails to initialize

#### 2.3 File Structure

```
dd-go/
├── apps/authenticator-intake/
│   ├── policyeval/           # CEL policy evaluator
│   ├── authzcheck/           # Integration point
│   └── shadow/               # Shadow mode support
├── pkg/authdatastore/        # FRAMES reader for policies
└── model/                    # Added OrgUUID field
```

#### 2.4 Key Implementation Decisions

**1. Temporary Self-Containment in dd-go:**
- Innovation Week approach: evaluator directly in dd-go to avoid unmerged package dependency complexity
- Production approach: evaluator will move to dd-source as reusable package
- Cherry-picked FRAMES reader from PR #220700 for immediate use

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
