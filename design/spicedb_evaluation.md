# SpiceDB Evaluation for Intake Policy System

**Date:** 2026-01-30
**Author:** Haopeng Liu
**Purpose:** Evaluate SpiceDB as an alternative to custom policy implementation for intake ingestion policies

---

## Executive Summary

**Recommendation:** **Hybrid Approach** - Use custom condition evaluator for ABAC (Attribute-Based Access Control) with optional SpiceDB integration for ReBAC (Relationship-Based Access Control) in the future.

**Key Finding:** SpiceDB excels at relationship-based authorization but struggles with attribute-based conditions (IP ranges, time restrictions, complex boolean logic) that are core to intake policies.

---

## What is SpiceDB?

SpiceDB is an open-source, Google Zanzibar-inspired authorization database that:
- Stores and evaluates **relationships** between subjects and resources
- Provides low-latency permission checks at scale
- Uses a schema language to define resources and permissions
- Supports distributed, horizontally-scalable deployments
- Offers production-ready infrastructure with observability

**Example SpiceDB Use Case:**
```
Can user:alice edit document:123?
Can team:platform view logs for org:456?
Does user:bob have admin permission on project:789?
```

---

## Our Intake Policy Requirements

### Core Requirements
1. **IP Allowlist**: Allow/deny based on client IP address or CIDR range
2. **API Key Scoping**: Restrict which API keys can access which products
3. **Product Access Control**: Control access to LOGS, METRICS, APM
4. **Complex Conditions**: Support boolean logic (AND, OR, NOT)
5. **Dynamic Attributes**: Check request attributes (IP, key UUID, timestamp)
6. **High Performance**: Low-latency evaluation for every intake request
7. **Flexible Policies**: Easy to add new conditions without schema changes

### Example Policies
```
"Allow LOGS access if IP in [10.0.1.100, 10.0.1.101, 10.0.1.102]"
"Allow API key xyz to access LOGS AND METRICS but not APM"
"Allow requests from CIDR 10.0.0.0/16 to access all products"
"Allow API key abc only during business hours (9am-5pm UTC)"
```

---

## SpiceDB Fit Analysis

### ✅ What SpiceDB Does Well

1. **Relationship-Based Authorization**
   - "API key xyz has access permission on product LOGS"
   - "Team platform can view resources in org 123"
   - "User alice is member of team backend"

2. **Complex Permission Hierarchies**
   - Transitive permissions (user → team → org → resource)
   - Permission inheritance
   - Group membership

3. **Production-Ready Infrastructure**
   - Battle-tested at scale
   - High availability
   - Observability built-in
   - Active development and community

### ❌ What SpiceDB Struggles With

1. **Attribute-Based Conditions**
   - **IP CIDR Matching**: No built-in support for "IP in CIDR range"
   - **Time-Based Conditions**: Can't express "only during 9am-5pm"
   - **Complex Boolean Logic**: Limited condition expression capabilities
   - **Dynamic Attributes**: Must store relationships in advance

2. **Performance for ABAC**
   - Would need to create relationships for every IP address (impractical)
   - Condition evaluation happens outside SpiceDB
   - Extra network hop for every authorization check

3. **Operational Overhead**
   - Additional service to deploy and manage
   - Separate database to backup and scale
   - Team needs to learn SpiceDB schema language
   - Debugging permission checks requires SpiceDB expertise

---

## Option 1: Pure SpiceDB Approach

### Architecture

```
Request → Intake Service → SpiceDB → Decision
                ↓
         Condition Check (custom)
                ↓
         Final Decision
```

### SpiceDB Schema Example

```zed
definition organization {
    relation member: user | team
}

definition apikey {
    relation org: organization
    relation can_access_logs: apikey
    relation can_access_metrics: apikey
    relation can_access_apm: apikey
}

definition product {
    relation org: organization
    permission access = org->member
}

definition logs_product {
    relation restricted_keys: apikey
    permission access = restricted_keys
}
```

### Limitations

1. **IP Allowlist Problem**
   ```
   Cannot express: "Allow if IP in [10.0.1.100, 10.0.1.101]"

   Would need: Pre-compute every IP and store as relationship
   → Impractical for CIDR ranges (millions of IPs)
   → Must check IP conditions in application code anyway
   ```

2. **Complex Conditions**
   ```
   Cannot express: "key == 'xxx' AND ipInRange(ip, '10.0.0.0/16') AND hour >= 9"

   Would need: Application-level condition evaluation PLUS SpiceDB check
   → Defeats the purpose of using SpiceDB
   ```

3. **Performance**
   ```
   Every request: Application → SpiceDB gRPC call → Response
   Latency: +5-10ms per authorization check
   Throughput: Limited by SpiceDB capacity
   ```

### Verdict
**❌ Not Recommended** - SpiceDB cannot handle attribute-based conditions that are core to intake policies.

---

## Option 2: Hybrid Approach (SpiceDB + Custom Conditions)

### Architecture

```
Request → Intake Service
            ↓
    ┌───────┴────────┐
    ↓                ↓
SpiceDB          Condition
(ReBAC)         Evaluator
(relationships)    (ABAC)
    ↓                ↓
    └───────┬────────┘
            ↓
     Final Decision
```

### When to Use Each

**SpiceDB** (for relationships):
- Team membership: "Is user Alice in team Platform?"
- Organizational permissions: "Can team Platform access org resources?"
- Role-based access: "Does user Bob have admin role?"

**Custom Condition Evaluator** (for attributes):
- IP allowlists: `ipInRange(request.ip, "10.0.0.0/16")`
- API key scoping: `request.key_uuid == "xxx"`
- Time restrictions: `request.hour >= 9 && request.hour < 17`
- Product matching: `request.product in ["LOGS", "METRICS"]`

### Example Policy Evaluation

```json
{
  "resource_type": "logs",
  "principal": "team:platform",
  "relation": "ALLOW",
  "condition": "request.key_uuid == 'xxx' && ipInRange(request.ip, '10.0.0.0/8')"
}
```

**Evaluation Flow:**
1. **SpiceDB Check**: "Is the request from team:platform?" → YES
2. **Condition Check**: "Does request match condition?" → YES
3. **Result**: ALLOW

### Benefits
- ✅ Use SpiceDB for what it's good at (relationships)
- ✅ Custom evaluator for attributes and conditions
- ✅ Future-proof for team/user-based permissions

### Drawbacks
- ❌ Two systems to maintain (SpiceDB + condition evaluator)
- ❌ More complex architecture
- ❌ SpiceDB is overkill for current needs (no team/user permissions yet)

### Verdict
**⚠️ Future Option** - Good if we need team/user permissions, but overkill for initial intake policies.

---

## Option 3: Custom Implementation (Recommended)

### Architecture

```
Request → Intake Service → Policy Evaluator → Decision
                              ↓
                      (Read from DB/Cache)
                              ↓
                       Condition Evaluator
                       (using CEL or expr)
```

### Implementation Plan

#### Phase 1: Core Policy Engine (Week 1-2)

**Components:**
1. **Policy Storage** (PostgreSQL)
   ```sql
   CREATE TABLE policy_context (
       uuid UUID PRIMARY KEY,
       org_id BIGINT NOT NULL,
       policy JSONB NOT NULL,
       modified_at TIMESTAMP NOT NULL
   );
   ```

2. **Policy Cache** (In-memory with TTL)
   - Cache policies per org_id
   - Invalidate on policy updates
   - Reduce DB queries

3. **Condition Evaluator** (using cel-go)
   ```go
   import "github.com/google/cel-go/cel"

   func evaluateCondition(condition string, request map[string]interface{}) (bool, error) {
       env, _ := cel.NewEnv(
           cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
       )
       ast, _ := env.Compile(condition)
       prg, _ := env.Program(ast)
       result, _ := prg.Eval(map[string]interface{}{
           "request": request,
       })
       return result.Value().(bool), nil
   }
   ```

4. **Policy Evaluator**
   ```go
   func EvaluatePolicy(policy *PolicyContext, request *Request) (Action, error) {
       // Iterate through bindings (first match wins)
       for _, binding := range policy.Bindings {
           if matchesResourceType(binding.ResourceType, request.ResourceType) {
               if matchesPrincipal(binding.Principal, request) {
                   if evaluateCondition(binding.Condition, requestToMap(request)) {
                       return binding.Relation, nil
                   }
               }
           }
       }
       return policy.DefaultAction, nil
   }
   ```

#### Phase 2: Integration with Intake (Week 3)

1. **Intercept Intake Requests**
   ```go
   func (h *IntakeHandler) Handle(w http.ResponseWriter, r *http.Request) {
       request := &PolicyRequest{
           OrgID:      extractOrgID(r),
           IP:         r.RemoteAddr,
           KeyUUID:    extractAPIKey(r),
           Product:    extractProduct(r),
           Route:      r.URL.Path,
       }

       decision, err := h.policyEngine.Evaluate(request)
       if err != nil || decision == DENY {
           http.Error(w, "Access Denied", http.StatusForbidden)
           return
       }

       // Continue with intake processing
       h.processIntake(w, r)
   }
   ```

2. **Performance Optimization**
   - Cache policy evaluation results (short TTL: 1-5 seconds)
   - Use read-through cache for policies
   - Monitor evaluation latency

#### Phase 3: API and UI (Week 4)

1. **Policy Management API**
   ```
   POST   /api/v1/policies          Create policy
   GET    /api/v1/policies          List policies
   GET    /api/v1/policies/:uuid    Get policy
   PUT    /api/v1/policies/:uuid    Update policy
   DELETE /api/v1/policies/:uuid    Delete policy
   POST   /api/v1/policies/:uuid/test  Test policy with sample request
   ```

2. **Policy Editor UI**
   - JSON editor with validation
   - Condition builder (visual + text)
   - Test panel to simulate requests
   - Audit log of policy changes

#### Phase 4: Observability (Week 5)

1. **Metrics**
   ```
   policy_evaluations_total{org_id, decision, resource_type}
   policy_evaluation_duration_seconds{org_id}
   policy_cache_hit_rate{org_id}
   policy_condition_errors_total{org_id, condition}
   ```

2. **Logging**
   - Log every DENY decision with context
   - Log policy evaluation errors
   - Dry-run mode logs (what would have happened)

3. **Alerting**
   - High rate of DENY decisions
   - Policy evaluation errors
   - Cache eviction rate anomalies

---

## Cost-Benefit Comparison

| Aspect | Pure SpiceDB | Hybrid | Custom Implementation |
|--------|--------------|--------|----------------------|
| **Development Time** | 4-6 weeks | 6-8 weeks | 4-5 weeks |
| **Operational Complexity** | High (new service) | Very High (two systems) | Medium (in-process) |
| **Performance** | +5-10ms latency | +5-10ms + eval | <1ms in-process |
| **Cost** | $500-2000/mo (managed) | $500-2000/mo + dev | $0 (just compute) |
| **Flexibility** | Limited (ReBAC only) | High | Very High |
| **ABAC Support** | Poor | Good | Excellent |
| **Team Learning Curve** | Steep (new concepts) | Steeper (two systems) | Moderate (CEL) |
| **Future: Team Permissions** | Excellent | Excellent | Good (need to build) |
| **Maintenance** | Low (managed) or High (self-hosted) | Very High | Medium |

---

## Recommended Implementation Plan

### Phase 1: MVP (2 weeks)
**Goal:** Basic policy evaluation for IP allowlists and API key scoping

1. Implement PolicyContext proto with Binding messages
2. Create PostgreSQL table for policies
3. Implement condition evaluator using cel-go
4. Build policy evaluation engine
5. Add integration tests

**Deliverables:**
- Policy storage and retrieval
- Condition evaluation (IP ranges, API keys)
- First-match-wins evaluation logic
- Unit tests

### Phase 2: Production Integration (2 weeks)
**Goal:** Deploy to staging and validate

1. Integrate with intake service
2. Add in-memory caching
3. Implement DRY_RUN mode
4. Add comprehensive logging and metrics
5. Performance testing

**Deliverables:**
- Intake service integration
- Performance <1ms for cached policies
- Dry-run testing in staging
- Observability dashboard

### Phase 3: Management API (2 weeks)
**Goal:** Self-service policy management

1. Build gRPC API for CRUD operations
2. Add policy validation and testing endpoint
3. Create policy audit log
4. Build admin UI for policy management

**Deliverables:**
- Policy management API
- Policy testing tool
- Audit log
- Admin UI

### Phase 4: Production Rollout (2 weeks)
**Goal:** Gradual rollout to production

1. Deploy with default ALLOW (no enforcement)
2. Enable dry-run mode for all orgs
3. Analyze dry-run logs and adjust policies
4. Enable enforcement org-by-org
5. Monitor and iterate

**Deliverables:**
- Production deployment
- Dry-run analysis
- Per-org enforcement
- Runbooks

---

## Future: When to Consider SpiceDB

Consider migrating to SpiceDB when:

1. **Team/User Permissions Needed**
   - "Team Platform can access org 123's logs"
   - "User Alice has editor role for org 456"
   - Need hierarchical permission inheritance

2. **Cross-Product Authorization**
   - Unified permissions across multiple Datadog products
   - Shared permission models with other teams

3. **Scale Requirements**
   - >100K policies
   - >1M authorization checks/second
   - Global distribution needed

4. **Complex Relationship Graphs**
   - Multi-level team hierarchies
   - Resource ownership chains
   - Delegated permissions

**Migration Path:**
1. Keep custom condition evaluator for ABAC
2. Add SpiceDB for ReBAC (team/user permissions)
3. Hybrid evaluation: SpiceDB check → Condition check
4. Gradually migrate pure relationship checks to SpiceDB

---

## Conclusion

**Recommendation: Custom Implementation First**

**Rationale:**
1. ✅ Intake policies are primarily **attribute-based** (IP, API keys, conditions)
2. ✅ SpiceDB is designed for **relationship-based** authorization
3. ✅ Custom implementation is **faster to build** and **easier to maintain**
4. ✅ **Lower latency** (<1ms in-process vs 5-10ms network call)
5. ✅ **No operational overhead** (no new service to manage)
6. ✅ **Full control** over condition expression language
7. ✅ **Easy to extend** for future requirements

**Future Consideration:**
When we need team/user-based permissions (not just org-level), we can:
- Keep custom evaluator for ABAC (IP, keys, conditions)
- Add SpiceDB for ReBAC (teams, users, roles)
- Use hybrid approach for best of both worlds

**Next Steps:**
1. Review and approve this design
2. Start Phase 1 implementation (2 weeks)
3. Iterate based on feedback
4. Plan production rollout

---

## Appendix: Sample Code

### Policy Definition
```json
{
  "uuid": "policy-123",
  "name": "Production IP Allowlist",
  "org_id": 12345,
  "status": "ENFORCED",
  "default_action": "DENY",
  "bindings": [
    {
      "resource_type": "*",
      "principal": "org:*",
      "relation": "ALLOW",
      "condition": "ipInRange(request.ip, '10.0.0.0/16')"
    },
    {
      "resource_type": "logs",
      "principal": "org:*",
      "relation": "ALLOW",
      "condition": "request.key_uuid == 'restricted-key-uuid'"
    }
  ]
}
```

### Evaluation Code
```go
package policy

import (
    "github.com/google/cel-go/cel"
    "github.com/google/cel-go/checker/decls"
)

type Evaluator struct {
    env *cel.Env
}

func NewEvaluator() (*Evaluator, error) {
    env, err := cel.NewEnv(
        cel.Declarations(
            decls.NewVar("request", decls.NewMapType(decls.String, decls.Dyn)),
        ),
        cel.Function("ipInRange",
            cel.Overload("ipInRange_string_string",
                []*cel.Type{cel.StringType, cel.StringType},
                cel.BoolType,
                cel.BinaryBinding(checkIPInRange),
            ),
        ),
    )
    if err != nil {
        return nil, err
    }
    return &Evaluator{env: env}, nil
}

func (e *Evaluator) Evaluate(policy *PolicyContext, request map[string]interface{}) (Action, error) {
    for _, binding := range policy.Bindings {
        if !matchesResourceType(binding.ResourceType, request["resource_type"].(string)) {
            continue
        }

        if binding.Condition == "" {
            return binding.Relation, nil
        }

        ast, _ := e.env.Compile(binding.Condition)
        prg, _ := e.env.Program(ast)
        result, err := prg.Eval(map[string]interface{}{
            "request": request,
        })

        if err != nil {
            return Action_UNSPECIFIED, err
        }

        if result.Value().(bool) {
            return binding.Relation, nil
        }
    }

    return policy.DefaultAction, nil
}
```

### Performance Test Results (Simulated)
```
Benchmark: Policy Evaluation Latency

Custom Implementation (in-process):
  p50: 0.2ms
  p95: 0.5ms
  p99: 1.2ms

SpiceDB (network call):
  p50: 5.3ms
  p95: 12.1ms
  p99: 25.4ms

Hybrid (SpiceDB + custom):
  p50: 6.1ms
  p95: 14.3ms
  p99: 28.7ms
```
