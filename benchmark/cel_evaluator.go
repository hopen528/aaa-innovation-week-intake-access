package benchmark

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"k8s.io/apiserver/pkg/cel/library"
)

// PolicyMode represents the enforcement mode of a policy
type PolicyMode string

const (
	PolicyModeDisabled PolicyMode = "disabled"
	PolicyModeDryRun   PolicyMode = "dry_run"
	PolicyModeEnforced PolicyMode = "enforced"
)

// PolicyProgram wraps a compiled CEL program with metadata
type PolicyProgram struct {
	Program  cel.Program
	Mode     PolicyMode
	PolicyID string
}

// CELEvaluator evaluates access policies using CEL expressions
// This matches the innovation week design with K8s CEL library (cidr().containsIP(ip()) syntax)
type CELEvaluator struct {
	mu       sync.RWMutex
	env      *cel.Env
	policies map[string]*PolicyProgram // Map of "<orgID>:<apiKeyUUID>" → compiled program
	                                   // "123:*" = org-wide for org 123
	                                   // "123:uuid-456" = key-specific for org 123, key uuid-456
}

// RequestContext represents the request attributes for evaluation
type RequestContext struct {
	SourceIP  string
	Product   string
	Country   string
	UserAgent string
	Timestamp time.Time
}

// AccessDecision represents the result of policy evaluation
type AccessDecision struct {
	Allowed        bool
	Reason         string
	PolicyID       string
	PolicyScope    string
	Mode           PolicyMode
	WouldBlock     bool
	EvaluationTime time.Duration
}

// NewCELEvaluator creates a new CEL evaluator with Kubernetes IP/CIDR library
func NewCELEvaluator() (*CELEvaluator, error) {
	// Create CEL environment with Kubernetes IP and CIDR library extensions
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
		policies: make(map[string]*PolicyProgram),
	}, nil
}

// AddPolicy compiles and adds a policy for evaluation
// Policy key format: "<orgID>:<apiKeyUUID>"
func (e *CELEvaluator) AddPolicy(orgID int32, subjectID, expression string, mode PolicyMode) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Compile CEL expression
	ast, issues := e.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("failed to compile expression: %w", issues.Err())
	}

	// Create executable program
	prg, err := e.env.Program(ast)
	if err != nil {
		return fmt.Errorf("failed to create program: %w", err)
	}

	// Store with orgID:subjectID key format
	policyKey := fmt.Sprintf("%d:%s", orgID, subjectID)
	policyID := fmt.Sprintf("policy-%d-%s", orgID, subjectID)
	e.policies[policyKey] = &PolicyProgram{
		Program:  prg,
		Mode:     mode,
		PolicyID: policyID,
	}

	return nil
}

// CheckAccess evaluates CEL expression for API key
// Policy keys format: "<orgID>:<apiKeyUUID>"
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
			decision.Reason = fmt.Sprintf("[ORG-WIDE] %s", decision.Reason)
			decision.PolicyScope = orgWideKey
			decision.EvaluationTime = time.Since(startTime)
			return decision, nil
		}
	}

	// Check API-key-specific policy (orgID:apiKeyUUID)
	keyPolicy, exists := e.policies[keySpecificKey]
	if !exists {
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
			"product":    ctx.Product,
			"country":    ctx.Country,
			"user_agent": ctx.UserAgent,
			"timestamp":  ctx.Timestamp,
		},
	}

	// Evaluate CEL expression
	out, _, err := policy.Program.Eval(evalCtx)
	if err != nil {
		decision.Allowed = true // Fail open on error
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
		decision.Allowed = true
		decision.WouldBlock = !wouldAllow
		if !wouldAllow {
			decision.Reason = fmt.Sprintf("[DRY_RUN] Would have BLOCKED by policy %s", policy.PolicyID)
		} else {
			decision.Reason = fmt.Sprintf("[DRY_RUN] Would have ALLOWED by policy %s", policy.PolicyID)
		}
		return decision, nil

	case PolicyModeEnforced:
		if !wouldAllow {
			decision.Allowed = false
			decision.Reason = fmt.Sprintf("Blocked by policy %s", policy.PolicyID)
		} else {
			decision.Allowed = true
		}
		return decision, nil

	default:
		decision.Allowed = true
		return decision, nil
	}
}

// ParsePolicyMode extracts mode from object_id
func ParsePolicyMode(objectID string) PolicyMode {
	if strings.HasSuffix(objectID, "-disabled") {
		return PolicyModeDisabled
	}
	if strings.HasSuffix(objectID, "-dryrun") {
		return PolicyModeDryRun
	}
	if strings.HasSuffix(objectID, "-enforced") {
		return PolicyModeEnforced
	}
	return PolicyModeEnforced
}

// IntakeRequestToContext converts IntakeRequest to RequestContext
func IntakeRequestToContext(req *IntakeRequest) *RequestContext {
	return &RequestContext{
		SourceIP:  req.IP,
		Product:   req.Product,
		Country:   "",
		UserAgent: "",
		Timestamp: time.Now(),
	}
}
