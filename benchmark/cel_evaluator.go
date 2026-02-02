package benchmark

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
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
// This matches the innovation week design with ip().in_cidr() syntax
type CELEvaluator struct {
	mu       sync.RWMutex
	env      *cel.Env
	policies map[string]*PolicyProgram // Map of subject ID → compiled program
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

// NewCELEvaluator creates a new CEL evaluator with custom IP functions
func NewCELEvaluator() (*CELEvaluator, error) {
	// Create CEL environment with custom IP helper function
	env, err := cel.NewEnv(
		// Define request context type
		cel.Variable("request", cel.MapType(cel.StringType, cel.AnyType)),

		// Add custom IP helper function
		cel.Function("ip",
			cel.Overload("string_to_ip",
				[]*cel.Type{cel.StringType},
				cel.ObjectType("IP"),
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					ipStr, ok := val.Value().(string)
					if !ok {
						return types.NewErr("ip() requires string argument")
					}
					return &ipValue{ip: net.ParseIP(ipStr)}
				}),
			),
		),

		// Add in_cidr method for IP type
		cel.Function("in_cidr",
			cel.MemberOverload("ip_in_cidr",
				[]*cel.Type{cel.ObjectType("IP"), cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					ipVal, ok := lhs.(*ipValue)
					if !ok {
						return types.NewErr("in_cidr() requires IP type")
					}
					cidrStr, ok := rhs.Value().(string)
					if !ok {
						return types.NewErr("in_cidr() requires string argument")
					}
					return types.Bool(ipVal.InCIDR(cidrStr))
				}),
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	return &CELEvaluator{
		env:      env,
		policies: make(map[string]*PolicyProgram),
	}, nil
}

// Custom IP type for CEL with in_cidr method
type ipValue struct {
	ip net.IP
}

func (i *ipValue) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
	return i.ip, nil
}

func (i *ipValue) ConvertToType(typeVal ref.Type) ref.Val {
	return i
}

func (i *ipValue) Equal(other ref.Val) ref.Val {
	if otherIP, ok := other.(*ipValue); ok {
		return types.Bool(i.ip.Equal(otherIP.ip))
	}
	return types.Bool(false)
}

func (i *ipValue) Type() ref.Type {
	return types.NewObjectType("IP")
}

func (i *ipValue) Value() interface{} {
	return i.ip
}

// Receive implements the custom method receiver for in_cidr
func (i *ipValue) Receive(function string, overload string, args []ref.Val) ref.Val {
	if function == "in_cidr" {
		if len(args) != 1 {
			return types.NewErr("in_cidr() requires exactly one argument")
		}
		cidrStr, ok := args[0].Value().(string)
		if !ok {
			return types.NewErr("in_cidr() requires string argument")
		}
		return types.Bool(i.InCIDR(cidrStr))
	}
	return types.NewErr("unknown function: %s", function)
}

func (i *ipValue) InCIDR(cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(i.ip)
}

// AddPolicy compiles and adds a policy for evaluation
func (e *CELEvaluator) AddPolicy(subjectID, expression string, mode PolicyMode) error {
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

	policyID := fmt.Sprintf("policy-%s", subjectID)
	e.policies[subjectID] = &PolicyProgram{
		Program:  prg,
		Mode:     mode,
		PolicyID: policyID,
	}

	return nil
}

// CheckAccess evaluates CEL expression for API key
func (e *CELEvaluator) CheckAccess(apiKeyID string, ctx *RequestContext) (*AccessDecision, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	startTime := time.Now()

	// Check org-wide policy first (api_key:*)
	if orgPolicy, exists := e.policies["*"]; exists {
		decision, err := e.evaluatePolicy(orgPolicy, "*", ctx)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed && decision.Mode == PolicyModeEnforced {
			decision.Reason = fmt.Sprintf("[ORG-WIDE] %s", decision.Reason)
			decision.PolicyScope = "*"
			decision.EvaluationTime = time.Since(startTime)
			return decision, nil
		}
	}

	// Check API-key-specific policy
	keyPolicy, exists := e.policies[apiKeyID]
	if !exists {
		return &AccessDecision{
			Allowed:        true,
			EvaluationTime: time.Since(startTime),
		}, nil
	}

	decision, err := e.evaluatePolicy(keyPolicy, apiKeyID, ctx)
	if err != nil {
		return nil, err
	}

	decision.Reason = fmt.Sprintf("[API_KEY] %s", decision.Reason)
	decision.PolicyScope = apiKeyID
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
