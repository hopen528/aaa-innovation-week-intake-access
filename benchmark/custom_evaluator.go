package benchmark

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// Policy represents a policy with bindings
type Policy struct {
	UUID     string
	Bindings []Binding
}

// Binding represents a policy binding
type Binding struct {
	ResourceType string
	Principal    string
	Relation     string
	Condition    string
}

// CustomEvaluator evaluates policies using CEL
type CustomEvaluator struct {
	env          *cel.Env
	compiledCache map[string]cel.Program
	cacheMutex   sync.RWMutex
}

// NewCustomEvaluator creates a new custom evaluator
func NewCustomEvaluator() (*CustomEvaluator, error) {
	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewVar("request", decls.NewMapType(decls.String, decls.Dyn)),
		),
		cel.Function("ipInRange",
			cel.Overload("ipInRange_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(ipInRangeImpl),
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	return &CustomEvaluator{
		env:          env,
		compiledCache: make(map[string]cel.Program),
	}, nil
}

// Evaluate evaluates a policy against a request
func (e *CustomEvaluator) Evaluate(policy *Policy, request *IntakeRequest) (bool, error) {
	for _, binding := range policy.Bindings {
		// Match resource type
		if binding.ResourceType != "*" && binding.ResourceType != request.Product {
			continue
		}

		// Empty condition means always match
		if binding.Condition == "" {
			return true, nil
		}

		// Evaluate condition
		matched, err := e.evaluateCondition(binding.Condition, request)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate condition: %w", err)
		}

		if matched {
			return true, nil
		}
	}

	return false, nil
}

// CompileAndCache pre-compiles a policy and caches it
func (e *CustomEvaluator) CompileAndCache(policy *Policy) error {
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	for i, binding := range policy.Bindings {
		if binding.Condition == "" {
			continue
		}

		ast, issues := e.env.Compile(binding.Condition)
		if issues != nil && issues.Err() != nil {
			return fmt.Errorf("failed to compile condition %d: %w", i, issues.Err())
		}

		prg, err := e.env.Program(ast)
		if err != nil {
			return fmt.Errorf("failed to create program %d: %w", i, err)
		}

		cacheKey := fmt.Sprintf("%s-%d", policy.UUID, i)
		e.compiledCache[cacheKey] = prg
	}

	return nil
}

// EvaluateCached evaluates using cached compiled programs
func (e *CustomEvaluator) EvaluateCached(policyUUID string, request *IntakeRequest) (bool, error) {
	e.cacheMutex.RLock()
	defer e.cacheMutex.RUnlock()

	i := 0
	for {
		cacheKey := fmt.Sprintf("%s-%d", policyUUID, i)
		prg, ok := e.compiledCache[cacheKey]
		if !ok {
			break
		}

		requestMap := requestToMap(request)
		out, _, err := prg.Eval(map[string]interface{}{
			"request": requestMap,
		})

		if err != nil {
			return false, fmt.Errorf("failed to evaluate: %w", err)
		}

		if out.Value().(bool) {
			return true, nil
		}

		i++
	}

	return false, nil
}

// evaluateCondition evaluates a CEL condition
func (e *CustomEvaluator) evaluateCondition(condition string, request *IntakeRequest) (bool, error) {
	ast, issues := e.env.Compile(condition)
	if issues != nil && issues.Err() != nil {
		return false, fmt.Errorf("failed to compile condition: %w", issues.Err())
	}

	prg, err := e.env.Program(ast)
	if err != nil {
		return false, fmt.Errorf("failed to create program: %w", err)
	}

	requestMap := requestToMap(request)

	out, _, err := prg.Eval(map[string]interface{}{
		"request": requestMap,
	})
	if err != nil {
		return false, fmt.Errorf("failed to evaluate: %w", err)
	}

	return out.Value().(bool), nil
}

// requestToMap converts IntakeRequest to map for CEL evaluation
func requestToMap(request *IntakeRequest) map[string]interface{} {
	return map[string]interface{}{
		"org_id":   request.OrgID,
		"ip":       request.IP,
		"key_uuid": request.KeyUUID,
		"product":  request.Product,
		"hour":     request.Hour,
	}
}

// ipInRangeImpl implements the ipInRange CEL function
func ipInRangeImpl(lhs, rhs ref.Val) ref.Val {
	ipStr, ok := lhs.Value().(string)
	if !ok {
		return types.NewErr("ipInRange: first argument must be string")
	}

	cidrStr, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("ipInRange: second argument must be string")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return types.Bool(false)
	}

	_, ipnet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return types.NewErr("ipInRange: invalid CIDR: %v", err)
	}

	return types.Bool(ipnet.Contains(ip))
}
