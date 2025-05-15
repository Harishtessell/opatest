package evaluator

import (
	"context"
	"embed"
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

//go:embed authz.rego
var regoFiles embed.FS

func Evaluate(ctx context.Context, query string, input map[string]interface{}) (interface{}, error) {
	// Step 1: Read the embedded rego policy
	policyBytes, err := regoFiles.ReadFile("authz.rego")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded rego file: %w", err)
	}

	// Step 2: Parse the module
	module, err := ast.ParseModule("authz.rego", string(policyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse rego module: %w", err)
	}

	// Step 3: Pass the parsed module directly
	r := rego.New(
		rego.Query(query),
		rego.ParsedModule(module), // ✅ use singular ParsedModule (v1.x)
	)

	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare failed: %w", err)
	}

	// Step 4: Evaluate with input
	rs, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil || len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	return rs[0].Expressions[0].Value, nil
}
