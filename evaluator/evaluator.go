package evaluator

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
)

func Evaluate(ctx context.Context, query string, input map[string]interface{}) (interface{}, error) {
	// Load Rego modules from the current directory
	r := rego.New(
		rego.Query(query),
		rego.Load([]string{"authz.rego"}, nil),
	)

	// Prepare the query for evaluation
	preparedQuery, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare query: %w", err)
	}

	// Evaluate the prepared query with the provided input
	results, err := preparedQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate query: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return nil, fmt.Errorf("no result returned from evaluation")
	}

	return results[0].Expressions[0].Value, nil
}
