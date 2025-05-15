package opa

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/open-policy-agent/opa/v1/rego"
)

//go:embed policies/*.rego policies/data.json
var policyFS embed.FS

func Evaluate(ctx context.Context, query string, input map[string]interface{}) (interface{}, error) {
	var regoOptions []func(*rego.Rego)
	regoOptions = append(regoOptions, rego.Query(query))

	// Step 1: Load and embed .rego modules
	err := fs.WalkDir(policyFS, "policies", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".rego" {
			content, err := policyFS.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", path, err)
			}
			regoOptions = append(regoOptions, rego.Module(path, string(content)))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("rego file loading failed: %w", err)
	}

	// Step 2: Merge input + data.json into a single input map
	dataBytes, err := policyFS.ReadFile("policies/data.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read data.json: %w", err)
	}

	var configData map[string]interface{}
	if err := json.Unmarshal(dataBytes, &configData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data.json: %w", err)
	}

	// Step 3: Merge input and data into one input
	mergedInput := map[string]interface{}{
		"config":  configData, // accessed in Rego as input.config
		"payload": input,      // accessed in Rego as input.payload
	}

	// Step 4: Prepare and evaluate
	r := rego.New(regoOptions...)

	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("query preparation failed: %w", err)
	}

	rs, err := prepared.Eval(ctx, rego.EvalInput(mergedInput))
	if err != nil || len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("evaluation failed: %w", err)
	}

	return rs[0].Expressions[0].Value, nil
}
