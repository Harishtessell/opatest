package opa

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

//go:embed policies/*.rego policies/data.json
var policyFS embed.FS

func Evaluate(ctx context.Context, query string, input map[string]interface{}) (interface{}, error) {
	var regoOptions []func(*rego.Rego)
	regoOptions = append(regoOptions, rego.Query(query))

	// Step 1: Load all .rego files as modules
	err := fs.WalkDir(policyFS, "policies", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".rego" {
			content, err := policyFS.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			regoOptions = append(regoOptions, rego.Module(path, string(content)))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load .rego files: %w", err)
	}

	// Step 2: Read and parse data.json
	dataBytes, err := policyFS.ReadFile("policies/data.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read data.json: %w", err)
	}

	var rawData interface{}
	if err := json.Unmarshal(dataBytes, &rawData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data.json: %w", err)
	}

	astValue, err := ast.InterfaceToValue(rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to convert data to AST value: %w", err)
	}

	regoOptions = append(regoOptions, rego.ParsedValue("data", astValue))

	// Step 3: Build, prepare, and evaluate
	r := rego.New(regoOptions...)

	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare query: %w", err)
	}

	rs, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil || len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("evaluation failed: %w", err)
	}

	return rs[0].Expressions[0].Value, nil
}
