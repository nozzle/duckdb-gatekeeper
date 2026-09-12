//go:build ignore

package main

import (
	"encoding/json"
	"os"

	"github.com/uwdata/mosaic/packages/server/duckdb-server-go/pkg/functionset"
)

func main() {
	extensions := map[string]any{}
	for _, extension := range functionset.CoreExtensions() {
		extensions[string(extension)] = map[string]any{"compute": extension.Compute(), "elevated": extension.Elevated()}
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"duckdb_version": "1.5.5",
		"defaults": functionset.DefaultFunctions(),
		"core": map[string]any{
			"operators": functionset.BuiltinOperators(), "aggregates": functionset.BuiltinAggregates(),
			"windows": functionset.BuiltinWindows(), "syntax_helpers": functionset.BuiltinSyntaxHelpers(),
			"table_generators": functionset.BuiltinTableGenerators(), "scalars": functionset.CommonScalarFunctions(),
		},
		"extensions": extensions,
	}); err != nil {
		panic(err)
	}
}
