#pragma once
// Adapters over the engine APIs that differ between the DuckDB releases Gatekeeper builds against: 1.5, the
// pinned release, and 2.0, where names became Identifier values, bound expressions gained accessors over
// private members, and a few types moved. Every helper is spelled as the 2.0 accessor it stands for, so call
// sites read the same on both engines and the 1.5 branch is dropped when the engine pin moves.
// GATEKEEPER_DUCKDB_MAJOR is set in CMakeLists.txt from DuckDB's own DUCKDB_MAJOR_VERSION.
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/common/serializer/serializer.hpp"
#include "duckdb/function/replacement_scan.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/subquery_expression.hpp"
#include "duckdb/parser/parsed_data/create_type_info.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/bound_parameter_map.hpp"
#include "duckdb/planner/expression/bound_aggregate_expression.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/planner/expression/bound_window_expression.hpp"
#include "validator.hpp"

#ifndef GATEKEEPER_DUCKDB_MAJOR
#error "GATEKEEPER_DUCKDB_MAJOR must be defined by the Gatekeeper build"
#endif

namespace duckdb {
namespace engine {

#if GATEKEEPER_DUCKDB_MAJOR >= 2
//! A name as the engine's own APIs carry it: a catalog, function, column or parameter name.
using Name = Identifier;
template <class T> using name_map_t = identifier_map_t<T>;
inline const string &Str(const Identifier &name) { return name.GetIdentifierName(); }
inline Identifier ToName(const string &text) { return Identifier(text); }
#else
using Name = string;
template <class T> using name_map_t = case_insensitive_map_t<T>;
inline const string &ToName(const string &text) { return text; }
#endif
inline const string &Str(const string &text) { return text; }
using NameList = vector<Name>;
using ParameterMap = name_map_t<BoundParameterData>;

// Bound expressions and the functions they carry.
#if GATEKEEPER_DUCKDB_MAJOR >= 2
using BoundScalar = BoundScalarFunction;
inline const BoundScalar &Function(const BoundFunctionExpression &expression) { return expression.Function(); }
inline const vector<unique_ptr<Expression>> &Children(const BoundFunctionExpression &expression) {
	return expression.GetChildren();
}
inline optional_ptr<FunctionData> BindInfo(const BoundFunctionExpression &expression) {
	return expression.BindInfo().get();
}
inline const string &FunctionName(const BoundAggregateExpression &expression) {
	return Str(expression.Function().GetName());
}
inline optional_ptr<const BoundAggregateFunction> WindowAggregate(const BoundWindowExpression &window) {
	return window.AggregateFunction().get();
}
template <class FUNCTION> inline const string &FunctionName(const FUNCTION &function) {
	return Str(function.GetName());
}
template <class FUNCTION> inline const string &CatalogName(const FUNCTION &function) {
	return Str(function.GetCatalogName());
}
template <class FUNCTION> inline bool SystemBuiltin(const FUNCTION &function) {
	auto qualified = function.GetQualifiedName();
	auto &path = qualified.Path();
	return path.size() == 3 && Str(path[0]) == "system" && Str(path[1]) == "main";
}
inline const LogicalType &ReturnType(const Expression &expression) { return expression.GetReturnType(); }
#else
using BoundScalar = ScalarFunction;
inline const BoundScalar &Function(const BoundFunctionExpression &expression) { return expression.function; }
inline const vector<unique_ptr<Expression>> &Children(const BoundFunctionExpression &expression) {
	return expression.children;
}
inline optional_ptr<FunctionData> BindInfo(const BoundFunctionExpression &expression) {
	return expression.bind_info.get();
}
inline const string &FunctionName(const BoundAggregateExpression &expression) { return expression.function.name; }
inline optional_ptr<const AggregateFunction> WindowAggregate(const BoundWindowExpression &window) {
	return window.aggregate.get();
}
template <class FUNCTION> inline const string &FunctionName(const FUNCTION &function) { return function.name; }
template <class FUNCTION> inline const string &CatalogName(const FUNCTION &function) { return function.catalog_name; }
template <class FUNCTION> inline bool SystemBuiltin(const FUNCTION &function) {
	return function.catalog_name == "system" && function.schema_name == "main";
}
inline const LogicalType &ReturnType(const Expression &expression) { return expression.return_type; }
#endif

// Parsed expressions.
#if GATEKEEPER_DUCKDB_MAJOR >= 2
inline const string &FunctionName(const FunctionExpression &expression) {
	return Str(expression.GetQualifiedName().Name());
}
inline idx_t ArgumentCount(const FunctionExpression &expression) { return expression.GetArguments().size(); }
inline const SelectStatement &Subquery(const SubqueryExpression &expression) { return *expression.Subquery(); }
#else
inline const string &FunctionName(const FunctionExpression &expression) { return expression.function_name; }
inline idx_t ArgumentCount(const FunctionExpression &expression) { return expression.children.size(); }
inline const SelectStatement &Subquery(const SubqueryExpression &expression) { return *expression.subquery; }
#endif

// Catalog entries and CREATE payloads.
inline const string &EntryName(const CatalogEntry &entry) { return Str(entry.name); }
inline gatekeeper::NamePath SchemaPath(const SchemaCatalogEntry &schema) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	gatekeeper::NamePath path;
	for (const auto &part : schema.GetSchemaPath())
		path.push_back(Str(part));
	return path;
#else
	return {EntryName(schema)};
#endif
}
inline gatekeeper::NamePath ReplacementName(const ReplacementScanInput &input) {
	gatekeeper::NamePath path;
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	for (const auto &part : input.name.Path())
		path.push_back(Str(part));
#else
	if (!input.catalog_name.empty()) {
		path.push_back(input.catalog_name);
		path.push_back(input.schema_name);
	} else if (!input.schema_name.empty())
		path.push_back(input.schema_name);
	path.push_back(input.table_name);
#endif
	return gatekeeper::FoldPath(std::move(path));
}
inline string ReplacementPath(ReplacementScanInput &input) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	string path;
	for (const auto &part : input.name.Path()) {
		if (part.empty())
			continue;
		if (!path.empty())
			path += ".";
		path += Str(part);
	}
	return path;
#else
	return ReplacementScan::GetFullPath(input);
#endif
}
inline void MissingReplacement(ClientContext &context, const ReplacementScanInput &input) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	Catalog::GetEntry(context, CatalogType::TABLE_ENTRY, input.name);
#else
	Catalog::GetEntry(context, CatalogType::TABLE_ENTRY, input.catalog_name, input.schema_name, input.table_name);
#endif
}
inline const string &CatalogName(const Catalog &catalog) { return Str(catalog.GetName()); }
#if GATEKEEPER_DUCKDB_MAJOR >= 2
inline const string &InfoCatalog(const CreateInfo &info) { return Str(info.GetQualifiedName().Catalog()); }
inline const string &InfoSchema(const CreateInfo &info) { return Str(info.GetQualifiedName().Schema()); }
inline const string &TypeName(const CreateTypeInfo &info) { return Str(info.GetTypeName()); }
inline CatalogEntry &GetEntry(ClientContext &context, CatalogType type, const string &catalog, const string &schema,
                              const string &name) {
	return Catalog::GetEntry(context, type, QualifiedName(Identifier(catalog), Identifier(schema), Identifier(name)));
}
#else
inline const string &InfoCatalog(const CreateInfo &info) { return info.catalog; }
inline const string &InfoSchema(const CreateInfo &info) { return info.schema; }
inline const string &TypeName(const CreateTypeInfo &info) { return info.name; }
inline CatalogEntry &GetEntry(ClientContext &context, CatalogType type, const string &catalog, const string &schema,
                              const string &name) {
	return Catalog::GetEntry(context, type, catalog, schema, name);
}
#endif

// A table function whose execution is its point (gatekeeper_enforce latches, gatekeeper_configure writes the
// policy) must run when its statement runs, however the statement is spelled. DuckDB 1.5 runs every statement
// to completion; 2.0 produces a SELECT's rows only as the client reads them, and runs CALL at once by marking
// the statement's result eagerness in Binder::Bind(CallStatement). The same mark from the function's bind makes
// `SELECT ... FROM gatekeeper_enforce()`, a prepared statement over it, and EXECUTE of one run at once too.
inline void RunAtOnce(TableFunctionBindInput &input) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	if (input.binder)
		input.binder->GetStatementProperties().result_eagerness = ResultEagerness::FORCED;
#else
	(void)input;
#endif
}

// The serializer settings that produce the shape the grammar was generated from: the latest storage version
// of the engine being built.
inline SerializationOptions LatestSerialization() {
	SerializationOptions options;
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	options.storage_compatibility = StorageCompatibility::Latest();
#else
	options.serialization_compatibility = SerializationCompatibility::Latest();
#endif
	return options;
}

} // namespace engine
} // namespace duckdb
