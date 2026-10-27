#pragma once
// Adapters over the engine APIs that differ between the DuckDB releases Gatekeeper builds against: the
// pinned 2.0 release and the supported 1.5 line. In 2.0 names became Identifier values, bound expressions
// gained accessors over private members, and a few types moved. Helpers use the 2.0 accessor spelling.
// Retain the 1.5 branches until its extended support ends on 2027-03-01 (issue #99).
// GATEKEEPER_DUCKDB_MAJOR is set in CMakeLists.txt from DuckDB's own DUCKDB_MAJOR_VERSION.
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/catalog/standard_entry.hpp"
#include "duckdb/common/serializer/serializer.hpp"
#include "duckdb/function/replacement_scan.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/subquery_expression.hpp"
#include "duckdb/parser/parsed_data/create_type_info.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/bound_parameter_map.hpp"
#include "duckdb/planner/expression/bound_aggregate_expression.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/planner/expression/bound_window_expression.hpp"
#include "name_path.hpp"
#include "validator.hpp"
#include <type_traits>
#include <utility>

#ifndef GATEKEEPER_DUCKDB_MAJOR
#error "GATEKEEPER_DUCKDB_MAJOR must be defined by the Gatekeeper build"
#endif
#if GATEKEEPER_DUCKDB_MAJOR >= 2
#include "duckdb/function/window_function.hpp"
#endif

namespace duckdb {
namespace engine {

// 2.0 tracks cardinality per vector: SetValue writes a slot without advancing its
// size, and deprecated DataChunk::SetCardinality changes only the chunk count.
// Append every field before checking the row, including LIST/STRUCT children.
inline void AppendResultRow(DataChunk &output, const vector<Value> &fields) {
	for (idx_t column = 0; column < fields.size(); column++) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
		output.data[column].Append(fields[column]);
#else
		output.SetValue(column, 0, fields[column]);
#endif
	}
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	output.CheckCardinality(1);
#else
	output.SetCardinality(1);
#endif
}

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

// Newer 2.0 snapshots register optional table-function options as typed **kwargs.
// Detect the old member so wheel-matched earlier 2.0 builds remain supported too.
template <class T, class = void> struct HasNamedParameters : std::false_type {};
template <class T>
struct HasNamedParameters<T, std::void_t<decltype(std::declval<T &>().named_parameters)>> : std::true_type {};
template <class T> inline void RegisterOptions(T &function, const std::vector<std::string> &names) {
	if constexpr (HasNamedParameters<T>::value) {
		for (const auto &name : names)
			function.named_parameters[ToName(name)] = LogicalType::ANY;
		function.named_parameters[ToName("json")] = LogicalType::ANY;
	} else {
		function.GetSignature().WithTypedKwargs(ToName("options"), [&](auto &options) {
			for (const auto &name : names)
				options.Add(ToName(name), LogicalType::ANY);
			options.Add(ToName("json"), LogicalType::ANY);
		});
	}
}

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

// Descriptor qualification is not CatalogEntry::internal. Leave origin unknown here;
// authorization restores it from the private bind's exact catalog-entry provenance.
template <class FUNCTION> inline gatekeeper::Identity FunctionIdentity(const FUNCTION &function, const string &kind) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	auto qualified = function.GetQualifiedName();
	auto &path = qualified.Path();
	if (path.size() < 3 || Str(path.front()).empty())
		return {"", {}, FunctionName(function), kind};
	gatekeeper::NamePath schema;
	for (idx_t i = 1; i + 1 < path.size(); i++)
		schema.push_back(Str(path[i]));
	return {Str(path.front()), schema, Str(path.back()), kind};
#else
	return {function.catalog_name,
	        function.schema_name.empty() ? gatekeeper::NamePath{} : gatekeeper::NamePath{function.schema_name},
	        function.name, kind};
#endif
}
inline gatekeeper::Identity AggregateIdentity(const BoundAggregateExpression &expression) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	return FunctionIdentity(expression.Function(), "aggregate");
#else
	return FunctionIdentity(expression.function, "aggregate");
#endif
}

// 2.0 retains the definition through descriptor mutation. Compare qualified identities,
// never callback/overload addresses across the host and loadable engine copies.
template <class FUNCTION> inline gatekeeper::Identity DefinitionIdentity(const FUNCTION &function, const string &kind) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	return function.GetDefinition() ? FunctionIdentity(*function.GetDefinition(), kind) : gatekeeper::Identity{};
#else
	return {};
#endif
}
inline gatekeeper::Identity AggregateDefinition(const BoundAggregateExpression &expression) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	return DefinitionIdentity(expression.Function(), "aggregate");
#else
	return {};
#endif
}

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
		if (!input.schema_name.empty())
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

// Resolve without binding arguments, then pin the replacement reference to the exact returned entry.
inline CatalogEntry &ResolveReplacementFunction(ClientContext &context, FunctionExpression &expression) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	auto binder = Binder::CreateBinder(context);
	auto name = binder->BindTableName(expression.GetQualifiedName());
	auto &entry = Catalog::GetEntry(context, CatalogType::TABLE_FUNCTION_ENTRY, name);
	auto &standard = entry.Cast<StandardEntry>();
	expression.SetQualifiedName(standard.schema.GetQualifiedName(entry.name));
#else
	auto catalog = expression.catalog;
	auto schema = expression.schema;
	Binder::BindSchemaOrCatalog(context, catalog, schema);
	auto &entry =
	    Catalog::GetEntry(context, CatalogType::TABLE_FUNCTION_ENTRY, catalog, schema, expression.function_name);
	auto &standard = entry.Cast<StandardEntry>();
	expression.catalog = standard.schema.catalog.GetName();
	expression.schema = standard.schema.name;
	expression.function_name = entry.name;
#endif
	return entry;
}

// A table function whose execution is its point must run even when the client does not fetch its rows. 2.0
// snapshots through v2.0.0-alpha46057 let the planner settle that: the mark completes the statement before its
// result is returned. Later ones removed planner eagerness and leave it to the reader, which streams only a SELECT
// that returns rows: CALL and EXECUTE still complete at submission, a SELECT over the function runs as it is read.
template <class T, class = void> struct HasResultEagerness : std::false_type {};
template <class T>
struct HasResultEagerness<T, std::void_t<decltype(std::declval<T &>().result_eagerness)>> : std::true_type {};
template <class PROPERTIES> inline void CompleteAtSubmission(PROPERTIES &properties) {
	if constexpr (HasResultEagerness<PROPERTIES>::value)
		properties.result_eagerness = decltype(properties.result_eagerness)::FORCED;
}
inline void RunAtOnce(TableFunctionBindInput &input) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	if (input.binder)
		CompleteAtSubmission(input.binder->GetStatementProperties());
#else
	(void)input;
#endif
}

// The parser the connection itself uses: its parser options and extensions. Newer 2.0 snapshots build it from the
// context and make ClientContext::GetParserOptions private.
template <class CONTEXT> inline Parser ConnectionParser(CONTEXT &context) {
	if constexpr (std::is_constructible<Parser, CONTEXT &>::value)
		return Parser(context);
	else
		return Parser(context.GetParserOptions());
}

// The database-wide replacement scans. Newer 2.0 snapshots guard them with a lock, hand the binder a snapshot of
// shared entries, and can only append; earlier engines expose the vector itself. Visit them in the order the engine
// asks them until `visit` returns true.
template <class T, class = void> struct HasScanSnapshot : std::false_type {};
template <class T>
struct HasScanSnapshot<T, std::void_t<decltype(std::declval<const T &>().Snapshot())>> : std::true_type {};
template <class LIST, class VISIT> inline void VisitReplacementScans(LIST &scans, VISIT &&visit) {
	if constexpr (HasScanSnapshot<LIST>::value) {
		for (auto &scan : scans.Snapshot())
			if (visit(*scan))
				return;
	} else {
		for (auto &scan : scans)
			if (visit(scan))
				return;
	}
}

// An existing entry carried into a rebuilt list unchanged: the same callback with the same data, shared with the
// original, so snapshots the binder already holds and the rebuilt list agree.
struct ForwardedScanData : ReplacementScanData {
	explicit ForwardedScanData(shared_ptr<ReplacementScan> scan_p) : scan(std::move(scan_p)) {}
	shared_ptr<ReplacementScan> scan;
};
inline unique_ptr<TableRef> ForwardedScan(ClientContext &context, ReplacementScanInput &input,
                                          optional_ptr<ReplacementScanData> data) {
	auto &scan = *data->Cast<ForwardedScanData>().scan;
	return scan.function(context, input, scan.data.get());
}

// Put `function` ahead of every registered scan. A list that can only append is rebuilt with it in front and
// replaced whole; a scan registered concurrently with the rebuild (another extension loading at the same time)
// would be lost, which is why the extension is loaded during trusted setup.
template <class LIST> inline void PrependReplacementScan(LIST &scans, replacement_scan_t function) {
	if constexpr (HasScanSnapshot<LIST>::value) {
		LIST rebuilt;
		rebuilt.emplace_back(function);
		for (auto &scan : scans.Snapshot())
			rebuilt.emplace_back(ForwardedScan, make_uniq<ForwardedScanData>(scan));
		scans = std::move(rebuilt);
	} else {
		scans.insert(scans.begin(), ReplacementScan(function));
	}
}

// Whether `modifications` is at most the creation of catalog entries. Engines without the comparison register no
// temporary-catalog modification for a dynamic PIVOT's enum type, so the question never arises there.
template <class T, class = void> struct HasModificationContains : std::false_type {};
template <class T>
struct HasModificationContains<T, std::void_t<decltype(std::declval<const T &>().Contains(std::declval<T>()))>>
    : std::true_type {};
template <class MODIFICATIONS> inline bool OnlyCreatesEntries(const MODIFICATIONS &modifications) {
	if constexpr (HasModificationContains<MODIFICATIONS>::value)
		return MODIFICATIONS(MODIFICATIONS::CREATE_CATALOG_ENTRY).Contains(modifications);
	else
		return false;
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
