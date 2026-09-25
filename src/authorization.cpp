#include "authorization.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/catalog/standard_entry.hpp"
#include "duckdb/function/lambda_functions.hpp"
#include "duckdb/planner/expression/bound_aggregate_expression.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/planner/expression/bound_window_expression.hpp"
#include "duckdb/planner/expression_iterator.hpp"
#include "duckdb/planner/logical_operator_visitor.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "engine_api.hpp"
#include "function_policy.hpp"
#include "json_serializer.hpp"
#include <map>

namespace duckdb {
using namespace duckdb_yyjson;

const char *FunctionKind(CatalogType type) {
	switch (type) {
	case CatalogType::SCALAR_FUNCTION_ENTRY:
		return "scalar";
	case CatalogType::AGGREGATE_FUNCTION_ENTRY:
		return "aggregate";
	case CatalogType::TABLE_FUNCTION_ENTRY:
		return "table";
	case CatalogType::MACRO_ENTRY:
		return "macro";
	case CatalogType::TABLE_MACRO_ENTRY:
		return "table_macro";
	case CatalogType::PRAGMA_FUNCTION_ENTRY:
		return "pragma";
	default:
		return nullptr;
	}
}

// The engine's own builtins live in system.main; an entry anywhere else is a host's or an extension's.

// Function policy, the never-bind list included, holds for names attributable to the caller; a trusted
// definition's own functions are outside it, with one exception: Gatekeeper's own control plane is refused on
// every route. The query-wide allowlist check for ambiguous caller syntax holds for the implementation DuckDB
// selects wherever it selects it, as documented.
static void AuthorizeFunction(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding,
                              const string &name, bool attributable, gatekeeper::Result &result) {
	auto canonical = gatekeeper::CanonicalFunction(name);
	if (gatekeeper::ControlPlane(name) || (attributable && gatekeeper::FunctionDenied(policy, name)) ||
	    (binding.synthesized_functions.count(canonical) && !gatekeeper::FunctionAllowed(policy, canonical))) {
		result.violations.emplace(gatekeeper::rules::FUNCTION, "resolved function is not allowed: " + canonical, "",
		                          gatekeeper::NamePath{}, "", canonical);
		throw PermissionException("resolved function is not allowed");
	}
}

static void AuthorizeObjectAgainst(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding,
                                   CatalogEntry &entry, gatekeeper::Result &result, bool attributable) {
	auto &name = engine::EntryName(entry);
	if (auto kind = FunctionKind(entry.type)) {
		AuthorizeFunction(policy, binding, name, attributable, result);
		auto &function = entry.Cast<StandardEntry>();
		auto catalog = engine::CatalogName(function.schema.catalog);
		auto schema = engine::SchemaPath(function.schema);
		bool builtin = catalog == "system" && schema == gatekeeper::NamePath{"main"};
		if ((entry.type == CatalogType::TABLE_FUNCTION_ENTRY || entry.type == CatalogType::TABLE_MACRO_ENTRY) &&
		    binding.runtime_table_functions.count(gatekeeper::Lower(name)) &&
		    (entry.type != CatalogType::TABLE_FUNCTION_ENTRY || !builtin)) {
			result.violations.emplace(gatekeeper::rules::BIND_TIME_EXPRESSION,
			                          "runtime arguments require a system table-in-out function", catalog, schema, "",
			                          name);
			throw PermissionException("untrusted table-in-out function");
		}
		if (binding.literal_constructors.count(gatekeeper::Lower(name)) &&
		    (entry.type != CatalogType::SCALAR_FUNCTION_ENTRY || !builtin)) {
			result.violations.emplace(gatekeeper::rules::BIND_TIME_EXPRESSION,
			                          "literal constructor must resolve to a system builtin", catalog, schema, "",
			                          name);
			throw PermissionException("untrusted bind-time constructor");
		}
		result.functions.insert({catalog, schema, name, kind});
		return;
	}
	if (entry.type != CatalogType::TABLE_ENTRY && entry.type != CatalogType::VIEW_ENTRY)
		return;
	auto &object = entry.Cast<StandardEntry>();
	auto catalog = engine::CatalogName(object.schema.catalog);
	auto schema = engine::SchemaPath(object.schema);
	// Table policy, the internal-object rule included, holds for objects attributable to the caller. An object
	// a trusted definition's body retrieved is that definition's own: recorded as evidence, outside policy.
	if (attributable && !gatekeeper::TableAllowed(policy, catalog, schema, name, entry.internal)) {
		if (gatekeeper::TableBlocked(policy, catalog, schema, name))
			result.violations.emplace(gatekeeper::rules::TABLE, "object is blocked", catalog, schema, name);
		else if (entry.internal)
			result.violations.emplace(gatekeeper::rules::INTERNAL_OBJECT,
			                          "internal object requires exact schema/table permission", catalog, schema, name);
		else
			result.violations.emplace(gatekeeper::rules::TABLE, "object is not allowed", catalog, schema, name);
	}
	if (!result.violations.empty())
		throw PermissionException("resolved object is not allowed");
	gatekeeper::Identity identity{catalog, schema, name, entry.type == CatalogType::TABLE_ENTRY ? "table" : "view"};
	result.objects.insert(identity);
	if (attributable)
		result.caller_objects.insert(identity);
}

void AuthorizeObject(const gatekeeper::Layers &layers, const gatekeeper::BindingPolicy &binding, CatalogEntry &entry,
                     gatekeeper::Result &result, bool attributable) {
	layers.Each(
	    [&](const gatekeeper::Policy &layer) { AuthorizeObjectAgainst(layer, binding, entry, result, attributable); });
}

// ListAggregatesBindData is private to core_functions. Its reviewed serialization callback exposes
// the actual bound aggregate without unsafe layout casts, evaluating arguments, or rebinding names.
// Inspect only this documented shape, never arbitrary JSON payloads that can resemble expressions.
static string ListAggregateImplementation(const BoundFunctionExpression &expression) {
	auto &function = engine::Function(expression);
	auto &name = engine::FunctionName(function);
	// Name-selected dispatchers plus the builtins with a fixed histogram implementation.
	static const gatekeeper::Names fixed = {"list_distinct", "list_unique", "array_distinct", "array_unique"};
	if (!gatekeeper::DispatchingAggregators().count(name) && !fixed.count(name))
		return {};
	// Catalog construction stamps this provenance onto each overload and binding preserves it.
	// A matching leaf name alone does not authorize inspecting a foreign implementation's bind data.
	if (!engine::SystemBuiltin(function))
		throw BinderException("List aggregate implementation is not the pinned builtin");
	auto &children = engine::Children(expression);
	auto bind_info = engine::BindInfo(expression);
	auto null_input = !children.empty() && engine::ReturnType(*children[0]).id() == LogicalTypeId::SQLNULL;
	// These builtins use the fixed histogram implementation and have no serialization callbacks.
	if (fixed.count(name))
		return null_input ? "" : "histogram";
	if (!bind_info) {
		// A NULL-list input carries no executable aggregate: DuckDB 1.5 binds it with a VariableReturnBindData
		// whose serialization holds no bind data (handled below), 2.0 with no bind data at all. Any other
		// missing bind data is a parameter whose type never resolved.
		if (null_input)
			return {};
		throw BinderException("List aggregate requires resolved parameter types");
	}
	if (!function.HasSerializationCallbacks())
		throw BinderException("Cannot inspect list aggregate implementation");
	unique_ptr<yyjson_mut_doc, decltype(&yyjson_mut_doc_free)> doc(yyjson_mut_doc_new(nullptr), yyjson_mut_doc_free);
	if (!doc)
		throw std::bad_alloc();
	JsonSerializer serializer(doc.get(), false, false, false, engine::LatestSerialization());
	function.GetSerializeCallback()(serializer, bind_info, function);
	auto data = yyjson_mut_obj_get(serializer.GetRootObject(), "bind_data");
	// A NULL-list input uses VariableReturnBindData and carries no executable aggregate.
	if (!data || yyjson_mut_is_null(data)) {
		if (null_input)
			return {};
		throw BinderException("Missing list aggregate bind data");
	}
	auto aggregate = yyjson_mut_obj_get(data, "aggr_expr");
	auto kind = yyjson_mut_obj_get(aggregate, "expression_class");
	// The bound aggregate's name (FunctionSerializer::Serialize): DuckDB 1.5 writes `name`; 2.0 writes the
	// qualified name as `qname.path`, whose last component is the name.
	auto target = yyjson_mut_obj_get(aggregate, "name");
	if (!target) {
		auto path = yyjson_mut_obj_get(yyjson_mut_obj_get(aggregate, "qname"), "path");
		if (yyjson_mut_is_arr(path) && yyjson_mut_arr_size(path))
			target = yyjson_mut_arr_get_last(path);
	}
	if (!yyjson_mut_is_str(kind) || string(yyjson_mut_get_str(kind)) != "BOUND_AGGREGATE" ||
	    !yyjson_mut_is_str(target) || !yyjson_mut_get_len(target))
		throw BinderException("Unsupported list aggregate bind data");
	return string(yyjson_mut_get_str(target), yyjson_mut_get_len(target));
}

static void AuthorizePlanAgainst(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding,
                                 const gatekeeper::Provenance &provenance, LogicalOperator &root,
                                 gatekeeper::Result &result) {
	auto attributable = [&](const string &name) { return provenance.Attributable(binding, name); };
	auto function = [&](const string &name, const string &type, bool callers) {
		AuthorizeFunction(policy, binding, name, callers, result);
		for (const auto &entry : result.functions)
			if (entry.name == name && entry.type == type)
				return;
		// Bound implementations do not provide reliable catalog provenance.
		result.functions.insert({"", {}, name, type});
	};
	vector<LogicalOperator *> operators{&root};
	vector<Expression *> expressions;
	while (!operators.empty()) {
		auto op = operators.back();
		operators.pop_back();
		for (auto &child : op->children)
			operators.push_back(child.get());
		if (op->type == LogicalOperatorType::LOGICAL_GET) {
			auto &get = op->Cast<LogicalGet>();
			auto &scan = engine::FunctionName(get.function);
			// A scan with a table entry is an attached catalog reading a table the policy allowed: the reader it
			// uses internally (iceberg_scan, ducklake_scan) is that catalog's, never the caller's.
			if (scan != "seq_scan")
				function(scan, "table", !get.GetTable() && attributable(scan));
		}
		LogicalOperatorVisitor::EnumerateExpressions(*op, [&](unique_ptr<Expression> *expr) {
			if (*expr)
				expressions.push_back(expr->get());
		});
	}
	while (!expressions.empty()) {
		auto &child = *expressions.back();
		expressions.pop_back();
		ExpressionIterator::EnumerateChildren(child, [&](Expression &nested) { expressions.push_back(&nested); });
		if (child.GetExpressionClass() == ExpressionClass::BOUND_UNNEST)
			function("unnest", "scalar", attributable("unnest"));
		if (child.GetExpressionClass() == ExpressionClass::BOUND_FUNCTION) {
			auto &bound = child.Cast<BoundFunctionExpression>();
			auto &implementation = engine::Function(bound);
			auto &name = engine::FunctionName(implementation);
			function(name, "scalar", attributable(name));
			auto lambda = dynamic_cast<ListLambdaBindData *>(engine::BindInfo(bound).get());
			// The system list-lambda builtins always carry ListLambdaBindData, and the lambda body it holds is
			// executable code that blocks must reach. A distributed loadable performs this cast across the
			// host/extension boundary; if it ever fails there, refuse rather than silently skip the body.
			if (!lambda && gatekeeper::ListLambdaFunctions().count(name) && engine::SystemBuiltin(implementation))
				throw BinderException("Cannot inspect list lambda implementation");
			if (lambda && lambda->lambda_expr)
				expressions.push_back(lambda->lambda_expr.get());
			auto aggregate = ListAggregateImplementation(bound);
			if (!aggregate.empty()) {
				// A caller-written dispatcher selects its aggregate by name, so that target is caller-chosen and
				// must be allowed, not merely unblocked. Fixed implementations (list_distinct's histogram) and
				// dispatchers introduced only by trusted views or macros keep the block-only treatment. Any
				// caller-written dispatcher triggers the check query-wide, like other ambiguous caller syntax.
				if (!binding.caller_dispatchers.empty() && gatekeeper::DispatchingAggregators().count(name) &&
				    !gatekeeper::FunctionAllowed(policy, aggregate)) {
					auto canonical = gatekeeper::CanonicalFunction(aggregate);
					result.violations.emplace(gatekeeper::rules::FUNCTION,
					                          "dispatched aggregate is not allowed: " + canonical, "",
					                          gatekeeper::NamePath{}, "", canonical);
					throw PermissionException("dispatched aggregate is not allowed");
				}
				// The dispatched aggregate is the dispatcher's: the caller's when the dispatcher is.
				function(aggregate, "aggregate", attributable(name) || attributable(aggregate));
			}
		}
		if (child.GetExpressionClass() == ExpressionClass::BOUND_AGGREGATE) {
			auto &name = engine::FunctionName(child.Cast<BoundAggregateExpression>());
			function(name, "aggregate", attributable(name));
		}
		if (child.GetExpressionClass() == ExpressionClass::BOUND_WINDOW) {
			auto &window = child.Cast<BoundWindowExpression>();
			if (auto aggregate = engine::WindowAggregate(window)) {
				auto &name = engine::FunctionName(*aggregate);
				function(name, "aggregate", attributable(name));
			} else {
				static const std::map<ExpressionType, string> windows = {
				    {ExpressionType::WINDOW_ROW_NUMBER, "row_number"},
				    {ExpressionType::WINDOW_RANK, "rank"},
				    {ExpressionType::WINDOW_RANK_DENSE, "dense_rank"},
				    {ExpressionType::WINDOW_NTILE, "ntile"},
				    {ExpressionType::WINDOW_PERCENT_RANK, "percent_rank"},
				    {ExpressionType::WINDOW_CUME_DIST, "cume_dist"},
				    {ExpressionType::WINDOW_FIRST_VALUE, "first_value"},
				    {ExpressionType::WINDOW_LAST_VALUE, "last_value"},
				    {ExpressionType::WINDOW_LEAD, "lead"},
				    {ExpressionType::WINDOW_LAG, "lag"},
				    {ExpressionType::WINDOW_NTH_VALUE, "nth_value"},
				    {ExpressionType::WINDOW_FILL, "fill"}};
				auto found = windows.find(window.GetExpressionType());
				if (found == windows.end())
					throw BinderException("Unsupported bound window implementation");
				function(found->second, "window", attributable(found->second));
			}
		}
	}
}

void AuthorizePlan(const gatekeeper::Layers &layers, const gatekeeper::BindingPolicy &binding,
                   const gatekeeper::Provenance &provenance, LogicalOperator &root, gatekeeper::Result &result) {
	layers.Each(
	    [&](const gatekeeper::Policy &layer) { AuthorizePlanAgainst(layer, binding, provenance, root, result); });
}
} // namespace duckdb
