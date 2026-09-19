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
static bool SystemBuiltin(const string &catalog, const string &schema) {
	return catalog == "system" && schema == "main";
}

// Function policy, the never-bind list included, holds for names attributable to the caller; a trusted
// definition's own functions are outside it, with one exception: Gatekeeper's own control plane is refused on
// every route. The query-wide allowlist check for ambiguous caller syntax holds for the implementation DuckDB
// selects wherever it selects it, as documented.
static void AuthorizeFunction(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding,
                              const string &name, bool attributable, gatekeeper::Result &result) {
	auto canonical = gatekeeper::CanonicalFunction(name);
	if (gatekeeper::ControlPlane(name) || (attributable && gatekeeper::FunctionDenied(policy, name)) ||
	    (binding.synthesized_functions.count(canonical) && !gatekeeper::FunctionAllowed(policy, canonical))) {
		result.violations.emplace(gatekeeper::rules::FUNCTION, "resolved function is not allowed: " + canonical, "", "",
		                          "", canonical);
		throw PermissionException("resolved function is not allowed");
	}
}

void AuthorizeObject(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding, CatalogEntry &entry,
                     gatekeeper::Result &result, bool attributable) {
	if (auto kind = FunctionKind(entry.type)) {
		AuthorizeFunction(policy, binding, entry.name, attributable, result);
		auto &function = entry.Cast<StandardEntry>();
		auto catalog = function.schema.catalog.GetName(), schema = function.schema.name;
		bool builtin = SystemBuiltin(catalog, schema);
		if ((entry.type == CatalogType::TABLE_FUNCTION_ENTRY || entry.type == CatalogType::TABLE_MACRO_ENTRY) &&
		    binding.runtime_table_functions.count(gatekeeper::Lower(entry.name)) &&
		    (entry.type != CatalogType::TABLE_FUNCTION_ENTRY || !builtin)) {
			result.violations.emplace(gatekeeper::rules::BIND_TIME_EXPRESSION,
			                          "runtime arguments require a system table-in-out function", catalog, schema, "",
			                          entry.name);
			throw PermissionException("untrusted table-in-out function");
		}
		if (binding.literal_constructors.count(gatekeeper::Lower(entry.name)) &&
		    (entry.type != CatalogType::SCALAR_FUNCTION_ENTRY || !builtin)) {
			result.violations.emplace(gatekeeper::rules::BIND_TIME_EXPRESSION,
			                          "literal constructor must resolve to a system builtin", catalog, schema, "",
			                          entry.name);
			throw PermissionException("untrusted bind-time constructor");
		}
		result.functions.insert({catalog, schema, entry.name, kind});
		return;
	}
	if (entry.type != CatalogType::TABLE_ENTRY && entry.type != CatalogType::VIEW_ENTRY)
		return;
	auto &object = entry.Cast<StandardEntry>();
	auto catalog = object.schema.catalog.GetName(), schema = object.schema.name, name = object.name;
	if (!gatekeeper::TableAllowed(policy, catalog, schema, name, entry.internal)) {
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
	result.objects.insert({catalog, schema, name, entry.type == CatalogType::TABLE_ENTRY ? "table" : "view"});
}

// ListAggregatesBindData is private to core_functions. Its reviewed serialization callback exposes
// the actual bound aggregate without unsafe layout casts, evaluating arguments, or rebinding names.
// Inspect only this documented shape, never arbitrary JSON payloads that can resemble expressions.
static string ListAggregateImplementation(BoundFunctionExpression &expression) {
	// Name-selected dispatchers plus the builtins with a fixed histogram implementation.
	static const gatekeeper::Names fixed = {"list_distinct", "list_unique", "array_distinct", "array_unique"};
	if (!gatekeeper::DispatchingAggregators().count(expression.function.name) && !fixed.count(expression.function.name))
		return {};
	// Catalog construction stamps this provenance onto each overload and binding preserves it.
	// A matching leaf name alone does not authorize inspecting a foreign implementation's bind data.
	if (!SystemBuiltin(expression.function.catalog_name, expression.function.schema_name))
		throw BinderException("List aggregate implementation is not the pinned builtin");
	auto null_input =
	    !expression.children.empty() && expression.children[0]->return_type.id() == LogicalTypeId::SQLNULL;
	// These builtins use the fixed histogram implementation and have no serialization callbacks.
	if (fixed.count(expression.function.name))
		return null_input ? "" : "histogram";
	if (!expression.bind_info)
		throw BinderException("List aggregate requires resolved parameter types");
	if (!expression.function.HasSerializationCallbacks())
		throw BinderException("Cannot inspect list aggregate implementation");
	unique_ptr<yyjson_mut_doc, decltype(&yyjson_mut_doc_free)> doc(yyjson_mut_doc_new(nullptr), yyjson_mut_doc_free);
	if (!doc)
		throw std::bad_alloc();
	SerializationOptions options;
	options.serialization_compatibility = SerializationCompatibility::Latest();
	JsonSerializer serializer(doc.get(), false, false, false, options);
	expression.function.GetSerializeCallback()(serializer, expression.bind_info.get(), expression.function);
	auto data = yyjson_mut_obj_get(serializer.GetRootObject(), "bind_data");
	// A NULL-list input uses VariableReturnBindData and carries no executable aggregate.
	if (!data || yyjson_mut_is_null(data)) {
		if (null_input)
			return {};
		throw BinderException("Missing list aggregate bind data");
	}
	auto aggregate = yyjson_mut_obj_get(data, "aggr_expr");
	auto kind = yyjson_mut_obj_get(aggregate, "expression_class");
	auto name = yyjson_mut_obj_get(aggregate, "name");
	if (!yyjson_mut_is_str(kind) || string(yyjson_mut_get_str(kind)) != "BOUND_AGGREGATE" || !yyjson_mut_is_str(name) ||
	    !yyjson_mut_get_len(name))
		throw BinderException("Unsupported list aggregate bind data");
	return string(yyjson_mut_get_str(name), yyjson_mut_get_len(name));
}

void AuthorizePlan(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding,
                   const gatekeeper::Provenance &provenance, LogicalOperator &root, gatekeeper::Result &result) {
	auto attributable = [&](const string &name) { return provenance.Attributable(binding, name); };
	auto function = [&](const string &name, const string &type, bool callers) {
		AuthorizeFunction(policy, binding, name, callers, result);
		for (const auto &entry : result.functions)
			if (entry.name == name && entry.type == type)
				return;
		// Bound implementations do not provide reliable catalog provenance.
		result.functions.insert({"", "", name, type});
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
			// A scan with a table entry is an attached catalog reading a table the policy allowed: the reader it
			// uses internally (iceberg_scan, ducklake_scan) is that catalog's, never the caller's.
			if (get.function.name != "seq_scan")
				function(get.function.name, "table", !get.GetTable() && attributable(get.function.name));
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
			function(bound.function.name, "scalar", attributable(bound.function.name));
			auto lambda = dynamic_cast<ListLambdaBindData *>(bound.bind_info.get());
			// The system list-lambda builtins always carry ListLambdaBindData, and the lambda body it holds is
			// executable code that blocks must reach. A distributed loadable performs this cast across the
			// host/extension boundary; if it ever fails there, refuse rather than silently skip the body.
			if (!lambda && gatekeeper::ListLambdaFunctions().count(bound.function.name) &&
			    SystemBuiltin(bound.function.catalog_name, bound.function.schema_name))
				throw BinderException("Cannot inspect list lambda implementation");
			if (lambda && lambda->lambda_expr)
				expressions.push_back(lambda->lambda_expr.get());
			auto aggregate = ListAggregateImplementation(bound);
			if (!aggregate.empty()) {
				// A caller-written dispatcher selects its aggregate by name, so that target is caller-chosen and
				// must be allowed, not merely unblocked. Fixed implementations (list_distinct's histogram) and
				// dispatchers introduced only by trusted views or macros keep the block-only treatment. Any
				// caller-written dispatcher triggers the check query-wide, like other ambiguous caller syntax.
				if (!binding.caller_dispatchers.empty() &&
				    gatekeeper::DispatchingAggregators().count(bound.function.name) &&
				    !gatekeeper::FunctionAllowed(policy, aggregate)) {
					auto canonical = gatekeeper::CanonicalFunction(aggregate);
					result.violations.emplace(gatekeeper::rules::FUNCTION,
					                          "dispatched aggregate is not allowed: " + canonical, "", "", "",
					                          canonical);
					throw PermissionException("dispatched aggregate is not allowed");
				}
				// The dispatched aggregate is the dispatcher's: the caller's when the dispatcher is.
				function(aggregate, "aggregate", attributable(bound.function.name) || attributable(aggregate));
			}
		}
		if (child.GetExpressionClass() == ExpressionClass::BOUND_AGGREGATE) {
			auto &name = child.Cast<BoundAggregateExpression>().function.name;
			function(name, "aggregate", attributable(name));
		}
		if (child.GetExpressionClass() == ExpressionClass::BOUND_WINDOW) {
			auto &window = child.Cast<BoundWindowExpression>();
			if (window.aggregate)
				function(window.aggregate->name, "aggregate", attributable(window.aggregate->name));
			else {
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
} // namespace duckdb
