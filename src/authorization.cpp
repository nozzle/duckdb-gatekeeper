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

static void AuthorizeFunction(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding,
                              const string &name, gatekeeper::Result &result) {
	auto canonical = gatekeeper::CanonicalFunction(name);
	if (gatekeeper::FunctionDenied(policy, name) ||
	    (binding.synthesized_functions.count(canonical) && !gatekeeper::FunctionAllowed(policy, canonical))) {
		result.violations.emplace("function", "resolved function is not allowed: " + canonical, "", "", "", canonical);
		throw PermissionException("resolved function is not allowed");
	}
}

void AuthorizeObject(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding, CatalogEntry &entry,
                     gatekeeper::Result &result) {
	switch (entry.type) {
	case CatalogType::SCALAR_FUNCTION_ENTRY:
	case CatalogType::AGGREGATE_FUNCTION_ENTRY:
	case CatalogType::TABLE_FUNCTION_ENTRY:
	case CatalogType::MACRO_ENTRY:
	case CatalogType::TABLE_MACRO_ENTRY:
	case CatalogType::PRAGMA_FUNCTION_ENTRY: {
		AuthorizeFunction(policy, binding, entry.name, result);
		auto &function = entry.Cast<StandardEntry>();
		if ((entry.type == CatalogType::TABLE_FUNCTION_ENTRY || entry.type == CatalogType::TABLE_MACRO_ENTRY) &&
		    binding.runtime_table_functions.count(gatekeeper::Lower(entry.name)) &&
		    (entry.type != CatalogType::TABLE_FUNCTION_ENTRY || function.schema.catalog.GetName() != "system" ||
		     function.schema.name != "main")) {
			result.violations.emplace("bind_time_expression",
			                          "runtime arguments require a system table-in-out function",
			                          function.schema.catalog.GetName(), function.schema.name, "", entry.name);
			throw PermissionException("untrusted table-in-out function");
		}
		if (binding.literal_constructors.count(gatekeeper::Lower(entry.name)) &&
		    (entry.type != CatalogType::SCALAR_FUNCTION_ENTRY || function.schema.catalog.GetName() != "system" ||
		     function.schema.name != "main")) {
			result.violations.emplace("bind_time_expression", "literal constructor must resolve to a system builtin",
			                          function.schema.catalog.GetName(), function.schema.name, "", entry.name);
			throw PermissionException("untrusted bind-time constructor");
		}
		string type = entry.type == CatalogType::SCALAR_FUNCTION_ENTRY      ? "scalar"
		              : entry.type == CatalogType::AGGREGATE_FUNCTION_ENTRY ? "aggregate"
		              : entry.type == CatalogType::TABLE_FUNCTION_ENTRY     ? "table"
		              : entry.type == CatalogType::MACRO_ENTRY              ? "macro"
		              : entry.type == CatalogType::TABLE_MACRO_ENTRY        ? "table_macro"
		                                                                    : "pragma";
		result.functions.insert({function.schema.catalog.GetName(), function.schema.name, entry.name, type});
		return;
	}
	default:
		break;
	}
	if (entry.type != CatalogType::TABLE_ENTRY && entry.type != CatalogType::VIEW_ENTRY)
		return;
	auto &object = entry.Cast<StandardEntry>();
	auto catalog = object.schema.catalog.GetName(), schema = object.schema.name, name = object.name;
	if (!gatekeeper::TableAllowed(policy, catalog, schema, name, entry.internal)) {
		if (gatekeeper::TableBlocked(policy, catalog, schema, name))
			result.violations.emplace("table", "object is blocked", catalog, schema, name);
		else if (entry.internal)
			result.violations.emplace("internal_object", "internal object requires exact schema/table permission",
			                          catalog, schema, name);
		else
			result.violations.emplace("table", "object is not allowed", catalog, schema, name);
	}
	if (!result.violations.empty())
		throw PermissionException("resolved object is not allowed");
	result.objects.insert({catalog, schema, name, entry.type == CatalogType::TABLE_ENTRY ? "table" : "view"});
}

// ListAggregatesBindData is private to core_functions. Its reviewed serialization callback exposes
// the actual bound aggregate without unsafe layout casts, evaluating arguments, or rebinding names.
// Inspect only this documented shape, never arbitrary JSON payloads that can resemble expressions.
static string ListAggregateImplementation(BoundFunctionExpression &expression) {
	auto null_input =
	    !expression.children.empty() && expression.children[0]->return_type.id() == LogicalTypeId::SQLNULL;
	// These builtins use the fixed histogram implementation and have no serialization callbacks.
	if (expression.function.name == "list_distinct" || expression.function.name == "list_unique" ||
	    expression.function.name == "array_distinct" || expression.function.name == "array_unique")
		return null_input ? "" : "histogram";
	static const gatekeeper::Names names = {"aggregate", "array_aggr", "array_aggregate", "list_aggr",
	                                        "list_aggregate"};
	if (!names.count(expression.function.name))
		return {};
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

void AuthorizePlan(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding, LogicalOperator &root,
                   gatekeeper::Result &result) {
	auto function = [&](const string &name, const string &type) {
		AuthorizeFunction(policy, binding, name, result);
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
		if (op->type == LogicalOperatorType::LOGICAL_GET && op->Cast<LogicalGet>().function.name != "seq_scan")
			function(op->Cast<LogicalGet>().function.name, "table");
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
			function("unnest", "scalar");
		if (child.GetExpressionClass() == ExpressionClass::BOUND_FUNCTION) {
			auto &bound = child.Cast<BoundFunctionExpression>();
			function(bound.function.name, "scalar");
			if (auto lambda = dynamic_cast<ListLambdaBindData *>(bound.bind_info.get())) {
				if (lambda->lambda_expr)
					expressions.push_back(lambda->lambda_expr.get());
			}
			auto aggregate = ListAggregateImplementation(bound);
			if (!aggregate.empty())
				function(aggregate, "aggregate");
		}
		if (child.GetExpressionClass() == ExpressionClass::BOUND_AGGREGATE)
			function(child.Cast<BoundAggregateExpression>().function.name, "aggregate");
		if (child.GetExpressionClass() == ExpressionClass::BOUND_WINDOW) {
			auto &window = child.Cast<BoundWindowExpression>();
			if (window.aggregate)
				function(window.aggregate->name, "aggregate");
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
				function(found->second, "window");
			}
		}
	}
}
} // namespace duckdb
