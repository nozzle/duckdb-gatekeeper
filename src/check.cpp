#include "check.hpp"
#include "authorization.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "json_serializer.hpp"

namespace duckdb {
using namespace duckdb_yyjson;

TextCheck CheckText(ClientContext &context, const gatekeeper::Policy &policy, const gatekeeper::Policy &ceiling,
                    const string &sql, const gatekeeper::Limits &limits) {
	TextCheck check;
	if (sql.find('\0') != string::npos)
		throw InvalidInputException("SQL contains a NUL byte");
	if (sql.size() > limits.bytes) {
		check.result = {false, "forbidden", "", "", {{"limit", "SQL exceeds fixed input size limit"}}};
		return check;
	}
	Parser parser(context.GetParserOptions());
	parser.ParseQuery(sql);
	if (parser.statements.empty())
		throw InvalidInputException("SQL contains no statements");
	if (parser.statements.size() > gatekeeper::MAX_STATEMENTS) {
		check.result = {false, "forbidden", "", "", {{"limit", "statement count exceeds fixed limit"}}};
		return check;
	}
	unique_ptr<yyjson_mut_doc, decltype(&yyjson_mut_doc_free)> doc(yyjson_mut_doc_new(nullptr), yyjson_mut_doc_free);
	if (!doc)
		throw std::bad_alloc();
	auto root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);
	yyjson_mut_obj_add_false(doc.get(), root, "error");
	auto statements = yyjson_mut_arr(doc.get());
	yyjson_mut_obj_add_val(doc.get(), root, "statements", statements);
	SerializationOptions serialization_options;
	serialization_options.serialization_compatibility = SerializationCompatibility::Latest();
	for (auto &statement : parser.statements) {
		if (statement->type != StatementType::SELECT_STATEMENT) {
			check.result = {
			    false, "unsupported", "", "", {{"statement", "only supported read statements are permitted"}}};
			return check;
		}
		yyjson_mut_arr_append(statements, JsonSerializer::Serialize(statement->Cast<SelectStatement>(), doc.get(), true,
		                                                            true, true, serialization_options));
	}
	unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> ast(yyjson_mut_doc_imut_copy(doc.get(), nullptr),
	                                                       yyjson_doc_free);
	if (!ast)
		throw std::bad_alloc();
	size_t bytes = 0;
	unique_ptr<char, decltype(&free)> serialized(yyjson_write(ast.get(), 0, &bytes), free);
	if (!serialized)
		throw std::bad_alloc();
	if (bytes > limits.bytes) {
		check.result = {false, "forbidden", "", "", {{"limit", "serialized AST exceeds fixed size limit"}}};
		return check;
	}
	check.result = gatekeeper::Validate(yyjson_doc_get_root(ast.get()), policy, &check.binding, &ceiling, limits);
	if (check.result.allowed)
		check.statements = std::move(parser.statements);
	return check;
}

void CheckPlan(const gatekeeper::Policy &policy, const gatekeeper::Policy &ceiling,
               const gatekeeper::BindingPolicy &binding, LogicalOperator &plan, gatekeeper::Result &result) {
	AuthorizePlan(ceiling, binding, plan, result);
	AuthorizePlan(policy, binding, plan, result);
}
} // namespace duckdb
