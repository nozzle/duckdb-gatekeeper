#include "validator.hpp"
#include <iostream>
#include <iterator>
#include <memory>

// Runs the grammar walk over a serialized AST read from stdin, with md5 and list_value blocked, and prints the
// result code followed by one line per violation: rule, function name and position, tab-separated.
int main() {
	std::string text(std::istreambuf_iterator<char>(std::cin), {});
	using namespace duckdb_yyjson;
	std::unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> doc(yyjson_read(text.data(), text.size(), 0),
	                                                            yyjson_doc_free);
	if (!doc)
		return 1;
	gatekeeper::Policy policy;
	policy.blocked_functions = {"md5", "list_value"};
	gatekeeper::BindingPolicy binding;
	auto result = gatekeeper::Validate(yyjson_doc_get_root(doc.get()), policy, &binding);
	std::cout << result.code;
	for (const auto &violation : result.violations)
		std::cout << '\n' << violation.rule << '\t' << violation.function_name << '\t' << violation.position;
}
