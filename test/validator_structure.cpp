#include "validator.hpp"
#include <iostream>
#include <iterator>
#include <memory>

int main() {
	std::string text(std::istreambuf_iterator<char>(std::cin), {});
	using namespace duckdb_yyjson;
	std::unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> doc(yyjson_read(text.data(), text.size(), 0),
	                                                            yyjson_doc_free);
	if (!doc)
		return 1;
	gatekeeper::Policy policy;
	policy.blocked_functions = {"md5"};
	auto result = gatekeeper::Validate(yyjson_doc_get_root(doc.get()), policy);
	std::cout << result.code;
}
