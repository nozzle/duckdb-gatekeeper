#include "validator.hpp"
#include <cstdlib>
#include <memory>
#include <stdexcept>

using namespace duckdb_yyjson;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size > 65536)
		return 0;
	std::unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> doc(
	    yyjson_read(reinterpret_cast<const char *>(data), size, 0), yyjson_doc_free);
	if (!doc)
		return 0;
	auto root = yyjson_doc_get_root(doc.get());
	try {
		gatekeeper::Policy policy;
		policy.schemas = true;
		policy.allowed_schemas.insert("public");
		policy.blocked_functions.insert("md5");
		auto ast = yyjson_obj_get(root, "ast");
		if (!ast)
			return 0;
		auto result = gatekeeper::Validate(ast, policy);
		if (result.allowed != (result.code == "ok") || (result.allowed && !result.violations.empty()))
			std::abort();
	} catch (const std::invalid_argument &) {
	}
	return 0;
}
