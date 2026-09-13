#include "validator.hpp"
#include <algorithm>
#include <cstdlib>
#include <memory>
#include <stdexcept>

using namespace duckdb_yyjson;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// Fixed prefix keeps policy mutations independent of the JSON document.
	if (size < 6 || size > 65536)
		return 0;
	std::unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> doc(
	    yyjson_read(reinterpret_cast<const char *>(data + 6), size - 6, 0), yyjson_doc_free);
	if (!doc)
		return 0;
	auto root = yyjson_doc_get_root(doc.get());
	try {
		gatekeeper::Policy policy;
		policy.functions = data[0] & 1;
		policy.defaults = policy.functions && (data[0] & 2);
		policy.catalogs = data[0] & 4;
		policy.schemas = data[0] & 8;
		policy.tables = data[0] & 16;
		policy.recursive = data[0] & 32;
		policy.table_functions = data[0] & 64;
		policy.dynamic_sql = data[0] & 128;
		policy.file_tables = data[1] & 1;
		if (data[1] & 2)
			policy.allowed_catalogs = {"memory", "system"};
		if (data[1] & 4)
			policy.allowed_schemas = {"main", "public"};
		if (data[1] & 8)
			policy.allowed_tables = {{"", "main", "t"}};
		if (data[1] & 64)
			policy.allowed_types = {{"system", "main", "json"}, {"", "main", "custom"}};
		if (data[1] & 16)
			policy.blocked_functions = {"md5", "read_csv"};
		if (policy.functions && (data[1] & 32))
			policy.allowed_functions = {"md5", "range", "query_table"};
		policy.nodes = data[2] ? data[2] : 100000;
		policy.depth = data[3] ? data[3] : 512;
		// These are Check()-level limits; the linked SQL harness exercises them.
		policy.bytes = data[4] ? data[4] : 8388608;
		policy.statements = data[5] ? data[5] : 1;
		auto ast = yyjson_obj_get(root, "ast");
		if (!ast)
			return 0;
		gatekeeper::BindingPolicy binding;
		auto result = gatekeeper::Validate(ast, policy, &binding);
		if ((result.code != "ok" && result.code != "forbidden" && result.code != "unsupported") ||
		    result.allowed != (result.code == "ok") || result.allowed != result.violations.empty() ||
		    !result.error_message.empty() || !result.error_type.empty())
			std::abort();
		gatekeeper::BindingPolicy again_binding;
		auto again = gatekeeper::Validate(ast, policy, &again_binding);
		if (binding.synthesized_functions != again_binding.synthesized_functions ||
		    binding.caller_types != again_binding.caller_types)
			std::abort();
		if (result.allowed != again.allowed || result.code != again.code || result.error_type != again.error_type ||
		    result.error_message != again.error_message || result.position != again.position ||
		    result.violations.size() != again.violations.size() ||
		    !std::equal(
		        result.violations.begin(), result.violations.end(), again.violations.begin(),
		        [](const gatekeeper::Violation &a, const gatekeeper::Violation &b) { return !(a < b) && !(b < a); }))
			std::abort();
		if (result.position >= 0 &&
		    std::none_of(result.violations.begin(), result.violations.end(),
		                 [&](const gatekeeper::Violation &v) { return v.position == result.position; }))
			std::abort();
	} catch (const std::invalid_argument &) {
	}
	return 0;
}
