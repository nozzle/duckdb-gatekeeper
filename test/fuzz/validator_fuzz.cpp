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
		policy.defaults = data[0] & 2;
		policy.tables = data[0] & 16;
		policy.replacement_scans = data[1] & 1;
		if (data[1] & 2)
			policy.allowed_tables.insert({"memory", "*", "*"});
		if (data[1] & 4)
			policy.allowed_tables.insert({"*", "main", "*"});
		if (data[1] & 8)
			policy.allowed_tables.insert({"", "main", "t"});
		if (data[1] & 16)
			policy.blocked_functions = {"md5", "read_csv"};
		if (data[1] & 32)
			policy.allowed_functions = {"md5", "range", "query_table"};
		// Statement counts are checked by the linked SQL harness.
		policy.statements = data[5] ? data[5] : 1;
		auto ast = yyjson_obj_get(root, "ast");
		if (!ast)
			return 0;
		gatekeeper::BindingPolicy binding;
		auto result = gatekeeper::Validate(ast, policy, &binding);
		gatekeeper::Policy ceiling;
		ceiling.defaults = data[4] & 1;
		ceiling.blocked_functions = {"abs", "md5"};
		auto layered = gatekeeper::Validate(ast, policy, nullptr, &ceiling);
		if (layered.allowed && (!result.allowed || !gatekeeper::Validate(ast, ceiling).allowed))
			std::abort();
		if ((result.code != "ok" && result.code != "forbidden" && result.code != "unsupported") ||
		    result.allowed != (result.code == "ok") || result.allowed != result.violations.empty() ||
		    !result.error_message.empty() || !result.error_type.empty())
			std::abort();
		gatekeeper::BindingPolicy again_binding;
		auto again = gatekeeper::Validate(ast, policy, &again_binding);
		if (binding.synthesized_functions != again_binding.synthesized_functions ||
		    binding.literal_constructors != again_binding.literal_constructors ||
		    binding.runtime_table_functions != again_binding.runtime_table_functions)
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
