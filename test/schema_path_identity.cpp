#include "function_policy.hpp"
#include "validator.hpp"
#include <cstdlib>

static void Check(bool condition) {
	if (!condition)
		std::abort();
}

int main() {
	using namespace gatekeeper;
	Policy functions;
	Check(FunctionAllowed(functions, {"system", {"main"}, "abs", "scalar"}));
	Check(!FunctionAllowed(functions, {"system", {"main"}, "abs", "table"}));
	Check(!FunctionAllowed(functions, {"system", {"main"}, "abs", "macro"}));
	Check(!FunctionAllowed(functions, {"memory", {"main"}, "abs", "scalar"}));
	Check(!FunctionAllowed(functions, {"", {}, "abs", "scalar"}));
	functions.defaults = false;
	functions.allowed_functions = {{"", {"finance", "*"}, "f", "scalar"},
	                               {"system", {"main"}, "*", "scalar"},
	                               {"system", {"main"}, "read_parquet", "table"}};
	Check(FunctionEligible(functions, "f"));
	Check(FunctionAllowed(functions, {"lake", {"finance", "reports"}, "f", "scalar"}));
	Check(!FunctionAllowed(functions, {"lake", {"finance", "reports"}, "f", "table"}));
	Check(!FunctionAllowed(functions, {"lake", {"finance", "reports", "deep"}, "f", "scalar"}));
	Check(!FunctionAllowed(functions, {"lake", {"finance.reports"}, "f", "scalar"}));
	Check(FunctionAllowed(functions, {"system", {"main"}, "*", "scalar"}));
	Check(!FunctionAllowed(functions, {"system", {"main"}, "abs", "scalar"}));
	Check(FunctionAllowed(functions, {"system", {"main"}, "parquet_scan", "table"}));
	Check(!FunctionAllowed(functions, {"memory", {"main"}, "parquet_scan", "table"}));
	functions.allowed_functions.insert({"memory", {"main"}, "read_parquet", ""});
	Check(!FunctionAllowed(functions, {"memory", {"main"}, "parquet_scan", "table"}));
	functions.allowed_functions.insert({"", {"finance", "reports"}, "f", ""});
	Check(FunctionAllowed(functions, {"lake", {"finance", "reports"}, "f", "table"}));
	functions.blocked_functions.insert({"system", {"main"}, "parquet_scan", "table"});
	Check(!FunctionAllowed(functions, {"system", {"main"}, "read_parquet", "table"}));
	functions.allowed_functions.insert({"*", {"*"}, "nextval", ""});
	Check(!FunctionEligible(functions, "nextval"));
	Policy blocks;
	blocks.defaults = false;
	blocks.allowed_functions = {{"*", {"a", "*"}, "f", ""}};
	blocks.blocked_functions = {{"*", {"a", "b"}, "f", ""}};
	Check(FunctionEligible(blocks, "f"));
	Check(!FunctionAllowed(blocks, {"host", {"a", "b"}, "f", "scalar"}));
	Check(FunctionAllowed(blocks, {"host", {"a", "c"}, "f", "scalar"}));
	Check(!FunctionBlocked(blocks, {"host", {"a", "b", "c"}, "f", "scalar"}));
	Check(!FunctionAllowed(blocks, {"", {}, "f", "scalar"}));
	blocks.blocked_functions.clear();
	for (const auto &kind : {"scalar", "aggregate", "table", "macro", "table_macro", "window"})
		blocks.blocked_functions.insert({"*", {"a", "*"}, "f", kind});
	Check(!FunctionEligible(blocks, "f"));
	blocks.allowed_functions.insert({"other", {"a", "*", "*"}, "f", "scalar"});
	Check(FunctionEligible(blocks, "f")); // A one-depth block cannot suppress a deeper eligible identity.
	Policy policy;
	policy.tables = true;
	policy.allowed_tables = {{"memory", {"finance", "*"}, "orders"}};
	Check(TableAllowed(policy, "MEMORY", {"FINANCE", "Reports"}, "ORDERS"));
	Check(!TableAllowed(policy, "memory", {"sales", "reports"}, "orders"));
	Check(!TableAllowed(policy, "memory", {"finance", "reports", "monthly"}, "orders"));
	Check(!TableAllowed(policy, "memory", {"finance.reports"}, "orders"));
	Check(!TableAllowed(policy, "memory", {"finance", "reports"}, "orders", true));
	policy.allowed_tables.insert({"memory", {"finance", "reports"}, "orders"});
	Check(TableAllowed(policy, "memory", {"finance", "reports"}, "orders", true));
	policy.blocked_tables.insert({"*", {"*", "reports"}, "*"});
	Check(!TableAllowed(policy, "memory", {"finance", "reports"}, "orders", true));

	WrittenNames names{{"finance", "reports", "orders"}};
	Check(NamesObject(names, "memory", {"finance", "reports"}, "orders"));
	Check(!NamesObject(names, "memory", {"sales", "reports"}, "orders"));
	Check(!NamesObject(names, "memory", {"finance.reports"}, "orders"));
	Check(NamesObject(names, "finance", {"reports"}, "orders"));
	Check(NamesObject({{"orders"}}, "memory", {"finance", "reports"}, "orders"));
	Check(NamesObject({{"memory", "orders"}}, "memory", {"main"}, "orders"));
	Check(NamesObject({{"memory", "", "orders"}}, "memory", {"main"}, "orders"));
	Check(!NamesObject({{"lake", "", "orders"}}, "memory", {"main"}, "orders"));
	Check(!NamesObject({{"a", "b", "c", "orders"}}, "memory", {"c"}, "orders"));
	Check(!NamesObject({{"memory", "finance", "reports", "orders"}}, "lake", {"finance", "reports"}, "orders"));

	Provenance provenance;
	auto finance = ObjectKey("memory", {"finance", "reports"}, "orders");
	auto sales = ObjectKey("memory", {"sales", "reports"}, "orders");
	provenance.caller_objects.insert(finance);
	provenance.trusted_objects.insert(sales);
	provenance.validated_scans[finance] = 1;
	provenance.validated_scans[sales] = 2;
	Check(provenance.validated_scans.size() == 2 && provenance.validated_scans[finance] == 1);
	Check(provenance.ObjectAttributable({}, "memory", {"finance", "reports"}, "orders"));
	Check(!provenance.ObjectAttributable({}, "memory", {"sales", "reports"}, "orders"));
	BindingPolicy binding;
	binding.caller_table_names.insert({"sales", "reports", "orders"});
	Check(provenance.ObjectAttributable(binding, "memory", {"sales", "reports"}, "orders"));
}
