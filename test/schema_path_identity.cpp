#include "validator.hpp"
#include <cstdlib>

static void Check(bool condition) {
	if (!condition)
		std::abort();
}

int main() {
	using namespace gatekeeper;
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
