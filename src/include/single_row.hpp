#pragma once
#include "duckdb/function/table_function.hpp"

namespace duckdb {
// Global state of the SQL surface's one-row table functions (gatekeeper_validate, gatekeeper_configure,
// gatekeeper_enforce): each produces its row on the first call and nothing afterwards.
struct SingleRowState : GlobalTableFunctionState {
	bool finished = false;
};

inline unique_ptr<GlobalTableFunctionState> InitSingleRow(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<SingleRowState>();
}
} // namespace duckdb
