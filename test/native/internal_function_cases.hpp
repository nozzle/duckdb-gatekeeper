#pragma once
#include "duckdb/catalog/catalog_entry.hpp"

// Included by qualified_function_probe.cpp after its shared native callbacks.
// Native registration is essential here: SQL-created macros cannot choose internal=true.
static void CheckInternalFunctions(Connection &connection, DuckDB &database) {
	Query(connection, "CREATE SCHEMA internal_cases");
	for (const auto &catalog : {"memory", "system"}) {
		const string schema = string(catalog) == "memory" ? "internal_cases" : "main";
		Query(connection, "BEGIN");
		if (string(catalog) == "memory")
			Query(connection, "CREATE TABLE internal_cases.registration_marker(i INTEGER)");
		for (bool internal : {false, true}) {
			// DuckDB disallows internal=true registrations outside the system catalog.
			if (internal && string(catalog) != "system")
				continue;
			const auto name = internal ? "origin_internal" : "origin_external";
			CreateScalarFunctionInfo info(ScalarFunction(name, {}, LogicalType::DOUBLE, FractionProbe));
			// Ordinary catalog creation forbids non-internal system entries. The native
			// fixture changes the actual flag afterwards to prove policy reads the entry,
			// rather than treating system.main as a proxy for internal.
			info.internal = string(catalog) == "system";
#if GATEKEEPER_DUCKDB_MAJOR >= 2
			info.SetQualifiedName(QualifiedName(Identifier(catalog), Identifier(schema), Identifier(name)));
#else
			info.catalog = catalog;
			info.schema = schema;
#endif
			auto entry = Catalog::GetCatalog(*connection.context, catalog).CreateFunction(*connection.context, info);
			entry->internal = internal;
		}
		Query(connection, "COMMIT");
		for (bool internal : {false, true}) {
			if (internal && string(catalog) != "system")
				continue;
			const string name = internal ? "origin_internal" : "origin_external";
			const auto sql = "SELECT " + string(catalog) + "." + schema + "." + name + "()";
			for (const auto &pattern : {"*", schema.c_str()}) {
				const bool expected = !internal || string(pattern) == schema;
				Query(connection, "CALL gatekeeper_configure(use_default_functions := false, allowed_functions := "
				                  "[{catalog:'*',schema_path:['" +
				                      string(pattern) + "'],name:'" + name + "',type:'scalar'}])");
				if (Cell(connection, "SELECT allowed FROM gatekeeper_validate('" + sql + "')").GetValue<bool>() !=
				    expected)
					std::exit(60);
				Connection agent(database);
				auto held = agent.Prepare(sql);
				if (held->HasError())
					std::exit(61);
				Query(agent, "CALL gatekeeper_enforce()");
				if (held->Execute()->HasError() == expected || agent.Query(sql)->HasError() == expected)
					std::exit(62);
			}
			// Even internal functions are trusted when introduced only by an admitted host body.
			Query(connection, "CREATE OR REPLACE MACRO internal_cases.wrapper() AS " + string(catalog) + "." + schema +
			                      "." + name + "()");
			Query(connection, "CALL gatekeeper_configure(use_default_functions := false, allowed_functions := "
			                  "[{catalog:'memory',schema_path:['*'],name:'wrapper',type:'macro'}], "
			                  "blocked_functions := [{schema_path:['*'],name:'" +
			                      name + "'}])");
			if (!Cell(connection, "SELECT allowed FROM gatekeeper_validate('SELECT internal_cases.wrapper()')")
			         .GetValue<bool>())
				std::exit(63);
		}
	}
	// A retained native definition does not prove an arbitrary callback replacement's
	// internal flag. Unknown origin cannot satisfy schema patterns on 2.0; 1.5 refuses
	// the callback before invocation. An exact target rule remains explicitly grantable.
	change_namespace = true;
	Query(connection, "CALL gatekeeper_configure(allowed_functions := "
	                  "[{catalog:'memory',schema_path:['origins'],name:'scalar_rename',type:'scalar'},"
	                  "{catalog:'memory',schema_path:['*'],name:'g',type:'scalar'}])");
	if (Cell(connection, "SELECT allowed FROM gatekeeper_validate('SELECT origins.scalar_rename()')").GetValue<bool>())
		std::exit(64);
	change_namespace = false;
	Query(connection, "CALL gatekeeper_configure()");
}
