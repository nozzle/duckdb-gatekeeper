#pragma once
#include "duckdb/catalog/catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/aggregate_function_catalog_entry.hpp"

static CatalogEntry &SystemProbeEntry(Connection &connection, CatalogType type, const string &name) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	return Catalog::GetEntry(*connection.context, type, QualifiedName("system", "main", Identifier(name)));
#else
	return Catalog::GetEntry(*connection.context, type, "system", "main", name);
#endif
}

static void CheckDefaultOriginAndPreflight(Connection &connection) {
	Query(connection, "CALL gatekeeper_configure(); BEGIN");
	auto &abs = SystemProbeEntry(connection, CatalogType::SCALAR_FUNCTION_ENTRY, "abs");
	const bool was_internal = abs.internal;
	abs.internal = false;
	Query(connection, "COMMIT");
	// Native metadata mutation is trusted setup, not an attacker capability. Ordinary
	// creation forbids non-internal system entries; this probes consistent flag handling.
	if (Cell(connection, "SELECT allowed FROM gatekeeper_validate('SELECT abs(1)')").GetValue<bool>())
		std::exit(66);
	for (const auto &schema : {"main", "*"}) {
		Query(connection, string("CALL gatekeeper_configure(allowed_functions := [{schema_path:['") + schema +
		                      "'],name:'abs',type:'scalar'}])");
		if (!Cell(connection, "SELECT allowed FROM gatekeeper_validate('SELECT abs(1)')").GetValue<bool>())
			std::exit(67);
	}
	abs.internal = was_internal;
	Query(connection, "CALL gatekeeper_configure(); BEGIN");
	auto &sum = SystemProbeEntry(connection, CatalogType::AGGREGATE_FUNCTION_ENTRY, "sum")
	                .Cast<AggregateFunctionCatalogEntry>();
	Query(connection, "COMMIT");
	// Replace the bind callback temporarily so a denied fixed target has an observable
	// bind-time effect if preflight mistakenly lets it run. Restore every descriptor.
	auto saved = sum.functions.functions;
	for (auto &overload : sum.functions.functions) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
		auto replacement = make_shared_ptr<AggregateFunction>(*overload);
		replacement->SetBindCallback(BindAggregateProbe);
		overload = std::move(replacement);
#else
		overload.SetBindCallback(BindAggregateProbe);
#endif
	}
	for (bool ceiling : {false, true}) {
		const string block = "[{schema_path:['*'],name:'sum',type:'aggregate'}]";
		Query(connection, "CALL gatekeeper_configure(" + (ceiling ? "blocked_functions := " + block : string()) + ")");
		aggregate_binds = 0;
		auto result = Cell(connection, "SELECT code='forbidden' AND violations[1].function_name='sum' AND "
		                               "violations[1].message='default macro aggregate is not allowed' "
		                               "FROM gatekeeper_validate('SELECT list_sum([1])', blocked_functions := " +
		                                   (ceiling ? "[]" : block) + ")");
		if (!result.GetValue<bool>() || aggregate_binds != 0)
			std::exit(68);
	}
	Query(connection, "CALL gatekeeper_configure()");
	aggregate_binds = 0;
	Cell(connection, "SELECT allowed FROM gatekeeper_validate('SELECT list_sum([1])')");
	if (aggregate_binds == 0)
		std::exit(70); // Positive control: this target really invokes the installed callback.
	sum.functions.functions = std::move(saved);
	aggregate_binds = 0;
	for (const auto &name : {"min", "max"}) {
		const string dependency = string("arg_") + name;
		Query(connection, "CALL gatekeeper_configure(allowed_functions := "
		                  "[{schema_path:['main'],name:'" +
		                      dependency + "',type:'aggregate'}]); BEGIN");
		auto &target = SystemProbeEntry(connection, CatalogType::AGGREGATE_FUNCTION_ENTRY, dependency);
		const bool internal = target.internal;
		target.internal = false;
		Query(connection, "COMMIT");
		if (!Cell(connection, "SELECT code='forbidden' AND violations[1].catalog='system' AND "
		                      "violations[1].schema_path=['main'] AND violations[1].function_name='" +
		                          dependency +
		                          "' AND violations[1].function_type='aggregate' FROM gatekeeper_validate('SELECT " +
		                          name + "(1)')")
		         .GetValue<bool>())
			std::exit(69);
		target.internal = internal;
	}
	Query(connection, "CALL gatekeeper_configure()");
}

// Included by qualified_function_probe.cpp after its shared native callbacks.
// Native registration is essential here: SQL-created macros cannot choose internal=true.
static void CheckInternalFunctions(Connection &connection, DuckDB &database) {
	CheckDefaultOriginAndPreflight(connection);
	Query(connection, "CREATE SCHEMA InTeRnAl_CaSeS; ATTACH ':memory:' AS MiXeD_CaTaLoG; "
	                  "CREATE SCHEMA MiXeD_CaTaLoG.InTeRnAl_CaSeS");
	for (const auto &catalog : {"memory", "system", "MiXeD_CaTaLoG"}) {
		const string schema = string(catalog) != "system" ? "InTeRnAl_CaSeS" : "main";
		Query(connection, "BEGIN");
		if (string(catalog) != "system")
			Query(connection, "CREATE TABLE " + string(catalog) + ".internal_cases.registration_marker(i INTEGER)");
		for (bool internal : {false, true}) {
			// DuckDB disallows internal=true registrations outside the system catalog.
			if (internal && string(catalog) != "system")
				continue;
			const auto name = internal ? "OrIgIn_InTeRnAl" : "OrIgIn_ExTeRnAl";
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
				if (expected && !Cell(connection, "SELECT functions[1].name = '" +
				                                      string(internal ? "OrIgIn_InTeRnAl" : "OrIgIn_ExTeRnAl") +
				                                      "' FROM gatekeeper_validate('" + sql + "')")
				                     .GetValue<bool>())
					std::exit(65); // Provenance keys must not lowercase the displayed catalog entry.
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
