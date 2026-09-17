#include "pragma_guard.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/function/pragma_function.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/extension_callback_manager.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/parsed_data/create_pragma_function_info.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parser_extension.hpp"
#include "duckdb/parser/statement/pragma_statement.hpp"

namespace duckdb {

static constexpr const char *REJECTED_PRAGMA = "gatekeeper_rejected_pragma";

// DuckDB's statement preprocessor evaluates PRAGMA argument expressions while parsing, before any
// extension hook runs (docs/security.md#residuals). The parser override is the only extension point in
// front of it. It receives text and parser options, never a connection, so what it does applies to
// every connection on the instance.

static bool ConstantArguments(const PragmaInfo &info) {
	for (auto &parameter : info.parameters)
		if (parameter->GetExpressionClass() != ExpressionClass::CONSTANT)
			return false;
	for (auto &entry : info.named_parameters)
		if (entry.second->GetExpressionClass() != ExpressionClass::CONSTANT)
			return false;
	return true;
}

// Parses with the engine parser (the override disabled on a copy of the options, so this never
// re-enters itself), then replaces each PRAGMA whose arguments are not constants with a call to the
// rejecting pragma, carrying the original name for the error. Everything else, parse errors included,
// is handed back to the engine: DISPLAY_ORIGINAL_ERROR makes it parse the text itself and report its
// own error, under fallback and strict alike. The engine parser has already stamped statement text and
// locations on the statements returned here.
static ParserOverrideResult GuardPragmas(ParserExtensionInfo *, const string &query, ParserOptions &options) {
	try {
		ParserOptions engine = options;
		engine.parser_override_setting = AllowParserOverride::DEFAULT_OVERRIDE;
		Parser parser(engine);
		parser.ParseQuery(query);
		bool rewritten = false;
		for (auto &statement : parser.statements) {
			if (statement->type != StatementType::PRAGMA_STATEMENT)
				continue;
			auto &info = *statement->Cast<PragmaStatement>().info;
			if (ConstantArguments(info))
				continue;
			auto name = info.name;
			info.name = REJECTED_PRAGMA;
			info.parameters.clear();
			info.named_parameters.clear();
			info.parameters.push_back(make_uniq<ConstantExpression>(Value(name)));
			rewritten = true;
		}
		if (!rewritten)
			return ParserOverrideResult();
		return ParserOverrideResult(std::move(parser.statements));
	} catch (const std::exception &) {
		return ParserOverrideResult();
	}
}

// A query pragma: the preprocessor calls it while parsing, so the refusal surfaces from every entry
// point (Query, Prepare, extract_statements) before anything is bound or evaluated.
static string RejectPragma(ClientContext &, const FunctionParameters &parameters) {
	throw PermissionException("Gatekeeper denied this statement (unsupported): statement: PRAGMA %s has a "
	                          "non-constant argument; PRAGMA arguments must be literals while "
	                          "allow_parser_override_extension is enabled",
	                          parameters.values[0].ToString());
}

bool PragmaGuardShadowed(DBConfig &config) {
	for (auto &extension : config.GetCallbackManager().ParserExtensions()) {
		if (extension.parser_override == GuardPragmas)
			return false;
		if (extension.parser_override)
			return true;
	}
	return false;
}

void RegisterPragmaGuard(ExtensionLoader &loader) {
	auto &db = loader.GetDatabaseInstance();
	ParserExtension guard;
	guard.parser_override = GuardPragmas;
	ParserExtension::Register(DBConfig::GetConfig(db), guard);

	CreatePragmaFunctionInfo info(PragmaFunction::PragmaCall(REJECTED_PRAGMA, RejectPragma, {LogicalType::VARCHAR}));
	info.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
	FunctionDescription description;
	description.description = "Refuses to run; Gatekeeper's parser override rewrites PRAGMA statements with "
	                          "non-constant arguments into this pragma.";
	description.parameter_names = {"pragma"};
	description.examples = {"PRAGMA gatekeeper_rejected_pragma('table_info')"};
	info.descriptions.push_back(std::move(description));
	auto &system_catalog = Catalog::GetSystemCatalog(db);
	auto data = CatalogTransaction::GetSystemTransaction(db);
	system_catalog.CreatePragmaFunction(data, info);
}
} // namespace duckdb
