#!/usr/bin/env Rscript
# Loadable smoke through the CRAN duckdb package, the host the windows_amd64_mingw artifact exists for
# (DuckDB's R package is built with RTools, so it loads _mingw extensions). Runs scripts/smoke/loadable.sql
# on one connection and scripts/smoke/enforced.sql on two connections to one database, with the paragraph
# conventions those files describe. Needs only DBI and duckdb.
#
#   Rscript scripts/smoke_loadable.R <gatekeeper.duckdb_extension> <engine version> <platform>
#   e.g.  Rscript scripts/smoke_loadable.R build/distributed/gatekeeper.duckdb_extension v1.5.5 windows_amd64_mingw

suppressPackageStartupMessages({
  library(DBI)
  library(duckdb)
})

args <- commandArgs(trailingOnly = TRUE)
if (length(args) != 3) {
  stop("usage: Rscript scripts/smoke_loadable.R <extension> <engine version> <platform>", call. = FALSE)
}
extension <- normalizePath(args[[1]], winslash = "/", mustWork = TRUE)
expected_version <- args[[2]]
expected_platform <- args[[3]]
script_dir <- dirname(normalizePath(sub("^--file=", "", grep("^--file=", commandArgs(), value = TRUE)[[1]]),
                                    winslash = "/"))
smoke_dir <- file.path(script_dir, "smoke")

fail <- function(...) {
  message("::error::smoke_loadable.R: ", ...)
  quit(status = 1)
}

# The paragraphs of a smoke file, as scripts/smoke_loadable.py reads them: blank-line separated, comment lines
# removed, a "-- @host|@agent [expect error: text]" directive on any comment line, trailing semicolon dropped.
statements <- function(path) {
  lines <- readLines(path, warn = FALSE)
  result <- list()
  paragraph <- character()
  first_line <- NA_integer_
  flush <- function() {
    if (!length(paragraph)) return()
    comments <- grepl("^\\s*--", paragraph)
    connection <- "host"
    error <- NA_character_
    for (comment in trimws(paragraph[comments])) {
      match <- regmatches(comment, regexec("^--\\s*@(host|agent)(?:\\s+expect error:\\s*(.+?))?\\s*$", comment, perl = TRUE))[[1]]
      if (length(match)) {
        connection <- match[[2]]
        error <- if (nzchar(match[[3]])) match[[3]] else NA_character_
      }
    }
    sql <- trimws(paste(paragraph[!comments], collapse = "\n"))
    sql <- trimws(sub(";\\s*$", "", sql))
    if (nzchar(sql)) {
      result[[length(result) + 1]] <<- list(connection = connection, sql = sql, error = error, line = first_line)
    }
    paragraph <<- character()
  }
  for (number in seq_along(lines)) {
    line <- lines[[number]]
    if (nzchar(trimws(line))) {
      if (!length(paragraph)) first_line <- number
      paragraph <- c(paragraph, line)
    } else {
      flush()
    }
  }
  flush()
  result
}

run <- function(path, connections) {
  name <- basename(path)
  for (statement in statements(path)) {
    con <- connections[[statement$connection]]
    outcome <- tryCatch({
      dbExecute(con, statement$sql)
      NULL
    }, error = function(e) conditionMessage(e))
    if (is.null(outcome)) {
      if (!is.na(statement$error)) {
        fail(name, ":", statement$line, ": succeeded, expected an error containing '", statement$error, "'")
      }
    } else if (is.na(statement$error)) {
      fail(name, ":", statement$line, ": ", outcome)
    } else if (!grepl(statement$error, outcome, fixed = TRUE)) {
      fail(name, ":", statement$line, ": failed with the wrong error: ", outcome)
    }
  }
}

connect <- function() {
  driver <- duckdb(config = list(allow_unsigned_extensions = "true", autoload_known_extensions = "false",
                                 autoinstall_known_extensions = "false"),
                   shared_home = FALSE)
  host <- dbConnect(driver)
  dbExecute(host, sprintf("LOAD '%s'", gsub("'", "''", extension)))
  list(driver = driver, host = host)
}

# 1. The host is the pinned engine and the artifact is this platform's.
db <- connect()
version <- dbGetQuery(db$host, "PRAGMA version")
platform <- dbGetQuery(db$host, "PRAGMA platform")$platform[[1]]
loaded <- dbGetQuery(db$host, "SELECT extension_version FROM duckdb_extensions() WHERE extension_name = 'gatekeeper' AND loaded")
if (!identical(version$library_version[[1]], expected_version)) {
  fail("the R package embeds ", version$library_version[[1]], ", expected ", expected_version)
}
if (!identical(platform, expected_platform)) {
  fail("the R package's platform is ", platform, ", expected ", expected_platform)
}
if (nrow(loaded) != 1) fail("gatekeeper did not load")
cat("host", version$library_version[[1]], version$source_id[[1]], platform, "extension", loaded$extension_version[[1]], "\n")

# 2. The single-connection half, from a scratch directory (it writes gatekeeper_smoke.parquet).
scratch <- tempfile("gatekeeper-smoke-")
dir.create(scratch)
setwd(scratch)
run(file.path(smoke_dir, "loadable.sql"), list(host = db$host))
dbDisconnect(db$host, shutdown = TRUE)

# 3. The enforced half: a second connection to the same database latches itself.
db <- connect()
agent <- dbConnect(db$driver)
run(file.path(smoke_dir, "enforced.sql"), list(host = db$host, agent = agent))
dbDisconnect(agent)
dbDisconnect(db$host, shutdown = TRUE)

cat(basename(extension), " (", expected_platform, "): R smoke checks passed\n", sep = "")
