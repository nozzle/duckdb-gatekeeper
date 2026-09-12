import argparse
import json
from pathlib import Path
import statistics
import time

import duckdb


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--extension", default=str(Path(__file__).resolve().parents[1] / "build/release/extension/gatekeeper/gatekeeper.duckdb_extension"))
    parser.add_argument("--iterations", type=int, default=1000)
    args = parser.parse_args()
    with duckdb.connect(config={"allow_unsigned_extensions": "true"}) as db:
        db.execute("LOAD '" + str(Path(args.extension).resolve()).replace("'", "''") + "'")
        db.execute("CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.orders(id INT, value DOUBLE)")
        print("DuckDB", duckdb.__version__)
        queries = {
            "simple": "SELECT * FROM tenant_a.orders",
            "cte": "WITH a AS (SELECT id,sum(value) AS total FROM tenant_a.orders GROUP BY id) SELECT * FROM a WHERE total > (SELECT avg(value) FROM tenant_a.orders)",
            "deep20": "SELECT * FROM " + "(SELECT * FROM " * 20 + "tenant_a.orders" + ") t" * 20,
        }
        for name, query in queries.items():
            times = []
            options = json.dumps({"allowed_schemas": ["tenant_a"]})
            for iteration in range(args.iterations + 20):
                start = time.perf_counter_ns()
                result = db.execute("SELECT gatekeeper_validate(?, ?)", [query, options]).fetchone()[0]
                elapsed = time.perf_counter_ns() - start
                assert result["allowed"], result
                if iteration >= 20:
                    times.append(elapsed / 1000)
            print(f"{name}: median={statistics.median(times):.1f} us p95={sorted(times)[int(len(times)*0.95)]:.1f} us")


if __name__ == "__main__":
    main()
