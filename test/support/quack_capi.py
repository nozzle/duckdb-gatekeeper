"""Held prepared handles using the C API exported by the exact Python engine under test.

Python execute() couples preparation and execution. These probes need to observe the server in
between and retain a handle across enforcement activation. The connection owns a separate database.
"""
from contextlib import contextmanager
import ctypes as c

import _duckdb


class Result(c.Structure):
    _fields_ = [("deprecated_column_count", c.c_uint64), ("deprecated_row_count", c.c_uint64),
                ("deprecated_rows_changed", c.c_uint64), ("deprecated_columns", c.c_void_p),
                ("deprecated_error_message", c.c_char_p), ("internal_data", c.c_void_p)]


class CConnection:
    def __init__(self):
        self.lib = c.CDLL(_duckdb.__file__)
        signatures = {
            "duckdb_create_config": ([c.POINTER(c.c_void_p)], c.c_int),
            "duckdb_set_config": ([c.c_void_p, c.c_char_p, c.c_char_p], c.c_int),
            "duckdb_destroy_config": ([c.POINTER(c.c_void_p)], None),
            "duckdb_open_ext": ([c.c_char_p, c.POINTER(c.c_void_p), c.c_void_p, c.POINTER(c.c_void_p)], c.c_int),
            "duckdb_free": ([c.c_void_p], None),
            "duckdb_close": ([c.POINTER(c.c_void_p)], None),
            "duckdb_connect": ([c.c_void_p, c.POINTER(c.c_void_p)], c.c_int),
            "duckdb_disconnect": ([c.POINTER(c.c_void_p)], None),
            "duckdb_query": ([c.c_void_p, c.c_char_p, c.POINTER(Result)], c.c_int),
            "duckdb_destroy_result": ([c.POINTER(Result)], None),
            "duckdb_result_error": ([c.POINTER(Result)], c.c_char_p),
            "duckdb_prepare": ([c.c_void_p, c.c_char_p, c.POINTER(c.c_void_p)], c.c_int),
            "duckdb_prepare_error": ([c.c_void_p], c.c_char_p),
            "duckdb_destroy_prepare": ([c.POINTER(c.c_void_p)], None),
            "duckdb_execute_prepared": ([c.c_void_p, c.POINTER(Result)], c.c_int),
            "duckdb_bind_int32": ([c.c_void_p, c.c_uint64, c.c_int32], c.c_int),
            "duckdb_bind_varchar": ([c.c_void_p, c.c_uint64, c.c_char_p], c.c_int),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.lib, name)
            function.argtypes, function.restype = args, result
        self.db, self.connection = c.c_void_p(), c.c_void_p()
        config, error = c.c_void_p(), c.c_void_p()
        assert self.lib.duckdb_create_config(c.byref(config)) == 0
        try:
            for name, value in [(b"allow_unsigned_extensions", b"true"),
                                (b"autoinstall_known_extensions", b"false"),
                                (b"autoload_known_extensions", b"false")]:
                assert self.lib.duckdb_set_config(config, name, value) == 0
            assert self.lib.duckdb_open_ext(None, c.byref(self.db), config, c.byref(error)) == 0
        finally:
            self.lib.duckdb_free(error)
            self.lib.duckdb_destroy_config(c.byref(config))
        if self.lib.duckdb_connect(self.db, c.byref(self.connection)):
            self.lib.duckdb_close(c.byref(self.db))
            raise RuntimeError("C API connection failed")

    def close(self):
        self.lib.duckdb_disconnect(c.byref(self.connection))
        self.lib.duckdb_close(c.byref(self.db))

    def result(self, invoke):
        result = Result()
        try:
            status = invoke(c.byref(result))
            error = self.lib.duckdb_result_error(c.byref(result))
            return error.decode() if status and error else ("unknown C API error" if status else None)
        finally:
            self.lib.duckdb_destroy_result(c.byref(result))

    def query(self, sql):
        error = self.result(lambda result: self.lib.duckdb_query(self.connection, sql.encode(), result))
        assert error is None, (sql, error)

    @contextmanager
    def prepare(self, sql):
        handle = c.c_void_p()
        try:
            status = self.lib.duckdb_prepare(self.connection, sql.encode(), c.byref(handle))
            error = self.lib.duckdb_prepare_error(handle)
            yield handle, error.decode() if status and error else None
        finally:
            self.lib.duckdb_destroy_prepare(c.byref(handle))

    def execute(self, handle, value=None):
        if isinstance(value, str):
            assert self.lib.duckdb_bind_varchar(handle, 1, value.encode()) == 0
        elif value is not None:
            assert self.lib.duckdb_bind_int32(handle, 1, value) == 0
        return self.result(lambda result: self.lib.duckdb_execute_prepared(handle, result))
