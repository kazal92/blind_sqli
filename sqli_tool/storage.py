"""기존 메타데이터 테이블을 유지하는 SQLite 결과 저장."""

import json
import sqlite3


class ResultStore:
    def __init__(self, path):
        self.connection = sqlite3.connect(path)
        try:
            self.connection.executescript("""
                CREATE TABLE IF NOT EXISTS basic_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version VARCHAR(255), user VARCHAR(255), UNIQUE(version, user));
                CREATE TABLE IF NOT EXISTS basic_results (
                    field TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS dbs_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, db_name VARCHAR(255), UNIQUE(db_name));
                CREATE TABLE IF NOT EXISTS table_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, db_name VARCHAR(255),
                    table_name VARCHAR(255), UNIQUE(db_name, table_name));
                CREATE TABLE IF NOT EXISTS column_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, db_name VARCHAR(255),
                    table_name VARCHAR(255), column_name VARCHAR(255), UNIQUE(db_name, table_name, column_name));
                CREATE TABLE IF NOT EXISTS data_dump (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, db_name TEXT, table_name TEXT,
                    column_name TEXT, row_index INTEGER, data TEXT);
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    dbms TEXT, mode TEXT, database_name TEXT, schema_name TEXT, results_json TEXT);
            """)
        except Exception:
            self.connection.close()
            raise

    def save(self, args, results):
        # 한 실행의 결과는 트랜잭션으로 묶어 실패 시 부분 저장하지 않는다.
        with self.connection:
            self.connection.execute(
                "INSERT INTO runs (dbms,mode,database_name,schema_name,results_json) VALUES (?,?,?,?,?)",
                (
                    args.dbms,
                    args.mode,
                    args.select_db,
                    args.db_schema or {"mssql": "dbo", "postgresql": "public"}.get(args.dbms),
                    json.dumps(results, ensure_ascii=False),
                ),
            )
            if args.basic:
                for field, value in results.items():
                    self.connection.execute(
                        "INSERT OR REPLACE INTO basic_results VALUES (?,?)", (field, value)
                    )
                if "Version" in results or "User" in results:
                    self.connection.execute("DELETE FROM basic_info")
                    self.connection.execute(
                        "INSERT INTO basic_info (version,user) VALUES (?,?)",
                        (results.get("Version"), results.get("User")),
                    )
            elif args.dbs:
                self.connection.executemany(
                    "INSERT OR IGNORE INTO dbs_info (db_name) VALUES (?)",
                    [(name,) for name in results["dbs"]],
                )
            elif args.tables:
                self.connection.executemany(
                    "INSERT OR IGNORE INTO table_info (db_name,table_name) VALUES (?,?)",
                    [(args.select_db, name) for name in results["tables"]],
                )
            elif args.columns:
                for table, columns in results.items():
                    self.connection.executemany(
                        "INSERT OR IGNORE INTO column_info (db_name,table_name,column_name) VALUES (?,?,?)",
                        [(args.select_db, table, column) for column in columns],
                    )
            elif args.dump:
                table = args.select_table[0]
                for index, row in enumerate(results[table], 1):
                    self.connection.executemany(
                        "INSERT INTO data_dump (db_name,table_name,column_name,row_index,data) VALUES (?,?,?,?,?)",
                        [
                            (args.select_db, table, column, index, value)
                            for column, value in row.items()
                        ],
                    )

    def close(self):
        self.connection.close()
