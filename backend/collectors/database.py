import json
import logging
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor, execute_values
 
logger = logging.getLogger(__name__)

class SupabaseQueryBuilder:
    def __init__(self, db, table_name):
        self.db = db
        self.table_name = table_name
        self._action = None
        self._data = None
        self._where = {}
        self._columns = "*"
        self._order_by = None
        self._limit = None

    def select(self, columns="*"):
        self._action = "select"
        self._columns = columns
        return self

    def insert(self, data):
        self._action = "insert"
        self._data = data
        return self

    def update(self, data):
        self._action = "update"
        self._data = data
        return self

    def eq(self, column, value):
        self._where[column] = value
        return self

    def order(self, column, desc=False):
        self._order_by = f"{column} {'DESC' if desc else 'ASC'}"
        return self

    def limit(self, limit):
        self._limit = limit
        return self

    def execute(self):
        class Result:
            def __init__(self, data):
                self.data = data
        
        conn = self.db.pool.getconn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if self._action == "select":
                    query = f"SELECT {self._columns} FROM {self.table_name}"
                    params = []
                    if self._where:
                        conds = []
                        for k, v in self._where.items():
                            conds.append(f"{k} = %s")
                            params.append(v)
                        query += " WHERE " + " AND ".join(conds)
                    if self._order_by:
                        query += f" ORDER BY {self._order_by}"
                    if self._limit:
                        query += f" LIMIT {self._limit}"
                        
                    cur.execute(query, tuple(params))
                    rows = cur.fetchall()
                    data = [dict(row) for row in rows]
                    return Result(data=data)
                    
                elif self._action == "insert":
                    if not self._data:
                        return Result(data=[])
                    
                    is_bulk = isinstance(self._data, list)
                    rows = self._data if is_bulk else [self._data]
                    if not rows:
                        return Result(data=[])
                        
                    # Handle JSONB / dicts serialization
                    for row in rows:
                        for k, v in row.items():
                            if isinstance(v, dict):
                                row[k] = psycopg2.extras.Json(v)
                            elif isinstance(v, list):
                                pg_array_cols = {
                                    'data_must_reside_in', 'applicable_compliances', 'requires_residency_in',
                                    'selected_compliances', 'triggered_compliances', 'affected_services',
                                    'default_compliances'
                                }
                                if k in pg_array_cols:
                                    row[k] = v
                                else:
                                    row[k] = psycopg2.extras.Json(v)

                    columns = list(rows[0].keys())
                    cols_str = ", ".join(columns)
                    
                    values_list = []
                    for r in rows:
                        values_list.append(tuple(r.get(c) for c in columns))
                        
                    query = f"INSERT INTO {self.table_name} ({cols_str}) VALUES %s RETURNING *"
                    inserted = execute_values(cur, query, values_list, fetch=True)
                    conn.commit()
                    
                    if inserted:
                        return Result(data=[dict(r) for r in inserted])
                    return Result(data=[])
                    
                elif self._action == "update":
                    if not self._data:
                        return Result(data=[])
                        
                    data_to_update = self._data.copy()
                    for k, v in data_to_update.items():
                        if isinstance(v, dict):
                            data_to_update[k] = psycopg2.extras.Json(v)
                        elif isinstance(v, list):
                            pg_array_cols = {
                                'data_must_reside_in', 'applicable_compliances', 'requires_residency_in',
                                'selected_compliances', 'triggered_compliances', 'affected_services',
                                'default_compliances'
                            }
                            if k in pg_array_cols:
                                data_to_update[k] = v
                            else:
                                data_to_update[k] = psycopg2.extras.Json(v)
                            
                    set_clauses = []
                    params = []
                    for k, v in data_to_update.items():
                        set_clauses.append(f"{k} = %s")
                        params.append(v)
                        
                    query = f"UPDATE {self.table_name} SET {', '.join(set_clauses)}"
                    
                    if self._where:
                        conds = []
                        for k, v in self._where.items():
                            conds.append(f"{k} = %s")
                            params.append(v)
                        query += " WHERE " + " AND ".join(conds)
                        
                    query += " RETURNING *"
                    cur.execute(query, tuple(params))
                    conn.commit()
                    updated = cur.fetchall()
                    return Result(data=[dict(r) for r in updated])
                    
        except Exception as e:
            conn.rollback()
            logger.exception(f"Database operation failed: {e}")
            raise e
        finally:
            self.db.pool.putconn(conn)

class PostgresClient:
    def __init__(self, uri: str):
        self.uri = uri
        self.pool = pool.SimpleConnectionPool(1, 10, self.uri)
        
    def table(self, table_name: str) -> SupabaseQueryBuilder:
        return SupabaseQueryBuilder(self, table_name)
