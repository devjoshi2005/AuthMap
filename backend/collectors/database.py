import json
import logging
from datetime import datetime
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

    def in_(self, column, values):
        self._where[column] = {"$in": values}
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
                            if isinstance(v, dict) and "$in" in v:
                                conds.append(f"{k} = ANY(%s)")
                                params.append(list(v["$in"]))
                            else:
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
                            if isinstance(v, dict) and "$in" in v:
                                conds.append(f"{k}::text = ANY(%s::text[])")
                                params.append(list(v["$in"]))
                            else:
                                conds.append(f"{k}::text = %s::text")
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

    def prune_expired_conversations(self) -> int:
        """Deletes any conversations that have passed their 48-hour expiration window."""
        conn = self.pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM ai_conversations WHERE expires_at <= NOW()")
                deleted_count = cur.rowcount
                conn.commit()
                return deleted_count
        except Exception as e:
            conn.rollback()
            logger.warning(f"Error pruning expired conversations: {e}")
            return 0
        finally:
            self.pool.putconn(conn)

    def get_user_conversations(self, clerk_id: str) -> list:
        """Retrieves all active (<=48hr) conversations for the user and prunes expired ones."""
        self.prune_expired_conversations()
        conn = self.pool.getconn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, title, messages, model_used, created_at, updated_at, expires_at
                    FROM ai_conversations
                    WHERE clerk_id = %s AND expires_at > NOW()
                    ORDER BY updated_at DESC
                """, (clerk_id,))
                rows = cur.fetchall()
                results = []
                for r in rows:
                    item = dict(r)
                    if isinstance(item.get("created_at"), datetime):
                        item["createdAt"] = int(item["created_at"].timestamp() * 1000)
                    elif isinstance(item.get("updated_at"), datetime):
                        item["createdAt"] = int(item["updated_at"].timestamp() * 1000)
                    else:
                        item["createdAt"] = int(datetime.utcnow().timestamp() * 1000)
                    results.append(item)
                return results
        except Exception as e:
            logger.error(f"Failed to fetch user conversations: {e}")
            return []
        finally:
            self.pool.putconn(conn)

    def upsert_conversation(self, clerk_id: str, conv_id: str, title: str, messages: list, model_used: str = "openai/gpt-oss-20b") -> dict:
        """Saves or updates a conversation, refreshing its 48-hour TTL window."""
        conn = self.pool.getconn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    INSERT INTO ai_conversations (id, clerk_id, title, messages, model_used, created_at, updated_at, expires_at)
                    VALUES (%s, %s, %s, %s, %s, NOW(), NOW(), NOW() + INTERVAL '48 hours')
                    ON CONFLICT (id) DO UPDATE SET
                        title = EXCLUDED.title,
                        messages = EXCLUDED.messages,
                        model_used = EXCLUDED.model_used,
                        updated_at = NOW(),
                        expires_at = NOW() + INTERVAL '48 hours'
                    RETURNING *;
                """, (conv_id, clerk_id, title, psycopg2.extras.Json(messages), model_used))
                conn.commit()
                row = cur.fetchone()
                return dict(row) if row else {}
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to upsert conversation {conv_id}: {e}")
            raise e
        finally:
            self.pool.putconn(conn)

    def delete_conversation(self, clerk_id: str, conv_id: str) -> bool:
        """Deletes a specific conversation owned by the user."""
        conn = self.pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM ai_conversations WHERE id = %s AND clerk_id = %s", (conv_id, clerk_id))
                conn.commit()
                return cur.rowcount > 0
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to delete conversation {conv_id}: {e}")
            return False
        finally:
            self.pool.putconn(conn)

    # ── Long-Term User & Org Memory Methods ──────────────────────────
    def get_user_memories(self, clerk_id: str) -> list:
        """Fetches all persistent memory notes for the user's organization."""
        conn = self.pool.getconn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, key, content, category, source, created_at, updated_at
                    FROM ai_user_memories
                    WHERE clerk_id = %s
                    ORDER BY updated_at DESC
                """, (clerk_id,))
                rows = cur.fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to fetch user memories: {e}")
            return []
        finally:
            self.pool.putconn(conn)

    def upsert_user_memory(self, clerk_id: str, key: str, content: str, category: str = "general", source: str = "user_defined") -> dict:
        """Adds or updates a persistent memory note for the organization."""
        conn = self.pool.getconn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    INSERT INTO ai_user_memories (clerk_id, key, content, category, source, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                    ON CONFLICT (clerk_id, key) DO UPDATE SET
                        content = EXCLUDED.content,
                        category = EXCLUDED.category,
                        source = EXCLUDED.source,
                        updated_at = NOW()
                    RETURNING *;
                """, (clerk_id, key.strip().lower().replace(" ", "_"), content.strip(), category, source))
                conn.commit()
                row = cur.fetchone()
                return dict(row) if row else {}
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to upsert memory for {clerk_id}: {e}")
            raise e
        finally:
            self.pool.putconn(conn)

    def delete_user_memory(self, clerk_id: str, key_or_id: str) -> bool:
        """Deletes a persistent memory note by key or uuid."""
        conn = self.pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM ai_user_memories
                    WHERE clerk_id = %s AND (key = %s OR id::text = %s)
                """, (clerk_id, key_or_id, key_or_id))
                conn.commit()
                return cur.rowcount > 0
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to delete memory {key_or_id}: {e}")
            return False
        finally:
            self.pool.putconn(conn)

