import sqlite3

db_name = "DB/IDS.db"
conn = sqlite3.connect(db_name)
cursor = conn.cursor()

create_table_rules = """
CREATE TABLE IF NOT EXISTS rules 
(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT,
    protocol TEXT,
    src_ip TEXT,
    src_port TEXT,
    direction TEXT,
    dst_ip TEXT,
    dst_port TEXT,
    options TEXT
);
"""

create_table_logs = """
CREATE TABLE IF NOT EXISTS logs 
(
    id INTEGER PRIMARY KEY,
    timestamp DATETIME,
    event_type TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    message TEXT,
    attack TEXT
);
"""

create_table_alerts="""
CREATE TABLE IF NOT EXISTS alerts 
(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME,
    src_ip TEXT,
    dst_ip TEXT,
    message TEXT,
    attack TEXT
    );
    """


def clear_table(table_name,conn):
    try:
        
        if not conn:
            print(f"[Error] Failed to connect to the database.")
            return False
        
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM {table_name};")  
        conn.commit()
        print(f"[Success] All records from '{table_name}' have been deleted.")

        return True

    except sqlite3.Error as e:
        print(f"[Database Error] {e}")
        return False

if __name__ == "__main__":
    cursor.execute(create_table_rules)
    cursor.execute(create_table_logs)
    cursor.execute(create_table_alerts)

    conn.commit()
    conn.close()