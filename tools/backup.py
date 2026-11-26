"""Reconstruct a faithful local SQLite copy of the live cubeSQL hv.db:
schema (tables/indexes/triggers/views with all constraints) + data.
Usage: python3 backup.py OUTFILE.db
"""
import sys, sqlite3, os
import cubeclient as cc

# cubeSQL column type ids
T_INT, T_FLOAT, T_TEXT, T_BLOB, T_BOOL, T_DATE, T_TIME, T_TS, T_CUR = 1, 2, 3, 4, 5, 6, 7, 8, 9


def conv(val, typ):
    if val is None:
        return None
    if typ == T_BLOB:
        return sqlite3.Binary(val)
    if typ in (T_INT, T_BOOL):
        try:
            return int(val)
        except Exception:
            return val.decode('utf-8', 'replace')
    if typ in (T_FLOAT, T_CUR):
        try:
            return float(val)
        except Exception:
            return val.decode('utf-8', 'replace')
    return val.decode('utf-8', 'replace')


def main():
    out = sys.argv[1]
    if os.path.exists(out):
        os.remove(out)
    c = cc.login()
    cc.use_hv(c)

    _, objs = c.select(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE sql IS NOT NULL "
        "ORDER BY rowid;")
    tables = [(n, s) for (t, n, tb, s) in objs if t == 'table' and not n.startswith('sqlite_')]
    indexes = [(n, s) for (t, n, tb, s) in objs if t == 'index' and not n.startswith('sqlite_')]
    triggers = [(n, s) for (t, n, tb, s) in objs if t == 'trigger']
    views = [(n, s) for (t, n, tb, s) in objs if t == 'view']

    db = sqlite3.connect(out)
    db.execute("PRAGMA foreign_keys=OFF;")
    db.execute("PRAGMA journal_mode=OFF;")
    cur = db.cursor()

    made = {'table': 0, 'index': 0, 'trigger': 0, 'view': 0}
    errors = []

    # 1) tables
    for name, sql in tables:
        try:
            cur.execute(sql)
            made['table'] += 1
        except Exception as e:
            errors.append(f"TABLE {name}: {e}")

    # 2) data
    counts = {}
    for name, _ in tables:
        try:
            cols, rows = c.select(f'SELECT * FROM "{name}";', raw=True)
            types = c.last_coltypes or []
            counts[name] = len(rows)
            if rows:
                ncol = len(rows[0])
                conv_rows = [[conv(v, types[i] if i < len(types) else T_TEXT) for i, v in enumerate(r)]
                             for r in rows]
                ph = ",".join(["?"] * ncol)
                cur.executemany(f'INSERT INTO "{name}" VALUES ({ph})', conv_rows)
        except Exception as e:
            errors.append(f"DATA {name}: {e}")
    db.commit()

    # 3) indexes, 4) views, 5) triggers  (retry for dependency order)
    for kind, items, key in (('index', indexes, 'index'),
                             ('view', views, 'view'),
                             ('trigger', triggers, 'trigger')):
        pending = list(items)
        for _ in range(3):
            still = []
            for name, sql in pending:
                try:
                    cur.execute(sql)
                    made[key] += 1
                except Exception as e:
                    still.append((name, sql, str(e)))
            pending = [(n, s) for (n, s, e) in still]
            if not pending:
                break
        for n, s, e in [(x[0], x[1], x[2]) for x in still]:
            errors.append(f"{kind.upper()} {n}: {e}")
    db.commit()

    # validation
    print("=== built:", made, file=sys.stderr)
    print("=== integrity_check:", cur.execute("PRAGMA integrity_check;").fetchone()[0], file=sys.stderr)
    fk = cur.execute("PRAGMA foreign_key_check;").fetchall()
    print(f"=== foreign_key_check: {len(fk)} violations", file=sys.stderr)
    for row in fk[:20]:
        print("   FKVIOL", row, file=sys.stderr)
    if errors:
        print(f"=== {len(errors)} object/data errors:", file=sys.stderr)
        for e in errors[:40]:
            print("   !", e, file=sys.stderr)
    db.close()
    c.close()
    print(f"=== wrote {out} ({os.path.getsize(out)} bytes), "
          f"{sum(counts.values())} data rows across {len(counts)} tables", file=sys.stderr)


if __name__ == '__main__':
    main()
