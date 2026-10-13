#!/usr/bin/env python3
"""Restore a Supabase database from a backup made by supabase_backup.py.

Uses the same .env as the backup (nothing else is needed):
  SUPABASE_ACCESS_TOKEN   personal access token
  BACKUP_PROJECTS         "Project Name=prefix, ..." (only used to offer a list and
                          to know each project's backup file prefix)

The backup is taken from the project's own private bucket:
  db-backups/production/<YYYY>/<MM>/<DD>/<prefix>-<YYYYMMDD>-<HHMMSS>.sql.gz

What is restored, in ONE transaction (any error or failed check -> nothing changes):
  - your schemas (public and any other non-Supabase schema): dropped and re-created
    exactly as in the backup - tables, data, functions, views, policies, grants
  - login users: all auth table data (users, identities, sessions, ...)
  - your triggers on auth tables (e.g. "create profile on sign-up")
  - at the end every restored table's row count is compared with the backup;
    any difference rolls the whole restore back
Not restored (by design): Storage file records (they must match the real files),
and Supabase-internal data (realtime, vault, migration logs).

Usage:
  python supabase_restore.py                              # uses RESTORE SETTINGS below
                                                          # (asks for what is empty)
  python supabase_restore.py --project hygieia --date 2026-10-13
  python supabase_restore.py --project hygieia --date 2026-10-13 --time 101300
  python supabase_restore.py --project hygieia --target "Test Project"   # into another project
  python supabase_restore.py --project hygieia --dry-run   # full rehearsal, rolled back
"""
import argparse
import gzip
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime

import requests
from dotenv import load_dotenv

HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(HERE, ".env"))

ACCESS_TOKEN = os.environ.get("SUPABASE_ACCESS_TOKEN", "")
BUCKET = "db-backups"
ENV_FOLDER = "production"

# ============================ RESTORE SETTINGS ============================
# What `python supabase_restore.py` (without options) restores. The same names
# in .env override these; command-line options override both. Leave "" to be asked.
RESTORE_PROJECT = "hashtag-clean"   # project name or its prefix from BACKUP_PROJECTS
RESTORE_DATE = "2026-10-13"         # day of the backup, YYYY-MM-DD
RESTORE_TIME = ""                   # HHMMSS of that day; "" = latest backup of the day
RESTORE_TARGET = ""                 # restore into another project; "" = the same project
# ==========================================================================

# Schemas that Supabase creates and manages in every project. Their structure is
# never restored; only the data/objects listed in restore_entry() are.
MANAGED_SCHEMAS = {
    "auth", "storage", "realtime", "vault", "graphql", "graphql_public", "extensions",
    "pgbouncer", "pgsodium", "pgsodium_masks", "net", "supabase_functions", "cron",
    "_realtime", "_analytics", "information_schema", "pg_catalog",
}
# Data in managed schemas that IS restored (auth = login users).
RESTORE_DATA_SCHEMAS = {"auth"}
# ...except these internal tables, which belong to the project, not the backup.
SKIP_DATA_TABLES = {"auth.schema_migrations"}


# ----------------------------------------------------------------- Supabase API
def mgmt_api(method: str, path: str, **kwargs) -> requests.Response:
    if not ACCESS_TOKEN:
        raise RuntimeError("SUPABASE_ACCESS_TOKEN is not set in .env")
    return requests.request(method, f"https://api.supabase.com/v1{path}", timeout=60,
                            headers={"Authorization": f"Bearer {ACCESS_TOKEN}"}, **kwargs)


@dataclass
class Project:
    name: str
    ref: str
    status: str
    prefix: str = ""
    service_key: str = ""

    @property
    def storage_url(self) -> str:
        return f"https://{self.ref}.supabase.co/storage/v1"


def all_projects() -> list[dict]:
    r = mgmt_api("GET", "/projects")
    if r.status_code != 200:
        raise RuntimeError(f"Listing projects failed ({r.status_code}): {r.text}")
    return r.json()


def configured_projects() -> list[tuple[str, str]]:
    """(project name, prefix) pairs from BACKUP_PROJECTS, as the backup uses them."""
    pairs = []
    for entry in os.environ.get("BACKUP_PROJECTS", "").split(","):
        if entry.strip():
            name, _, prefix = (s.strip() for s in entry.partition("="))
            pairs.append((name, prefix or re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")))
    return pairs


def find_project(projects: list[dict], wanted: str) -> Project:
    """Find a project by name, BACKUP_PROJECTS prefix or "Name=prefix"."""
    name, _, prefix = (s.strip() for s in wanted.partition("="))
    for cfg_name, cfg_prefix in configured_projects():
        if name.lower() in (cfg_name.lower(), cfg_prefix.lower()):
            name, prefix = cfg_name, prefix or cfg_prefix
            break
    matches = [p for p in projects if p["name"].strip().lower() == name.lower()]
    if not matches:
        raise RuntimeError(f"No project named '{name}' (token can see: "
                           f"{', '.join(p['name'] for p in projects)})")
    if len(matches) > 1:
        raise RuntimeError(f"More than one project named '{name}'")
    p = matches[0]
    prefix = prefix or re.sub(r"[^a-z0-9]+", "-", p["name"].lower()).strip("-")
    return Project(p["name"], p["id"], p.get("status", "UNKNOWN"), prefix)


def fetch_service_key(p: Project) -> None:
    r = mgmt_api("GET", f"/projects/{p.ref}/api-keys", params={"reveal": "true"})
    if r.status_code != 200:
        raise RuntimeError(f"Fetching the service key failed ({r.status_code}): {r.text}")
    keys = r.json()
    secret = [k["api_key"] for k in keys if k.get("type") == "secret" and k.get("api_key")]
    legacy = [k["api_key"] for k in keys if k.get("name") == "service_role" and k.get("api_key")]
    if not (secret or legacy):
        raise RuntimeError(f"Project {p.ref} has no secret / service_role key")
    p.service_key = (secret or legacy)[0]


def storage_headers(p: Project) -> dict[str, str]:
    return {"Authorization": f"Bearer {p.service_key}", "apikey": p.service_key}


# ---------------------------------------------------------------- find backup
def list_folder(p: Project, prefix: str) -> list[str]:
    names, offset = [], 0
    while True:
        r = requests.post(f"{p.storage_url}/object/list/{BUCKET}", headers=storage_headers(p),
                          timeout=60, json={"prefix": prefix, "limit": 1000, "offset": offset,
                                            "sortBy": {"column": "name", "order": "asc"}})
        if r.status_code != 200:
            raise RuntimeError(f"Listing {BUCKET}/{prefix} failed ({r.status_code}): {r.text}")
        page = [item["name"] for item in r.json()]
        names += page
        if len(page) < 1000:
            return names
        offset += 1000


def list_backups(p: Project) -> list[tuple[datetime, str]]:
    """All backups of p (by prefix, case-insensitive) as (time stamp, path), oldest first."""
    pattern = re.compile(rf"^{re.escape(p.prefix)}-(\d{{8}}-\d{{6}})\.sql\.gz$", re.IGNORECASE)

    def subfolders(path: str) -> list[str]:
        return [n for n in list_folder(p, path) if re.fullmatch(r"\d{1,4}", n)]

    found = []
    for year in subfolders(ENV_FOLDER):
        for month in subfolders(f"{ENV_FOLDER}/{year}"):
            for day in subfolders(f"{ENV_FOLDER}/{year}/{month}"):
                day_path = f"{ENV_FOLDER}/{year}/{month}/{day}"
                for name in list_folder(p, day_path):
                    m = pattern.match(name)
                    if m:
                        found.append((datetime.strptime(m.group(1), "%Y%m%d-%H%M%S"),
                                      f"{day_path}/{name}"))
    return sorted(found)


def choose_backup(backups: list[tuple[datetime, str]], date: str | None,
                  time: str | None) -> str:
    """Pick the backup of `date` (latest that day, or the one at `time`)."""
    if not backups:
        raise RuntimeError("No backups found for this project")
    if date is None:
        days = sorted({s.date() for s, _ in backups}, reverse=True)
        print("Backups available on:")
        for d in days[:15]:
            n = sum(1 for s, _ in backups if s.date() == d)
            print(f"  {d}  ({n} backup{'s' if n > 1 else ''})")
        answer = input(f"Date to restore [{days[0]}]: ").strip()
        date = answer or str(days[0])
    day = datetime.strptime(date.replace("-", ""), "%Y%m%d").date()
    of_day = [(s, path) for s, path in backups if s.date() == day]
    if not of_day:
        raise RuntimeError(f"No backup on {day} (latest is {backups[-1][0]:%Y-%m-%d %H:%M:%S})")
    if time:
        of_day = [(s, path) for s, path in of_day if f"{s:%H%M%S}" == time.replace(":", "")]
        if not of_day:
            raise RuntimeError(f"No backup on {day} at {time}")
    if len(of_day) > 1:
        print(f"{len(of_day)} backups on {day}: "
              f"{', '.join(f'{s:%H:%M:%S}' for s, _ in of_day)} -> using the latest")
    return of_day[-1][1]


def download(p: Project, remote_path: str, local_path: str) -> None:
    print(f"Downloading {BUCKET}/{remote_path} ...")
    with requests.get(f"{p.storage_url}/object/{BUCKET}/{remote_path}",
                      headers=storage_headers(p), stream=True, timeout=1800) as r:
        if r.status_code != 200:
            raise RuntimeError(f"Download failed ({r.status_code}): {r.text}")
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                f.write(chunk)
    print(f"Downloaded ({os.path.getsize(local_path) / 1024 / 1024:.2f} MB)")


# ------------------------------------------------------------ build restore SQL
# pg_dump writes a header like this before every object:
#   -- Name: clients; Type: TABLE; Schema: public; Owner: postgres
#   -- Data for Name: users; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
ENTRY_RE = re.compile(r"^-- (?:Data for )?Name: (.*); Type: (.*?); Schema: (.*?);")
COPY_RE = re.compile(r"^COPY (\S+) ")
DUMP_END = "-- PostgreSQL database dump complete"


@dataclass
class DumpInfo:
    user_schemas: set[str] = field(default_factory=set)      # schemas we own and restore
    rows: dict[str, int] = field(default_factory=dict)       # restored table -> row count
    auth_tables: list[str] = field(default_factory=list)     # auth tables to replace


def scan_dump(gz_path: str) -> DumpInfo:
    """First pass: which schemas/tables the backup contains and their row counts."""
    info, cur = DumpInfo(), None
    info.user_schemas.add("public")
    with gzip.open(gz_path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if cur is not None:
                if line == "\\.\n":
                    cur = None
                elif cur:
                    info.rows[cur] += 1
                continue
            m = ENTRY_RE.match(line)
            if m and m.group(2) == "SCHEMA" and m.group(1) not in MANAGED_SCHEMAS:
                info.user_schemas.add(m.group(1))
            m = COPY_RE.match(line)
            if m:
                table = m.group(1)
                schema = table.split(".")[0].strip('"')
                keep = (schema not in MANAGED_SCHEMAS or
                        (schema in RESTORE_DATA_SCHEMAS and table not in SKIP_DATA_TABLES))
                cur = table if keep else ""
                if keep:
                    info.rows[table] = 0
                    if schema in RESTORE_DATA_SCHEMAS:
                        info.auth_tables.append(table)
    return info


def restore_entry(kind: str, schema: str, name: str, info: DumpInfo) -> str:
    """'keep', 'wrap' (keep, but tolerate 'exists'/'not allowed') or 'skip'."""
    if schema in info.user_schemas:
        return "keep"
    if schema == "-":
        if kind == "SCHEMA":
            return "keep" if name in info.user_schemas else "skip"
        if kind == "EXTENSION":
            return "keep"  # CREATE EXTENSION IF NOT EXISTS
        if kind in ("ACL", "COMMENT") and name.startswith("SCHEMA "):
            return "keep" if name[len("SCHEMA "):] in info.user_schemas else "skip"
        return "skip"  # event triggers, publications, extension comments: Supabase's
    if schema in RESTORE_DATA_SCHEMAS and kind in ("TABLE DATA", "SEQUENCE SET"):
        return "keep" if f"{schema}.{name}" not in SKIP_DATA_TABLES else "skip"
    if schema in ("auth", "storage") and kind in ("TRIGGER", "POLICY"):
        return "wrap"  # your triggers/policies on Supabase tables
    return "skip"


def wrap_statement(sql: str, label: str) -> str:
    """Run sql, but skip it (with a warning) if it already exists or is not allowed."""
    return (f"DO $restore$ BEGIN\n  EXECUTE $stmt${sql.strip().rstrip(';')}$stmt$;\n"
            f"EXCEPTION WHEN duplicate_object THEN NULL;\n"
            f"  WHEN insufficient_privilege THEN RAISE WARNING 'restore: not allowed, skipped %', "
            f"$lbl${label}$lbl$;\nEND $restore$;\n")


def restore_sql(gz_path: str, info: DumpInfo, commit: bool):
    """Yield the SQL (as text lines) that restores the dump in one transaction."""
    yield "SET ROLE postgres;\n"
    yield "SET statement_timeout = 0;\n"
    yield "BEGIN;\n"
    yield "SET LOCAL session_replication_role = replica;\n"  # no triggers/FK checks while loading
    # 1. remove what will be restored
    for s in sorted(info.user_schemas - {"public"}):
        yield f'DROP SCHEMA IF EXISTS "{s}" CASCADE;\n'
    yield "DROP SCHEMA IF EXISTS public CASCADE;\nCREATE SCHEMA public;\n"
    if info.auth_tables:
        yield f"TRUNCATE {', '.join(info.auth_tables)};\n"

    # 2. the dump, filtered
    action, in_copy, wrapped, label = "keep", False, [], ""
    with gzip.open(gz_path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if in_copy:
                in_copy = line != "\\.\n"
                if action == "keep":
                    yield line
                continue
            m = ENTRY_RE.match(line)
            if m or line.startswith(DUMP_END):
                if wrapped:
                    yield wrap_statement("".join(wrapped), label)
                    wrapped = []
                action = restore_entry(m.group(2), m.group(3), m.group(1), info) if m else "keep"
                label = f"{m.group(2)} {m.group(3)}.{m.group(1)}" if m else ""
            elif line.startswith("COPY "):
                in_copy = True
            if action == "skip":
                continue
            # Ownership/default privileges can only be set for our own role.
            m = re.match(r"^ALTER .* OWNER TO (\S+);$", line.rstrip())
            if m and m.group(1) != "postgres":
                continue
            m = re.match(r"^ALTER DEFAULT PRIVILEGES FOR ROLE (\S+) ", line)
            if m and m.group(1) != "postgres":
                continue
            if action == "wrap" and not line.startswith("--") and line.strip():
                wrapped.append(line)
            elif action != "wrap":
                yield line
    if wrapped:
        yield wrap_statement("".join(wrapped), label)

    # 3. prove it: every restored table must have the backup's row count
    yield "RESET session_replication_role;\nDO $verify$ DECLARE n bigint; BEGIN\n"
    for table, count in info.rows.items():
        yield (f"  SELECT count(*) INTO n FROM {table};\n"
               f"  IF n <> {count} THEN RAISE EXCEPTION 'restore check failed: {table} has % "
               f"rows, the backup has {count}', n; END IF;\n")
    yield "END $verify$;\n"
    yield "COMMIT;\n" if commit else "ROLLBACK;\n"


# ------------------------------------------------------------------ run restore
def write_login(p: Project) -> tuple[str, str]:
    """Temporary login with postgres rights (expires on its own). Returns (url, password).
    Uses the direct connection (needs IPv6), else the Session pooler."""
    r = mgmt_api("POST", f"/projects/{p.ref}/cli/login-role", json={"read_only": False})
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Creating a temporary login failed ({r.status_code}): {r.text}")
    login = r.json()
    env = {**os.environ, "PGPASSWORD": login["password"]}
    direct = f"postgresql://{login['role']}@db.{p.ref}.supabase.co:5432/postgres"
    if subprocess.run(["psql", direct, "--no-psqlrc", "-tAc", "select 1"], env=env,
                      capture_output=True).returncode == 0:
        return direct, login["password"]
    r = mgmt_api("GET", f"/projects/{p.ref}/config/database/pooler")
    pooler = next((x for x in r.json() if x.get("database_type") == "PRIMARY"), r.json()[0])
    print("Direct connection not available, using the Session pooler")
    return (f"postgresql://{login['role']}.{p.ref}@{pooler['db_host']}:5432/postgres",
            login["password"])


def current_counts(url: str, password: str) -> tuple[int, int]:
    r = subprocess.run(["psql", url, "--no-psqlrc", "-tA", "-F", " ", "-c", "set role postgres",
                        "-c", "select (select count(*) from pg_tables where schemaname = 'public'), "
                              "(select count(*) from auth.users)"],
                       env={**os.environ, "PGPASSWORD": password}, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"Cannot connect to the target database: {r.stderr.strip()}")
    tables, users = r.stdout.strip().splitlines()[-1].split()  # first line is "SET"
    return int(tables), int(users)


def run_restore(url: str, password: str, gz_path: str, info: DumpInfo, commit: bool) -> None:
    proc = subprocess.Popen(["psql", url, "--no-psqlrc", "--quiet", "-v", "ON_ERROR_STOP=1"],
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, env={**os.environ, "PGPASSWORD": password})
    with tempfile.TemporaryFile() as err_buf:  # drain stderr so psql never blocks
        t = threading.Thread(target=shutil.copyfileobj, args=(proc.stderr, err_buf), daemon=True)
        t.start()
        try:
            for line in restore_sql(gz_path, info, commit):
                proc.stdin.write(line.encode("utf-8"))
        except BrokenPipeError:
            pass  # psql stopped on an error; reported below
        finally:
            try:
                proc.stdin.close()
            except BrokenPipeError:
                pass
        proc.wait()
        t.join()
        err_buf.seek(0)
        err = err_buf.read().decode(errors="replace")
    for line in err.splitlines():
        if "WARNING" in line:
            print(f"  {line.strip()}")
    if proc.returncode != 0:
        errors = [l for l in err.splitlines() if "ERROR" in l or "FATAL" in l] or err.splitlines()
        raise RuntimeError("Restore failed and was rolled back, nothing changed:\n  "
                           + "\n  ".join(errors[:10]))


def main() -> None:
    ap = argparse.ArgumentParser(description="Restore a Supabase database from a backup.")
    ap.add_argument("--project", help="project to take the backup from: name, prefix "
                                      "from BACKUP_PROJECTS, or 'Name=prefix'")
    ap.add_argument("--date", help="day of the backup, YYYY-MM-DD (asks when omitted)")
    ap.add_argument("--time", help="time of the backup that day, HHMMSS (default: latest)")
    ap.add_argument("--target", help="restore into this project instead (default: the same)")
    ap.add_argument("--dry-run", action="store_true",
                    help="do the complete restore and checks, then roll back (changes nothing)")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation question")
    args = ap.parse_args()
    # Command line > .env > RESTORE SETTINGS at the top of this file.
    args.project = args.project or os.environ.get("RESTORE_PROJECT") or RESTORE_PROJECT or None
    args.date = args.date or os.environ.get("RESTORE_DATE") or RESTORE_DATE or None
    args.time = args.time or os.environ.get("RESTORE_TIME") or RESTORE_TIME or None
    args.target = args.target or os.environ.get("RESTORE_TARGET") or RESTORE_TARGET or None

    projects = all_projects()
    if not args.project:
        cfg = configured_projects()
        if not cfg:
            raise RuntimeError("Give --project (BACKUP_PROJECTS in .env is empty)")
        print("Projects (BACKUP_PROJECTS):")
        for i, (name, prefix) in enumerate(cfg, 1):
            print(f"  {i}. {name} ({prefix})")
        answer = input("Project to restore [1]: ").strip() or "1"
        args.project = cfg[int(answer) - 1][0] if answer.isdigit() else answer

    source = find_project(projects, args.project)
    target = find_project(projects, args.target) if args.target else source
    if target.status != "ACTIVE_HEALTHY":
        raise RuntimeError(f"{target.name} is not running (status {target.status})")
    fetch_service_key(source)

    remote_path = choose_backup(list_backups(source), args.date, args.time)
    url, password = write_login(target)
    tables, users = current_counts(url, password)

    print(f"\nBackup : {source.name}: {BUCKET}/{remote_path}")
    print(f"Target : {target.name} ({target.ref})")
    print(f"         now has {tables} table(s) in public and {users} auth user(s); "
          "these will be REPLACED by the backup")
    if args.dry_run:
        print("Dry run: the restore is done and checked, then rolled back.")
    elif not args.yes:
        answer = input(f"Restore into '{target.name}' now? [y/N]: ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return

    with tempfile.TemporaryDirectory() as tmp:
        gz_path = os.path.join(tmp, os.path.basename(remote_path))
        download(source, remote_path, gz_path)
        info = scan_dump(gz_path)
        print(f"Backup contains {len(info.rows)} tables to restore "
              f"({sum(info.rows.values())} rows), schemas: {', '.join(sorted(info.user_schemas))}")
        print("Restoring (one transaction)...")
        run_restore(url, password, gz_path, info, commit=not args.dry_run)

    if args.dry_run:
        print(f"Dry run OK: all {len(info.rows)} tables restored with the backup's row "
              "counts, then rolled back. Nothing changed.")
    else:
        tables, users = current_counts(url, password)
        print(f"Restored and verified: {len(info.rows)} tables match the backup "
              f"({tables} tables in public, {users} auth users now).")
    print("Done.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
