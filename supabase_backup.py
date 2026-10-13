#!/usr/bin/env python3
"""Back up the Supabase projects listed in BACKUP_PROJECTS.

Only two settings are needed (GitHub Actions secret/variable, or .env locally):

  SUPABASE_ACCESS_TOKEN   personal access token (secret). With it the script finds
                          each project by name, creates a temporary read-only
                          database login (no stored password) and gets the
                          project's Storage key.
  BACKUP_PROJECTS         comma-separated project names as shown in the dashboard,
                          each optionally "=<file prefix>", e.g.
                            Hygieia Database=hygieia, Pulse
                          Without "=", the prefix is the name in lower case with
                          spaces -> "-" (Pulse -> pulse).

For every project this
  1. takes a complete logical backup with pg_dump (whole database, gzipped),
  2. uploads it to the private `db-backups` bucket of that database's own project:
       db-backups/production/<YYYY>/<MM>/<DD>/<name>-<YYYYMMDD>-<HHMMSS>.sql.gz
  3. after a successful upload, deletes that database's backups older than
     RETENTION_DAYS (the newest backup is always kept).

Paused projects are reported as failed (they cannot be dumped).

Usage:
  python supabase_backup.py                # every project in BACKUP_PROJECTS
  python supabase_backup.py hygieia        # only this one (name or prefix)
  python supabase_backup.py --dry-run      # check config, connections, buckets and
                                           # show what would be deleted; changes nothing
"""
import argparse
import gzip
import os
import re
import secrets
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests
from dotenv import load_dotenv

HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(HERE, ".env"))  # local runs; on GitHub Actions secrets are env vars

ACCESS_TOKEN = os.environ.get("SUPABASE_ACCESS_TOKEN", "")

BUCKET = "db-backups"
ENV_FOLDER = "production"

# Time zone for the date folders and the file time stamp. One of:
#   "UTC", "UTC+5", "UTC-3:30" (fixed offset), "local" (this computer's clock),
#   or a region name such as "Asia/Karachi" (needs `pip install tzdata` on Windows).
# Can be overridden per run with --timezone.
TIMEZONE = "UTC+5"

# Backups older than this many days are deleted after each successful backup
# (the newest backup of each database is always kept).
# Can be overridden per run with --retention-days.
RETENTION_DAYS = 7


@dataclass
class Target:
    project: str       # Supabase project name, as in the dashboard
    name: str          # backup file prefix: <name>-YYYYMMDD-HHMMSS.sql.gz
    ref: str = ""      # Supabase project ref (looked up from the name)
    status: str = ""   # ACTIVE_HEALTHY, INACTIVE (paused), ...
    db_url: str = ""   # pooler connection string without password
    password: str = ""
    service_key: str = ""

    @property
    def storage_url(self) -> str:
        return f"https://{self.ref}.supabase.co/storage/v1"


def mgmt_api(method: str, path: str, **kwargs) -> requests.Response:
    """Call the Supabase Management API with the access token."""
    return requests.request(method, f"https://api.supabase.com/v1{path}", timeout=60,
                            headers={"Authorization": f"Bearer {ACCESS_TOKEN}"}, **kwargs)


def load_targets() -> list[Target]:
    """Projects listed in BACKUP_PROJECTS, looked up by name with the access token.

    BACKUP_PROJECTS is a comma-separated list of project names, each optionally
    followed by "=<file prefix>"; without it the prefix is the name in lower case
    with spaces -> "-" (Hygieia Database -> hygieia-database).
    """
    if not ACCESS_TOKEN:
        raise RuntimeError("SUPABASE_ACCESS_TOKEN is not set (secret or .env)")
    wanted = [p.strip() for p in os.environ.get("BACKUP_PROJECTS", "").split(",") if p.strip()]
    if not wanted:
        raise RuntimeError("BACKUP_PROJECTS is empty: list the project names to back up")

    r = mgmt_api("GET", "/projects")
    if r.status_code != 200:
        raise RuntimeError(f"Listing projects failed ({r.status_code}): {r.text}")
    projects = r.json()

    targets: list[Target] = []
    for entry in wanted:
        project, _, prefix = (s.strip() for s in entry.partition("="))
        prefix = prefix or re.sub(r"[^a-z0-9]+", "-", project.lower()).strip("-")
        matches = [p for p in projects if p["name"].strip().lower() == project.lower()]
        if not matches:
            raise RuntimeError(f"No project named '{project}' (token can see: "
                               f"{', '.join(p['name'] for p in projects)})")
        if len(matches) > 1:
            raise RuntimeError(f"More than one project named '{project}': "
                               f"{', '.join(p['id'] for p in matches)}")
        if any(t.name == prefix for t in targets):
            raise RuntimeError(f"Two projects use the backup prefix '{prefix}'")
        targets.append(Target(matches[0]["name"], prefix, matches[0]["id"],
                              matches[0].get("status", "UNKNOWN")))
    return targets


# ============ BEGIN: temporary database login (no stored password) ============
BACKUP_ROLE = "db_backup_reader"
LOGIN_VALID_HOURS = 2


def create_temp_login(t: Target) -> None:
    """Give t's database a read-only login with a fresh random password that
    expires after LOGIN_VALID_HOURS, and point t at the Session pooler (which
    also works without IPv6, e.g. on GitHub Actions).

    The role is created once and kept, only its password changes each run: the
    pooler caches roles, so a role that is dropped and re-created (as the
    Supabase CLI's /cli/login-role does) fails there with "invalid role OID".
    It can read every table (pg_read_all_data) and is not limited by row-level
    security (BYPASSRLS), so the dump is complete; it cannot change anything.
    """
    r = mgmt_api("GET", f"/projects/{t.ref}/config/database/pooler")
    if r.status_code != 200:
        raise RuntimeError(f"Reading the pooler config failed ({r.status_code}): {r.text}")
    pooler = next((p for p in r.json() if p.get("database_type") == "PRIMARY"), r.json()[0])

    password = secrets.token_urlsafe(32)  # letters, digits, "-" and "_": safe in SQL
    expires = datetime.now(timezone.utc) + timedelta(hours=LOGIN_VALID_HOURS)
    sql = f"""
        do $$ begin
            if not exists (select from pg_roles where rolname = '{BACKUP_ROLE}') then
                create role {BACKUP_ROLE} login;
            end if;
        end $$;
        alter role {BACKUP_ROLE} with login bypassrls password '{password}'
            valid until '{expires:%Y-%m-%d %H:%M:%S}+00';
        grant pg_read_all_data to {BACKUP_ROLE};
    """
    r = mgmt_api("POST", f"/projects/{t.ref}/database/query", json={"query": sql})
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Preparing the backup login failed ({r.status_code}): {r.text}")
    t.password = password
    # Session mode runs on port 5432 of the pooler; its user is <role>.<project ref>.
    t.db_url = (f"postgresql://{BACKUP_ROLE}.{t.ref}@{pooler['db_host']}:5432/"
                f"{pooler.get('db_name') or 'postgres'}")
# ============= END: temporary database login (no stored password) =============


def fetch_service_key(t: Target) -> None:
    """Get t's project secret (service role) key, used for Storage."""
    r = mgmt_api("GET", f"/projects/{t.ref}/api-keys", params={"reveal": "true"})
    if r.status_code != 200:
        raise RuntimeError(f"Fetching the service key failed ({r.status_code}): {r.text}")
    keys = r.json()
    secret = [k["api_key"] for k in keys if k.get("type") == "secret" and k.get("api_key")]
    legacy = [k["api_key"] for k in keys if k.get("name") == "service_role" and k.get("api_key")]
    if not (secret or legacy):
        raise RuntimeError(f"Project {t.ref} has no secret / service_role key")
    t.service_key = (secret or legacy)[0]


def storage_headers(t: Target) -> dict[str, str]:
    return {"Authorization": f"Bearer {t.service_key}", "apikey": t.service_key}


def pg_env(t: Target) -> dict[str, str]:
    env = dict(os.environ)
    if t.password:
        env["PGPASSWORD"] = t.password
    return env


def check_connection(t: Target) -> None:
    r = subprocess.run(["psql", t.db_url, "--no-psqlrc", "-tAc", "select version()"],
                       env=pg_env(t), capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"Cannot connect to the database: {r.stderr.strip()}")
    print(f"Connected: {r.stdout.strip().split(' on ')[0]}")


def ensure_private_bucket(t: Target, create: bool) -> None:
    """Make sure the backup bucket exists in t's project and is private."""
    r = requests.get(f"{t.storage_url}/bucket/{BUCKET}", headers=storage_headers(t), timeout=60)
    if r.status_code == 200:
        if r.json().get("public"):
            raise RuntimeError(f"Bucket {BUCKET} in {t.ref} is PUBLIC; make it private first")
        return
    if not create:
        print(f"Bucket {BUCKET} does not exist yet; it will be created (private) on a real run")
        return
    print(f"Creating private bucket {BUCKET} ...")
    r = requests.post(f"{t.storage_url}/bucket", headers=storage_headers(t), timeout=60,
                      json={"id": BUCKET, "name": BUCKET, "public": False})
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Creating bucket {BUCKET} failed ({r.status_code}): {r.text}")


def dump_database(t: Target, out_path: str) -> None:
    """Complete logical backup of the whole database with pg_dump, gzipped to out_path."""
    print("Running pg_dump (whole database)...")
    tail = b""
    with gzip.open(out_path, "wb") as gz:
        proc = subprocess.Popen(["pg_dump", t.db_url], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=pg_env(t))
        for chunk in iter(lambda: proc.stdout.read(1024 * 1024), b""):
            gz.write(chunk)
            tail = (tail + chunk)[-4096:]
        _, err = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"pg_dump failed: {err.decode(errors='replace')}")
    # pg_dump writes this marker last; without it the dump is incomplete.
    if b"PostgreSQL database dump complete" not in tail:
        raise RuntimeError("pg_dump output is incomplete (end marker missing)")


def upload(t: Target, local_path: str, remote_path: str) -> None:
    print(f"Uploading to {BUCKET}/{remote_path} ...")
    headers = {**storage_headers(t), "Content-Type": "application/gzip", "x-upsert": "false"}
    with open(local_path, "rb") as f:
        r = requests.post(f"{t.storage_url}/object/{BUCKET}/{remote_path}",
                          headers=headers, data=f, timeout=1800)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Upload failed ({r.status_code}): {r.text}")


# ===================== BEGIN: retention period =====================
def apply_retention(t: Target, days: int, tz: tzinfo | None, dry_run: bool = False) -> None:
    """Delete t's backups older than `days` days from its project's bucket.

    A backup's age comes from the time stamp in its file name
    (<name>-YYYYMMDD-HHMMSS.sql.gz). The newest backup is always kept, and
    files that do not belong to t are never touched.
    """
    if days < 1:
        raise RuntimeError(f"Retention period must be at least 1 day, got {days}")

    def list_folder(prefix: str) -> list[str]:
        names, offset = [], 0
        while True:
            r = requests.post(f"{t.storage_url}/object/list/{BUCKET}",
                              headers=storage_headers(t), timeout=60, json={
                                  "prefix": prefix, "limit": 1000, "offset": offset,
                                  "sortBy": {"column": "name", "order": "asc"}})
            if r.status_code != 200:
                raise RuntimeError(f"Listing {BUCKET}/{prefix} failed ({r.status_code}): {r.text}")
            page = [item["name"] for item in r.json()]
            names += page
            if len(page) < 1000:
                return names
            offset += 1000

    def subfolders(path: str) -> list[str]:
        # month/day folders may be "1" or "01"
        return [n for n in list_folder(path) if re.fullmatch(r"\d{1,4}", n)]

    # Case-insensitive, so older "Hygieia-..." files count as hygieia's backups.
    pattern = re.compile(rf"^{re.escape(t.name)}-(\d{{8}}-\d{{6}})\.sql\.gz$", re.IGNORECASE)
    backups: list[tuple[datetime, str]] = []
    for year in subfolders(ENV_FOLDER):
        for month in subfolders(f"{ENV_FOLDER}/{year}"):
            for day in subfolders(f"{ENV_FOLDER}/{year}/{month}"):
                day_path = f"{ENV_FOLDER}/{year}/{month}/{day}"
                for name in list_folder(day_path):
                    m = pattern.match(name)
                    if m:
                        stamp = datetime.strptime(m.group(1), "%Y%m%d-%H%M%S")
                        backups.append((stamp, f"{day_path}/{name}"))

    cutoff = datetime.now(tz).replace(tzinfo=None) - timedelta(days=days)
    backups.sort()
    expired = [path for stamp, path in backups[:-1] if stamp < cutoff]  # [:-1] keeps the newest
    print(f"Retention ({days} days, cutoff {cutoff:%Y-%m-%d %H:%M:%S}): "
          f"{len(backups)} backup(s), {len(expired)} expired")
    for path in expired:
        print(f"  {'Would delete' if dry_run else 'Deleting'} {BUCKET}/{path}")
    if expired and not dry_run:
        # The Storage API deletes up to 1000 objects per request.
        for i in range(0, len(expired), 1000):
            r = requests.delete(f"{t.storage_url}/object/{BUCKET}", headers=storage_headers(t),
                                json={"prefixes": expired[i:i + 1000]}, timeout=60)
            if r.status_code != 200:
                raise RuntimeError(f"Deleting expired backups failed ({r.status_code}): {r.text}")
# ====================== END: retention period ======================


def parse_timezone(name: str) -> tzinfo | None:
    """Turn a TIMEZONE setting into a tzinfo (None means this computer's local time)."""
    if name.lower() == "local":
        return None
    m = re.fullmatch(r"UTC(?:([+-])(\d{1,2})(?::(\d{2}))?)?", name.strip(), re.IGNORECASE)
    if m:
        if not m.group(1):
            return timezone.utc
        offset = timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0))
        return timezone(-offset if m.group(1) == "-" else offset)
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise RuntimeError(f"Unknown time zone '{name}' (use UTC, UTC+5, local or e.g. "
                           "Asia/Karachi; region names need `pip install tzdata`)") from None


def backup(t: Target, tz: tzinfo | None, retention_days: int, dry_run: bool) -> None:
    if t.status != "ACTIVE_HEALTHY":
        raise RuntimeError(f"Project is not running (status {t.status}); "
                           "paused projects cannot be backed up")
    fetch_service_key(t)
    ensure_private_bucket(t, create=not dry_run)

    create_temp_login(t)
    check_connection(t)
    if dry_run:
        apply_retention(t, retention_days, tz, dry_run=True)
        return
    now = datetime.now(tz)
    filename = f"{t.name}-{now:%Y%m%d-%H%M%S}.sql.gz"
    remote_path = f"{ENV_FOLDER}/{now:%Y}/{now:%m}/{now:%d}/{filename}"
    with tempfile.TemporaryDirectory() as tmp:
        local_path = os.path.join(tmp, filename)
        dump_database(t, local_path)
        print(f"Backup created: {filename} ({os.path.getsize(local_path) / 1024 / 1024:.2f} MB)")
        upload(t, local_path, remote_path)

    # Only reached after a successful upload.
    apply_retention(t, retention_days, tz)


def main() -> None:
    p = argparse.ArgumentParser(description="Back up the projects listed in BACKUP_PROJECTS.")
    p.add_argument("name", nargs="?",
                   help="only this project (name or backup prefix; default: all)")
    p.add_argument("--timezone", default=TIMEZONE,
                   help=f"UTC, UTC+5, local, Asia/Karachi, ... (default: {TIMEZONE})")
    p.add_argument("--retention-days", type=int, default=RETENTION_DAYS,
                   help=f"delete backups older than this many days (default: {RETENTION_DAYS})")
    p.add_argument("--dry-run", action="store_true",
                   help="check config, connections and buckets and show what retention "
                        "would delete; no backup, upload or delete")
    args = p.parse_args()
    tz = parse_timezone(args.timezone)
    print(f"Time zone: {args.timezone} -> now {datetime.now(tz):%Y-%m-%d %H:%M:%S}")

    targets = load_targets()
    if args.name:
        known = ", ".join(t.name for t in targets)
        wanted = args.name.lower()
        targets = [t for t in targets if wanted in (t.name, t.project.lower())]
        if not targets:
            raise RuntimeError(f"'{args.name}' is not in BACKUP_PROJECTS (known: {known})")

    failed = []
    for t in targets:
        print(f"=== {t.project} -> {t.name} ({t.ref}) ===")
        try:
            backup(t, tz, args.retention_days, args.dry_run)
        except Exception as e:
            print(f"ERROR ({t.name}): {e}", file=sys.stderr)
            failed.append(t.name)

    if failed:
        raise RuntimeError(f"Backup failed for: {', '.join(failed)}")
    print("Done.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
