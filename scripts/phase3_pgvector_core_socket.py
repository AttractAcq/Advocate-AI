"""Run the built Core image against pgvector over a private Unix socket."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
import uuid

from scripts.synthetic_pg_fixture import fixture as _fixture, put as _put
from infrastructure.deploy.container_runtime import (
    RuntimeError as ProductRuntimeError, _health as _product_health,
)
from infrastructure.deploy.postgres_socket import (
    ready as _ready, secure_database as _secure_database,
)

_IMAGE = re.compile(r"(?:(?:docker.io/)?pgvector/pgvector@sha256:[0-9a-f]{64}"
                    r"|sovereign-knowledge:synthetic)\Z")
_CORE = re.compile(r"sovereign-core:[a-z0-9-]{1,40}\Z")
_WRITER_DSN = "postgresql://sovereign_ingest@/postgres?host=/run/postgresql"
_MIGRATION_DSN = "postgresql://sovereign_migrate@/postgres?host=/run/postgresql"
_READER_DSN = "postgresql://sovereign_read@/postgres?host=/run/postgresql"
_STAGING = Path(__file__).resolve().parents[1] / "infrastructure/lab/runtime"


def _docker(*args: str, timeout: int = 120) -> str:
    try:
        result = subprocess.run(["docker", *args], capture_output=True, text=True,
                                check=True, timeout=timeout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"synthetic socket Docker operation failed: {args[0]}") from exc
    return result.stdout.strip()


def _credentials(root: Path) -> tuple[Path, Path, Path, Path, str, str, str]:
    admin = root / "postgres-admin-password"
    migrate = root / "postgres-migrate.pgpass"
    writer = root / "postgres-writer.pgpass"
    reader = root / "postgres-reader.pgpass"
    admin_secret = secrets.token_hex(32)
    migration_secret = secrets.token_hex(32)
    writer_secret = secrets.token_hex(32)
    reader_secret = secrets.token_hex(32)
    _put(admin, (admin_secret + "\n").encode())
    _put(migrate, (f"/run/postgresql:5432:postgres:sovereign_migrate:{migration_secret}\n").encode())
    _put(writer, (f"/run/postgresql:5432:postgres:sovereign_ingest:{writer_secret}\n").encode())
    _put(reader, (f"/run/postgresql:5432:postgres:sovereign_read:{reader_secret}\n").encode())
    return admin, migrate, writer, reader, migration_secret, writer_secret, reader_secret


_SCHEMA_SETUP = """\
from services.knowledge.postgres_index import _connect, initialize_schema
dsn='postgresql://sovereign_migrate@/postgres?host=/run/postgresql'
initialize_schema(dsn)
with _connect(dsn) as db:
 db.execute('GRANT SELECT, INSERT, UPDATE, DELETE ON knowledge_sources, knowledge_passages, knowledge_quarantine, knowledge_vectors TO sovereign_ingest')
 db.execute('GRANT SELECT ON knowledge_sources, knowledge_passages, knowledge_quarantine, knowledge_vectors TO sovereign_read')
"""


_BOOTSTRAP = """\
import os
from pathlib import Path
from services.knowledge.ingestion import sync_manifest
from services.knowledge.embedding import build_vectors, vector_search
root=Path('/var/lib/sovereign')
dsn=os.environ['SOVEREIGN_KNOWLEDGE_DB']
result=sync_manifest(root, root/'approved.json', dsn)
assert result['indexed']==['ENG-001','DEC-001'], result
class TestEmbedder:
 model='synthetic-core-socket'
 def embed(self, texts):
  return [[float('generator' in text.casefold()),float('deck' in text.casefold())] for text in texts]
assert build_vectors(dsn,TestEmbedder())==2
assert [r['document_id'] for r in vector_search(root,root/'approved.json',dsn,'engineer','generator',TestEmbedder())]==['ENG-001']
"""

_API_CHECK = """\
import json, os, psycopg
from pathlib import Path
import httpx
from services.knowledge.postgres_index import _connect
root=Path('/var/lib/sovereign')
password=Path('/run/secrets/lab-password').read_text().strip()
dsn=os.environ['SOVEREIGN_KNOWLEDGE_DB']
with _connect(dsn) as db:
 assert db.execute('SELECT current_user').fetchone()['current_user']=='sovereign_read'
def denied(statement):
 try:
  with _connect(dsn) as db:
   db.execute(statement)
 except psycopg.errors.InsufficientPrivilege:
  return
 raise AssertionError('Core database role acquired write or schema permission')
denied("INSERT INTO knowledge_quarantine VALUES ('FORBIDDEN','core-write')")
denied('CREATE TABLE core_must_not_create (id integer)')
try:
 psycopg.connect('postgresql://sovereign_ingest@/postgres?host=/run/postgresql',connect_timeout=3)
except psycopg.OperationalError:
 pass
else:
 raise AssertionError('Core could authenticate as ingestion writer')
with httpx.Client(base_url='http://127.0.0.1:18100',trust_env=False,timeout=5) as client:
 def auth(user):
  response=client.post('/api/login',json={'user_id':user,'password':password})
  assert response.status_code==200,response.text
  return {'Authorization':'Bearer '+response.json()['access_token']}
 engineer=auth('engineer')
 deckhand=auth('deckhand')
 allowed=client.post('/api/search',headers=engineer,json={'query':'generator inspection'})
 assert allowed.status_code==200,allowed.text
 assert [r['document_id'] for r in allowed.json()['results']]==['ENG-001']
 denied=client.post('/api/search',headers=deckhand,json={'query':'generator inspection'})
 assert denied.status_code==200 and denied.json()['results']==[],denied.text
 preview=client.get('/api/sources/ENG-001/preview',headers=engineer)
 assert preview.status_code==200 and preview.json()['excerpt']=='generator inspection secret marker',preview.text
 assert client.get('/api/sources/ENG-001/preview',headers=deckhand).status_code==404
 policy=json.loads((root/'roles.json').read_text())
 policy['document_rules']={'ENG-001':{'deny_users':['engineer']}}
 (root/'roles.json').write_text(json.dumps(policy))
 revoked=client.post('/api/search',headers=engineer,json={'query':'generator inspection'})
 assert revoked.status_code==200 and revoked.json()['results']==[],revoked.text
 print(json.dumps({'result':'pass','sources':2,'denied_role':'deckhand','revocation':'denied',
                   'database_role':'sovereign_read','database_write':'denied',
                   'writer_auth':'denied'}))
"""


def rehearse(image: str, core_image: str) -> dict[str, object]:
    if not _IMAGE.fullmatch(image) or not _CORE.fullmatch(core_image):
        raise ValueError("socket rehearsal requires a pinned or built Knowledge and named Core image")
    return _rehearse_verified_images(image, core_image)


def _rehearse_verified_images(image: str, core_image: str,
                             console_image: str | None = None) -> dict[str, object]:
    """Exercise image IDs already bound to verified signed archives."""
    name = f"sovereign-pg-socket-{uuid.uuid4().hex[:12]}"
    volume = ""
    network = ""
    created: list[str] = []
    try:
        _STAGING.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(prefix="sovereign-core-socket-", dir=_STAGING) as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir(mode=0o700)
            _fixture(state)
            credential = root / "lab-password"
            _put(credential, (secrets.token_urlsafe(24) + "\n").encode())
            admin_password, migrate_passfile, writer_passfile, reader_passfile, \
                migration_secret, writer_secret, reader_secret = \
                _credentials(root)
            if console_image is not None:
                config = root / "console-config.json"
                config.write_bytes(b'{"schema":1,"oidc_issuer":null}\n')
                config.chmod(0o644)
                network = _docker("network", "create", "--internal", name)
                if _docker("network", "inspect", network, "--format", "{{.Internal}}") != "true":
                    raise RuntimeError("signed product network is not internal")
            volume = _docker("volume", "create", name + "-socket")
            pg = _docker("run", "-d", "--rm", "--pull", "never", "--name", name + "-postgres",
                         "--network", "none", "--tmpfs", "/var/lib/postgresql/data",
                         "--mount", f"type=volume,source={volume},target=/var/run/postgresql",
                         "--mount", (f"type=bind,source={admin_password.resolve()},"
                                     "target=/run/secrets/postgres-password,readonly"),
                         "-e", "POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password", image)
            created.append(pg)
            _ready(pg)
            _secure_database(pg, migration_secret, writer_secret, reader_secret)
            _docker("run", "--rm", "--pull", "never", "--name", name + "-migrate",
                    "--network", "none", "--read-only",
                    "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                    "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                    "--user", f"{os.getuid()}:{os.getgid()}",
                    "--mount", f"type=volume,source={volume},target=/run/postgresql,readonly",
                    "--mount", (f"type=bind,source={migrate_passfile.resolve()},"
                                "target=/run/secrets/pgpass,readonly"),
                    "-e", f"SOVEREIGN_KNOWLEDGE_DB={_MIGRATION_DSN}",
                    "-e", "PGPASSFILE=/run/secrets/pgpass",
                    core_image, "python", "-c", _SCHEMA_SETUP)
            _docker("run", "--rm", "--pull", "never", "--name", name + "-ingest",
                    "--network", "none", "--read-only",
                    "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                    "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                    "--user", f"{os.getuid()}:{os.getgid()}",
                    "--mount", f"type=volume,source={volume},target=/run/postgresql,readonly",
                    "--mount", f"type=bind,source={state.resolve()},target=/var/lib/sovereign,readonly",
                    "--mount", (f"type=bind,source={writer_passfile.resolve()},"
                                "target=/run/secrets/pgpass,readonly"),
                    "-e", f"SOVEREIGN_KNOWLEDGE_DB={_WRITER_DSN}",
                    "-e", "PGPASSFILE=/run/secrets/pgpass",
                    core_image, "python", "-c", _BOOTSTRAP)
            core = _docker("run", "-d", "--rm", "--pull", "never", "--name", name + "-core",
                           "--network", name if network else "none",
                           *(["--network-alias", "core"] if network else []),
                           "--read-only",
                           "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                           "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                           "--user", f"{os.getuid()}:{os.getgid()}",
                           "--mount", f"type=volume,source={volume},target=/run/postgresql,readonly",
                           "--mount", f"type=bind,source={state.resolve()},target=/var/lib/sovereign",
                           "--mount", f"type=bind,source={credential.resolve()},target=/run/secrets/lab-password,readonly",
                           "--mount", (f"type=bind,source={reader_passfile.resolve()},"
                                       "target=/run/secrets/pgpass,readonly"),
                           "-e", "SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign",
                           "-e", "SOVEREIGN_KNOWLEDGE_MANIFEST=/var/lib/sovereign/approved.json",
                           "-e", f"SOVEREIGN_KNOWLEDGE_DB={_READER_DSN}",
                           "-e", "PGPASSFILE=/run/secrets/pgpass",
                           "-e", "SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password",
                           core_image)
            created.append(core)
            if console_image is not None:
                console = _docker("run", "-d", "--rm", "--pull", "never",
                                  "--name", name + "-console", "--network", name,
                                  "--network-alias", "console", "--read-only",
                                  "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                                  "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                                  "--mount", (f"type=bind,source={config.resolve()},"
                                              "target=/srv/console-config.json,readonly"),
                                  console_image)
                created.append(console)
            for identifier in created:
                expected_network = (name if network and identifier in (core, console) else "none")
                if (_docker("inspect", identifier, "--format", "{{.HostConfig.NetworkMode}}") != expected_network
                        or _docker("inspect", identifier, "--format",
                                   "{{json .HostConfig.PortBindings}}") not in ("null", "{}")):
                    raise RuntimeError("synthetic socket runtime exposed a network route")
            for attempt in range(30):
                try:
                    _docker("exec", core, "python", "-c",
                            'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:18100/health", timeout=2).status==200')
                    if network:
                        _product_health(core)
                    break
                except (RuntimeError, ProductRuntimeError) as exc:
                    if attempt == 29:
                        if network:
                            probe = subprocess.run(
                                ["docker", "exec", core, "python", "-c",
                                 'import urllib.request; urllib.request.urlopen('
                                 '"http://console:8080/console-config.json", timeout=3)'],
                                capture_output=True, text=True, timeout=10)
                            status = _docker("inspect", console, "--format",
                                             "{{.State.Status}}")
                            raise RuntimeError(
                                "signed Console health failed: "
                                f"container={status}; probe={probe.stderr[-600:]}") from exc
                        raise
                    time.sleep(1)
            result = json.loads(_docker("exec", core, "python", "-c", _API_CHECK))
            return {**result, "pgvector_image": image, "core_image": core_image,
                    "network_mode": "internal" if network else "none",
                    "knowledge_network_mode": "none",
                    "console_runtime": "healthy" if network else "not-started",
                    "database_transport": "unix-socket"}
    finally:
        for identifier in reversed(created):
            subprocess.run(["docker", "rm", "-f", identifier], capture_output=True,
                           text=True, timeout=30)
        if volume:
            subprocess.run(["docker", "volume", "rm", volume], capture_output=True,
                           text=True, timeout=30)
        if network:
            subprocess.run(["docker", "network", "rm", network], capture_output=True,
                           text=True, timeout=30)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pgvector-image", required=True)
    parser.add_argument("--core-image", required=True)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.pgvector_image, args.core_image), sort_keys=True))


if __name__ == "__main__":
    main()
