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

_IMAGE = re.compile(r"(?:docker.io/)?pgvector/pgvector@sha256:[0-9a-f]{64}\Z")
_CORE = re.compile(r"sovereign-core:[a-z0-9-]{1,40}\Z")
_DSN = "postgresql://sovereign@/postgres?host=/run/postgresql"
_STAGING = Path(__file__).resolve().parents[1] / "infrastructure/lab/runtime"


def _docker(*args: str, timeout: int = 120) -> str:
    try:
        result = subprocess.run(["docker", *args], capture_output=True, text=True,
                                check=True, timeout=timeout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"synthetic socket Docker operation failed: {args[0]}") from exc
    return result.stdout.strip()


def _ready(identifier: str) -> None:
    for _ in range(40):
        result = subprocess.run(["docker", "exec", "-u", "postgres", identifier,
                                 "pg_isready", "-q", "-d", "postgres"],
                                capture_output=True, timeout=10)
        if result.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("synthetic socket PostgreSQL server did not become ready")


def _sql(identifier: str, statement: str) -> str:
    return _docker("exec", "-u", "postgres", identifier, "psql", "-X",
                   "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-Atqc", statement)

_BOOTSTRAP = """\
import os
from pathlib import Path
from services.knowledge.postgres_index import initialize_schema
from services.knowledge.ingestion import sync_manifest
from services.knowledge.embedding import build_vectors, vector_search
root=Path('/var/lib/sovereign')
dsn=os.environ['SOVEREIGN_KNOWLEDGE_DB']
initialize_schema(dsn)
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
import json
from pathlib import Path
import httpx
root=Path('/var/lib/sovereign')
password=Path('/run/secrets/lab-password').read_text().strip()
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
 print(json.dumps({'result':'pass','sources':2,'denied_role':'deckhand','revocation':'denied'}))
"""


def rehearse(image: str, core_image: str) -> dict[str, object]:
    if not _IMAGE.fullmatch(image) or not _CORE.fullmatch(core_image):
        raise ValueError("socket rehearsal requires a pinned pgvector and named local Core image")
    name = f"sovereign-pg-socket-{uuid.uuid4().hex[:12]}"
    volume = ""
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
            volume = _docker("volume", "create", name + "-socket")
            pg = _docker("run", "-d", "--rm", "--pull", "never", "--name", name + "-postgres",
                         "--network", "none", "--tmpfs", "/var/lib/postgresql/data",
                         "--mount", f"type=volume,source={volume},target=/var/run/postgresql",
                         "-e", "POSTGRES_HOST_AUTH_METHOD=trust", image)
            created.append(pg)
            _ready(pg)
            _sql(pg, "CREATE EXTENSION vector")
            _sql(pg, "CREATE ROLE sovereign LOGIN")
            _sql(pg, "GRANT CREATE ON SCHEMA public TO sovereign")
            core = _docker("run", "-d", "--rm", "--pull", "never", "--name", name + "-core",
                           "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                           "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                           "--user", f"{os.getuid()}:{os.getgid()}",
                           "--mount", f"type=volume,source={volume},target=/run/postgresql,readonly",
                           "--mount", f"type=bind,source={state.resolve()},target=/var/lib/sovereign",
                           "--mount", f"type=bind,source={credential.resolve()},target=/run/secrets/lab-password,readonly",
                           "-e", "SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign",
                           "-e", "SOVEREIGN_KNOWLEDGE_MANIFEST=/var/lib/sovereign/approved.json",
                           "-e", f"SOVEREIGN_KNOWLEDGE_DB={_DSN}",
                           "-e", "SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password",
                           core_image)
            created.append(core)
            for identifier in created:
                if (_docker("inspect", identifier, "--format", "{{.HostConfig.NetworkMode}}") != "none"
                        or _docker("inspect", identifier, "--format",
                                   "{{json .HostConfig.PortBindings}}") not in ("null", "{}")):
                    raise RuntimeError("synthetic socket runtime exposed a network route")
            _docker("exec", core, "python", "-c", _BOOTSTRAP)
            for attempt in range(30):
                try:
                    _docker("exec", core, "python", "-c",
                            'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:18100/health", timeout=2).status==200')
                    break
                except RuntimeError:
                    if attempt == 29:
                        raise
                    time.sleep(1)
            result = json.loads(_docker("exec", core, "python", "-c", _API_CHECK))
            return {**result, "pgvector_image": image, "core_image": core_image,
                    "network_mode": "none", "database_transport": "unix-socket"}
    finally:
        for identifier in reversed(created):
            subprocess.run(["docker", "rm", "-f", identifier], capture_output=True,
                           text=True, timeout=30)
        if volume:
            subprocess.run(["docker", "volume", "rm", volume], capture_output=True,
                           text=True, timeout=30)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pgvector-image", required=True)
    parser.add_argument("--core-image", required=True)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.pgvector_image, args.core_image), sort_keys=True))


if __name__ == "__main__":
    main()
