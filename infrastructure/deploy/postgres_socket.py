"""Protected local PostgreSQL socket setup for the synthetic vessel runtime."""

from __future__ import annotations

import re
import subprocess
import time


HBA = ("local all postgres peer\n"
       "local all all scram-sha-256\n"
       "host all all 0.0.0.0/0 reject\n"
       "host all all ::/0 reject\n")


class PostgresSocketError(ValueError):
    """The socket database could not be configured or verified safely."""


def docker(*args: str, timeout: int = 120) -> str:
    try:
        completed = subprocess.run(["docker", *args], capture_output=True,
                                   text=True, check=True, timeout=timeout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise PostgresSocketError(f"PostgreSQL Docker operation failed: {args[0]}") from exc
    return completed.stdout.strip()


def ready(identifier: str) -> None:
    for _ in range(40):
        try:
            process = subprocess.run(["docker", "exec", identifier, "cat",
                                      "/proc/1/comm"], capture_output=True,
                                     text=True, timeout=10)
            completed = subprocess.run(["docker", "exec", "-u", "postgres",
                                        identifier, "pg_isready", "-q", "-d", "postgres"],
                                       capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PostgresSocketError("PostgreSQL readiness check failed") from exc
        # The official entrypoint starts a temporary local server during init.
        # Only PID 1's final postgres process is safe for persistent setup.
        if (process.returncode == 0 and process.stdout.strip() == "postgres"
                and completed.returncode == 0):
            return
        time.sleep(1)
    raise PostgresSocketError("PostgreSQL server did not become ready")


def sql(identifier: str, statement: str) -> str:
    return docker("exec", "-u", "postgres", identifier, "psql", "-X",
                  "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-Atqc", statement)


def pg_input(identifier: str, program: str, payload: str) -> str:
    """Send generated secrets through stdin, never Docker arguments."""
    try:
        completed = subprocess.run(["docker", "exec", "-i", "-u", "postgres",
                                    identifier, "sh", "-c", program], input=payload,
                                   capture_output=True, text=True, check=True, timeout=30)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise PostgresSocketError("PostgreSQL configuration failed") from exc
    return completed.stdout.strip()


def secure_database(identifier: str, writer_secret: str, reader_secret: str) -> None:
    """Create separate roles and replace bootstrap trust with local SCRAM."""
    if not all(re.fullmatch(r"[0-9a-f]{64}", value)
               for value in (writer_secret, reader_secret)):
        raise PostgresSocketError("invalid PostgreSQL role secret")
    sql(identifier, "CREATE EXTENSION vector")
    pg_input(identifier, "psql -X -v ON_ERROR_STOP=1 -d postgres",
             "SET password_encryption='scram-sha-256';\n"
             f"CREATE ROLE sovereign_ingest LOGIN PASSWORD '{writer_secret}';\n"
             f"CREATE ROLE sovereign_read LOGIN PASSWORD '{reader_secret}';\n"
             "REVOKE ALL ON SCHEMA public FROM PUBLIC;\n"
             "GRANT USAGE, CREATE ON SCHEMA public TO sovereign_ingest;\n"
             "GRANT USAGE ON SCHEMA public TO sovereign_read;\n")
    pg_input(identifier, "cat > /var/lib/postgresql/data/pg_hba.conf", HBA)
    verify_security(identifier, reload=True)


def verify_security(identifier: str, *, reload: bool = False) -> None:
    """Fail if the persisted database admits unauthorised local or TCP access."""
    if reload and sql(identifier, "SELECT pg_reload_conf()") != "t":
        raise PostgresSocketError("PostgreSQL authentication reload failed")
    if sql(identifier, "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL") != "0":
        raise PostgresSocketError("PostgreSQL authentication rules are invalid")
    if docker("exec", "-u", "postgres", identifier, "cat",
              "/var/lib/postgresql/data/pg_hba.conf") + "\n" != HBA:
        raise PostgresSocketError("PostgreSQL authentication rules changed")
    roles = sql(identifier,
                "SELECT rolname || ':' || rolsuper::int || ':' || rolcreatedb::int || ':' || "
                "rolcreaterole::int || ':' || rolreplication::int || ':' || rolbypassrls::int "
                "FROM pg_roles WHERE rolname IN "
                "('sovereign_ingest','sovereign_read') ORDER BY rolname")
    if roles.splitlines() != ["sovereign_ingest:0:0:0:0:0",
                              "sovereign_read:0:0:0:0:0"]:
        raise PostgresSocketError("PostgreSQL application role privileges changed")
    if sql(identifier,
           "SELECT has_schema_privilege('sovereign_read','public','CREATE')") != "f":
        raise PostgresSocketError("Core database role can create schema objects")


def verify_login(identifier: str, role: str, secret: str) -> None:
    """Check a role password via stdin without putting it in Docker arguments."""
    if (role not in {"sovereign_ingest", "sovereign_read"}
            or not re.fullmatch(r"[0-9a-f]{64}", secret)):
        raise PostgresSocketError("invalid PostgreSQL login probe")
    program = ("IFS= read -r password; export PGPASSWORD=\"$password\"; "
               "psql -X -v ON_ERROR_STOP=1 -h /run/postgresql -U " + role +
               " -d postgres -Atqc 'SELECT current_user'")
    if pg_input(identifier, program, secret + "\n") != role:
        raise PostgresSocketError("PostgreSQL role credential mismatch")
