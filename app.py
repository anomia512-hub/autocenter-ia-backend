import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("AUTOCHECK_DB", str(BASE_DIR / "autocheck.sqlite3")))
AUTH_SECRET = os.getenv("AUTOCHECK_AUTH_SECRET", "change-this-secret-before-production").encode()
DEV_AUTH = os.getenv("AUTOCHECK_DEV_AUTH", "false").lower() == "true"
PLAY_VALIDATION_MODE = os.getenv("AUTOCHECK_PLAY_VALIDATION", "disabled").lower()

app = FastAPI(title="AutoCenter IA License API", version="0.1.0")
_db_lock = threading.Lock()


def now() -> int:
    return int(time.time())


def iso(ts: Optional[int]) -> Optional[str]:
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def digest(value: str) -> str:
    return hmac.new(AUTH_SECRET, value.encode(), hashlib.sha256).hexdigest()


def normalize_email(value: str) -> str:
    return value.strip().lower()


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _db_lock, db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                verified INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                deleted_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS auth_challenges (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                code_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS licenses (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL UNIQUE REFERENCES accounts(id) ON DELETE CASCADE,
                product_id TEXT NOT NULL,
                installation_id TEXT NOT NULL,
                plate_fingerprint TEXT NOT NULL,
                state TEXT NOT NULL,
                purchase_token_hash TEXT NOT NULL,
                activated_at INTEGER NOT NULL,
                expires_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS vehicle_change_requests (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                new_plate_fingerprint TEXT NOT NULL,
                reason TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )


init_db()


class AccountCreate(BaseModel):
    email: EmailStr


class SessionCreate(BaseModel):
    email: EmailStr
    challenge_id: str = Field(min_length=10, max_length=100)
    code: str = Field(min_length=4, max_length=12)


class LicenseActivate(BaseModel):
    product_id: str = Field(min_length=1, max_length=100)
    purchase_token: str = Field(min_length=8, max_length=4096)
    installation_id: str = Field(min_length=8, max_length=200)
    plate_fingerprint: str = Field(min_length=16, max_length=200)


class VehicleChange(BaseModel):
    new_plate_fingerprint: str = Field(min_length=16, max_length=200)
    reason: str = Field(min_length=3, max_length=500)


def account_row(account_id: str) -> sqlite3.Row:
    with db() as connection:
        row = connection.execute(
            "SELECT * FROM accounts WHERE id = ? AND deleted_at IS NULL", (account_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Conta inválida")
    return row


def current_account(authorization: Optional[str] = Header(default=None)) -> sqlite3.Row:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Sessão necessária")
    token = authorization.split(" ", 1)[1].strip()
    if len(token) < 32:
        raise HTTPException(status_code=401, detail="Sessão inválida")
    with db() as connection:
        row = connection.execute(
            "SELECT account_id, expires_at, revoked_at FROM sessions WHERE token_hash = ?",
            (digest(token),),
        ).fetchone()
    if row is None or row["revoked_at"] is not None or row["expires_at"] <= now():
        raise HTTPException(status_code=401, detail="Sessão expirada")
    return account_row(row["account_id"])


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "autocenter-ia-license", "time": iso(now())}


@app.post("/v1/accounts", status_code=status.HTTP_201_CREATED)
def create_account(payload: AccountCreate) -> dict:
    email = normalize_email(str(payload.email))
    account_id = secrets.token_urlsafe(18)
    challenge_id = secrets.token_urlsafe(18)
    code = f"{secrets.randbelow(1_000_000):06d}"
    created = now()
    with _db_lock, db() as connection:
        existing = connection.execute(
            "SELECT id FROM accounts WHERE email = ? AND deleted_at IS NULL", (email,)
        ).fetchone()
        if existing:
            account_id = existing["id"]
        else:
            connection.execute(
                "INSERT INTO accounts(id, email, created_at) VALUES (?, ?, ?)",
                (account_id, email, created),
            )
        connection.execute(
            "INSERT INTO auth_challenges(id, account_id, code_hash, expires_at) VALUES (?, ?, ?, ?)",
            (challenge_id, account_id, digest(code), created + 600),
        )
    response = {
        "account_id": account_id,
        "challenge_id": challenge_id,
        "message": "Código de confirmação enviado pelo canal configurado.",
        "expires_at": iso(created + 600),
    }
    if DEV_AUTH:
        response["dev_code"] = code
    return response


@app.post("/v1/sessions")
def create_session(payload: SessionCreate) -> dict:
    email = normalize_email(str(payload.email))
    with _db_lock, db() as connection:
        row = connection.execute(
            """
            SELECT c.id, c.account_id, c.code_hash, c.expires_at, c.used_at
            FROM auth_challenges c JOIN accounts a ON a.id = c.account_id
            WHERE a.email = ? AND c.id = ? AND a.deleted_at IS NULL
            """,
            (email, payload.challenge_id),
        ).fetchone()
        if row is None or row["used_at"] is not None or row["expires_at"] <= now():
            raise HTTPException(status_code=401, detail="Código inválido ou expirado")
        if not hmac.compare_digest(row["code_hash"], digest(payload.code)):
            raise HTTPException(status_code=401, detail="Código inválido ou expirado")
        connection.execute("UPDATE auth_challenges SET used_at = ? WHERE id = ?", (now(), row["id"]))
        token = secrets.token_urlsafe(48)
        connection.execute(
            "INSERT INTO sessions(token_hash, account_id, expires_at) VALUES (?, ?, ?)",
            (digest(token), row["account_id"], now() + 900),
        )
        connection.execute("UPDATE accounts SET verified = 1 WHERE id = ?", (row["account_id"],))
    return {"access_token": token, "token_type": "bearer", "expires_in": 900}


@app.get("/v1/licenses/current")
def current_license(account: sqlite3.Row = Depends(current_account)) -> dict:
    with db() as connection:
        license_row = connection.execute(
            "SELECT product_id, state, activated_at, expires_at FROM licenses WHERE account_id = ?",
            (account["id"],),
        ).fetchone()
    if license_row is None:
        return {"state": "not_activated", "account_id": account["id"]}
    return {
        "state": license_row["state"],
        "account_id": account["id"],
        "product_id": license_row["product_id"],
        "activated_at": iso(license_row["activated_at"]),
        "expires_at": iso(license_row["expires_at"]),
    }


def validate_google_play_purchase(product_id: str, purchase_token: str) -> bool:
    # Segurança: nunca aceitar token inventado em produção. O modo stub só existe
    # para testes automatizados e exige o prefixo TEST_.
    return PLAY_VALIDATION_MODE == "stub" and purchase_token.startswith("TEST_") and bool(product_id)


@app.post("/v1/licenses/activate")
def activate_license(payload: LicenseActivate, account: sqlite3.Row = Depends(current_account)) -> dict:
    if not validate_google_play_purchase(payload.product_id, payload.purchase_token):
        raise HTTPException(
            status_code=503,
            detail="Validação da Google Play ainda não foi configurada neste servidor",
        )
    with _db_lock, db() as connection:
        existing = connection.execute(
            "SELECT * FROM licenses WHERE account_id = ?", (account["id"],)
        ).fetchone()
        if existing and (
            existing["installation_id"] != payload.installation_id
            or existing["plate_fingerprint"] != payload.plate_fingerprint
        ):
            raise HTTPException(status_code=409, detail="A licença já está vinculada a outro aparelho ou veículo")
        license_id = existing["id"] if existing else secrets.token_urlsafe(18)
        timestamp = now()
        if existing:
            connection.execute(
                "UPDATE licenses SET state = 'active', product_id = ?, activated_at = ?, purchase_token_hash = ? WHERE id = ?",
                (payload.product_id, timestamp, digest(payload.purchase_token), license_id),
            )
        else:
            connection.execute(
                """
                INSERT INTO licenses(id, account_id, product_id, installation_id,
                plate_fingerprint, state, purchase_token_hash, activated_at)
                VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
                """,
                (license_id, account["id"], payload.product_id, payload.installation_id,
                 payload.plate_fingerprint, digest(payload.purchase_token), timestamp),
            )
    return {"state": "active", "license_id": license_id, "message": "Licença ativada"}


@app.post("/v1/vehicles/change-request", status_code=status.HTTP_202_ACCEPTED)
def request_vehicle_change(payload: VehicleChange, account: sqlite3.Row = Depends(current_account)) -> dict:
    with db() as connection:
        license_row = connection.execute(
            "SELECT id FROM licenses WHERE account_id = ? AND state = 'active'", (account["id"],)
        ).fetchone()
    if license_row is None:
        raise HTTPException(status_code=409, detail="A conta não possui licença ativa")
    request_id = secrets.token_urlsafe(18)
    with _db_lock, db() as connection:
        connection.execute(
            """
            INSERT INTO vehicle_change_requests(id, account_id, new_plate_fingerprint, reason, state, created_at)
            VALUES (?, ?, ?, ?, 'pending_review', ?)
            """,
            (request_id, account["id"], payload.new_plate_fingerprint, payload.reason, now()),
        )
    return {"request_id": request_id, "state": "pending_review"}


@app.delete("/v1/accounts")
def delete_account(account: sqlite3.Row = Depends(current_account)) -> dict:
    timestamp = now()
    with _db_lock, db() as connection:
        connection.execute("UPDATE accounts SET deleted_at = ? WHERE id = ?", (timestamp, account["id"]))
        connection.execute("UPDATE sessions SET revoked_at = ? WHERE account_id = ?", (timestamp, account["id"]))
    return {"ok": True, "message": "Exclusão iniciada; dados da conta não serão mais usados para autenticação"}
