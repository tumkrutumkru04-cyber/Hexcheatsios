import base64
import hashlib
import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

app = Flask(__name__)
DB_PATH = os.getenv("DB_PATH", "licenses.db")
APP_SLUG = "cuban-proxy-vpn"
LICENSE_KEY = os.getenv("LICENSE_KEY", "CUBAN-PROXY")
DEX_HASH = os.getenv("DEX_HASH", "fa057a6017fe35683cfaef87d766e6eb7574a7851cb7485b9459d8e74d51e900")
LIB_HASH_ARM64 = os.getenv("LIB_HASH_ARM64", "80022ff5b350e8039eb509c04b06e381dfa1784d9729d27e45ea73b1b8c64c85")
LIB_HASH_V7A = os.getenv("LIB_HASH_V7A", "677c7b94c0f104e25634592950e6936369681569aca5d70a3296709a8606dd60")

# Must be the original private key corresponding to the public key embedded in the APK.
PRIVATE_KEY_PEM = os.getenv("LICENSE_PRIVATE_KEY_PEM", "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7Fp50S0XJjTbxyvk\npsTmcUUi0ZxGYTVio/Y73WDuH0KhRANCAAS2VcFYILAAf7IBWyrmWXG1GkrzsyTH\npQ2GUZKKd+wn+DwPni/JJEPjqBHwL1R2qsQmfWG2B34JpxBPcMJmhRZp\n-----END PRIVATE KEY-----")
EXPECTED_PUBLIC_KEY_B64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtlXBWCCwAH+yAVsq5llxtRpK87Mkx6UNhlGSinfsJ/g8D54vySRD46gR8C9UdqrEJn1htgd+CacQT3DCZoUWaQ=="


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            app TEXT NOT NULL,
            expires_at TEXT,
            revoked INTEGER NOT NULL DEFAULT 0,
            device_limit INTEGER NOT NULL DEFAULT 1,
            hwids TEXT NOT NULL DEFAULT '[]'
        )""")
        conn.execute("""INSERT OR IGNORE INTO licenses
            (license_key, app, expires_at, revoked, device_limit, hwids)
            VALUES (?, ?, NULL, 0, 1, '[]')""", (LICENSE_KEY, APP_SLUG))


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_private_key():
    if not PRIVATE_KEY_PEM:
        return None
    key = serialization.load_pem_private_key(PRIVATE_KEY_PEM.replace("\\n", "\n").encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("LICENSE_PRIVATE_KEY_PEM is not an EC private key")
    public_der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if base64.b64encode(public_der).decode() != EXPECTED_PUBLIC_KEY_B64:
        raise ValueError("Private key does not match the public key embedded in the old APK")
    return key


def sign_token(hwid: str, exp: str | None):
    key = load_private_key()
    if key is None:
        raise RuntimeError("Original signing private key is not configured")
    now = int(time.time())
    claims = {"v": 1, "app": APP_SLUG, "hwid": hwid, "iat": now}
    if exp:
        claims["exp"] = exp
    payload = b64u(json.dumps(claims, separators=(",", ":")).encode())
    signature = key.sign(payload.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    return "v1." + payload + "." + b64u(signature)


def authorized_build(data):
    if data.get("app") != APP_SLUG:
        return False
    if data.get("dex_hash") != DEX_HASH:
        return False
    # The supplied APK contains the arm64 library on normal modern devices.
    return data.get("lib_hash") in {LIB_HASH_ARM64, LIB_HASH_V7A}


def json_body():
    return request.get_json(silent=True) or {}


@app.get("/api/health")
def health():
    return jsonify(ok=True, service="cuban-proxy-license", time=datetime.now(timezone.utc).isoformat())


@app.post("/api/lic/activate")
def activate():
    data = json_body()
    required = ("app", "key", "hwid", "model", "version", "dex_hash", "lib_hash")
    if any(not data.get(k) for k in required):
        return jsonify(ok=False, error="missing_fields"), 400
    if not authorized_build(data):
        return jsonify(ok=False, error="build_not_authorized")

    with db() as conn:
        row = conn.execute("SELECT * FROM licenses WHERE license_key=? AND app=?", (data["key"], APP_SLUG)).fetchone()
        if not row:
            return jsonify(ok=False, error="invalid_key")
        if row["revoked"]:
            return jsonify(ok=False, error="revoked")
        if row["expires_at"] and row["expires_at"] <= datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"):
            return jsonify(ok=False, error="expired")
        hwids = json.loads(row["hwids"] or "[]")
        if data["hwid"] not in hwids and len(hwids) >= row["device_limit"]:
            return jsonify(ok=False, error="device_limit")
        if data["hwid"] not in hwids:
            hwids.append(data["hwid"])
            conn.execute("UPDATE licenses SET hwids=? WHERE license_key=?", (json.dumps(hwids), data["key"]))

        try:
            token = sign_token(data["hwid"], row["expires_at"])
        except RuntimeError:
            return jsonify(ok=False, error="server_not_configured"), 503
        except ValueError:
            return jsonify(ok=False, error="server_key_mismatch"), 500
        return jsonify(ok=True, token=token, exp=row["expires_at"] or "")


@app.post("/api/lic/heartbeat")
def heartbeat():
    data = json_body()
    token = data.get("token", "")
    hwid = data.get("hwid", "")
    if not token or not hwid or data.get("app") != APP_SLUG:
        return jsonify(ok=False, error="invalid_token")
    try:
        version, payload_b64, sig_b64 = token.split(".")
        if version != "v1":
            raise ValueError
        key = load_private_key()
        public_key = key.public_key()
        payload = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        signature = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        public_key.verify(signature, payload_b64.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        claims = json.loads(payload)
        if claims.get("v") != 1 or claims.get("app") != APP_SLUG or claims.get("hwid") != hwid:
            raise ValueError
        if claims.get("exp") and claims["exp"] <= datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"):
            raise ValueError
        return jsonify(ok=True)
    except Exception:
        return jsonify(ok=False, error="invalid_token")


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
