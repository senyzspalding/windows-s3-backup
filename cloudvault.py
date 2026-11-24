"""
CloudVault Backup — Windows Desktop Application
=================================================
A native Windows GUI for backing up your home folder to AWS S3.

Features:
  - AES-256-GCM client-side encryption (files encrypted BEFORE upload)
  - Full & incremental backups (SHA-256 deduplication)
  - Browse & restore backed-up files with version history
  - 90-day retention for deleted files before permanent S3 removal
  - AWS credentials via profile / AWS credential chain, or Windows Credential Manager
    (keys are never written to disk in plaintext)
  - Real-time progress tracking
  - Activity log viewer

Requirements:
  pip install boto3 cryptography keyring

Run:
  python cloudvault.py
"""

import os
import sys
import json
import hashlib
import sqlite3
import logging
import threading
import tempfile
import base64
import secrets
import struct
import io
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fnmatch import fnmatch
from typing import Optional

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("boto3 is required. Install with: pip install boto3")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import keyring  # Windows Credential Manager on Windows
    HAS_KEYRING = True
except ImportError:
    HAS_KEYRING = False


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "bucket_name": "",
    "aws_region": "us-east-1",
    "aws_profile": "",           # optional named profile from ~/.aws/config
    "home_folder": str(Path.home()),
    "backup_prefix": "cloudvault-backup",
    "exclude_patterns": [
        "*.tmp", "*.log", "~$*", "Thumbs.db", "desktop.ini",
        ".git", "__pycache__", "node_modules", ".venv",
        "AppData/Local/Temp", "AppData/Local/Microsoft/Windows/INetCache",
        "NTUSER.DAT*", "ntuser.dat*",
    ],
    "retention_days": 90,
    "encryption_enabled": True,    # mandatory: backups are refused without it
    "encryption_salt": "",       # base64-encoded salt for PBKDF2
    "encryption_verify": "",     # encrypted marker to verify passphrase
}

APP_DIR = Path.home() / ".cloudvault"
APP_DIR.mkdir(exist_ok=True)
CONFIG_PATH = APP_DIR / "config.json"
DB_PATH = APP_DIR / "catalog.db"
LOG_PATH = APP_DIR / "cloudvault.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("cloudvault")

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

# AWS keys must never be written to config.json. They live in the OS credential
# store (Windows Credential Manager) or come from the standard AWS credential
# chain (environment variables, ~/.aws/credentials, SSO, instance role, ...).
_SECRET_CONFIG_KEYS = ("aws_access_key", "aws_secret_key")

def load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            stored = json.load(f)
        # Legacy plaintext keys are never used from here; migrate_legacy_credentials()
        # moves them to the credential store and scrubs the file.
        for k in _SECRET_CONFIG_KEYS:
            stored.pop(k, None)
        return {**DEFAULT_CONFIG, **stored}
    return dict(DEFAULT_CONFIG)

def save_config(cfg: dict):
    clean = {k: v for k, v in cfg.items() if k not in _SECRET_CONFIG_KEYS}
    tmp = CONFIG_PATH.with_suffix(".json.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=2)
    os.replace(tmp, CONFIG_PATH)

# ═══════════════════════════════════════════════════════════════════════════════
# AWS CREDENTIAL STORAGE
# ═══════════════════════════════════════════════════════════════════════════════

KEYRING_SERVICE = "CloudVault"
_KR_ACCESS = "aws_access_key_id"
_KR_SECRET = "aws_secret_access_key"

def keyring_available() -> bool:
    """True if a real (non-null/fail) keyring backend is usable."""
    if not HAS_KEYRING:
        return False
    try:
        backend = keyring.get_keyring()
        return getattr(backend, "priority", 0) > 0
    except Exception:
        return False

def store_aws_credentials(access_key: str, secret_key: str):
    """Save AWS keys to the OS credential store. Raises if none is available."""
    if not keyring_available():
        raise RuntimeError(
            "No secure credential store available. Install it with "
            "'pip install keyring', or use the AWS credential chain instead "
            "(aws configure / environment variables / AWS profile).")
    keyring.set_password(KEYRING_SERVICE, _KR_ACCESS, access_key)
    keyring.set_password(KEYRING_SERVICE, _KR_SECRET, secret_key)

def load_stored_aws_credentials() -> Optional[tuple]:
    """Return (access_key, secret_key) from the credential store, or None."""
    if not keyring_available():
        return None
    try:
        ak = keyring.get_password(KEYRING_SERVICE, _KR_ACCESS)
        sk = keyring.get_password(KEYRING_SERVICE, _KR_SECRET)
    except Exception as e:
        log.warning(f"Could not read credential store: {type(e).__name__}")
        return None
    return (ak, sk) if ak and sk else None

def get_stored_access_key_id() -> str:
    creds = load_stored_aws_credentials()
    return creds[0] if creds else ""

def delete_stored_aws_credentials():
    if not keyring_available():
        return
    for name in (_KR_ACCESS, _KR_SECRET):
        try:
            keyring.delete_password(KEYRING_SERVICE, name)
        except Exception:
            pass

def migrate_legacy_credentials() -> str:
    """
    Older versions kept AWS keys in plaintext in config.json. Move them into the
    credential store and scrub the file. Returns "", "migrated" or "unmigrated"
    (plaintext keys remain on disk because no secure store is available).
    """
    if not CONFIG_PATH.exists():
        return ""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return ""
    ak, sk = raw.get("aws_access_key", ""), raw.get("aws_secret_key", "")
    if not any(k in raw for k in _SECRET_CONFIG_KEYS):
        return ""
    if ak and sk:
        if not keyring_available():
            log.warning("Plaintext AWS keys found in config.json but no secure "
                        "credential store is available; they are being ignored. "
                        "Install 'keyring' or use the AWS credential chain, "
                        "then delete the keys from config.json.")
            return "unmigrated"
        try:
            store_aws_credentials(ak, sk)
            if load_stored_aws_credentials() != (ak, sk):
                raise RuntimeError("credential store read-back mismatch")
        except Exception as e:
            log.warning(f"Could not migrate AWS keys to credential store: {type(e).__name__}")
            return "unmigrated"
    for k in _SECRET_CONFIG_KEYS:
        raw.pop(k, None)
    save_config(raw)
    log.info("Moved AWS keys from config.json to the secure credential store")
    return "migrated"

# ═══════════════════════════════════════════════════════════════════════════════
# ENCRYPTION MODULE
# ═══════════════════════════════════════════════════════════════════════════════

ENCRYPTION_MARKER = b"CLOUDVAULT_ENCRYPTED_OK"
PBKDF2_ITERATIONS = 600_000  # OWASP recommended minimum for SHA-256

class EncryptionManager:
    """
    AES-256-GCM encryption with PBKDF2 key derivation from a passphrase.

    File format on S3:
      [12 bytes nonce][ciphertext + 16 byte GCM tag]

    The encryption key is derived from (passphrase + salt) via PBKDF2-SHA256.
    The salt is stored in config.json (it's not secret, just unique).
    A verification token is stored to validate the passphrase without
    needing to download a file.
    """

    def __init__(self):
        self._key: Optional[bytes] = None
        self._enabled = False

    @property
    def is_ready(self) -> bool:
        return self._enabled and self._key is not None

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def configure(self, enabled: bool):
        self._enabled = enabled
        if not enabled:
            self._key = None

    def derive_key(self, passphrase: str, salt: bytes) -> bytes:
        """Derive a 256-bit key from passphrase using PBKDF2-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(passphrase.encode("utf-8"))

    def setup_new(self, passphrase: str) -> tuple[str, str]:
        """
        Initialize encryption with a new passphrase.
        Returns (salt_b64, verify_b64) to store in config.
        """
        salt = secrets.token_bytes(32)
        self._key = self.derive_key(passphrase, salt)
        self._enabled = True
        # Create verification token
        verify_enc = self.encrypt_bytes(ENCRYPTION_MARKER)
        return base64.b64encode(salt).decode(), base64.b64encode(verify_enc).decode()

    def unlock(self, passphrase: str, salt_b64: str, verify_b64: str) -> bool:
        """
        Unlock encryption with an existing passphrase.
        Returns True if the passphrase is correct.
        """
        salt = base64.b64decode(salt_b64)
        self._key = self.derive_key(passphrase, salt)
        # Verify
        try:
            verify_enc = base64.b64decode(verify_b64)
            plaintext = self.decrypt_bytes(verify_enc)
            if plaintext == ENCRYPTION_MARKER:
                self._enabled = True
                return True
        except Exception:
            pass
        self._key = None
        return False

    def encrypt_bytes(self, data: bytes) -> bytes:
        """Encrypt data with AES-256-GCM. Returns nonce + ciphertext."""
        aesgcm = AESGCM(self._key)
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct

    def decrypt_bytes(self, data: bytes) -> bytes:
        """Decrypt nonce + ciphertext from AES-256-GCM."""
        aesgcm = AESGCM(self._key)
        nonce = data[:12]
        ct = data[12:]
        return aesgcm.decrypt(nonce, ct, None)

    def encrypt_file(self, src_path: str, dest_path: str):
        """Encrypt a file from disk to a temp file."""
        with open(src_path, "rb") as f:
            plaintext = f.read()
        ciphertext = self.encrypt_bytes(plaintext)
        with open(dest_path, "wb") as f:
            f.write(ciphertext)

    def decrypt_file(self, src_path: str, dest_path: str):
        """Decrypt a file from disk to destination."""
        with open(src_path, "rb") as f:
            ciphertext = f.read()
        plaintext = self.decrypt_bytes(ciphertext)
        with open(dest_path, "wb") as f:
            f.write(plaintext)


class EncryptionUnavailable(Exception):
    """Raised when a backup needs the encryption key but it is not available."""


# Global encryption manager
encryptor = EncryptionManager()


def encryption_block_reason(cfg: dict) -> Optional[str]:
    """
    Encryption is mandatory for every backup. Returns None if a backup may
    proceed, otherwise a human-readable reason it must be refused.
    """
    if not HAS_CRYPTO:
        return "the 'cryptography' package is not installed (pip install cryptography)"
    if not (cfg.get("encryption_salt") and cfg.get("encryption_verify")):
        return "encryption is not set up yet - create a passphrase in Settings"
    if not encryptor.is_ready:
        return "encryption is locked - unlock it with your passphrase in Settings"
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_id TEXT UNIQUE NOT NULL,
            backup_type TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT DEFAULT 'running',
            files_count INTEGER DEFAULT 0,
            bytes_total INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_id TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            s3_key TEXT NOT NULL,
            file_hash TEXT,
            file_size INTEGER,
            modified_at TEXT,
            backed_up_at TEXT NOT NULL,
            is_deleted INTEGER DEFAULT 0,
            deleted_at TEXT,
            is_encrypted INTEGER DEFAULT 0,
            FOREIGN KEY (backup_id) REFERENCES backups(backup_id)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_files_path ON files(relative_path)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_files_deleted ON files(is_deleted, deleted_at)")
    # Migration: add is_encrypted column if missing
    try:
        c.execute("ALTER TABLE files ADD COLUMN is_encrypted INTEGER DEFAULT 0")
    except Exception:
        pass
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

# ═══════════════════════════════════════════════════════════════════════════════
# S3 HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _aws_session(cfg: dict):
    """
    Credential precedence:
      1. Named AWS profile (cfg["aws_profile"])
      2. Keys saved in the OS credential store (Windows Credential Manager)
      3. The default boto3 chain (env vars, ~/.aws, SSO, instance role, ...)
    """
    region = cfg.get("aws_region") or None
    profile = (cfg.get("aws_profile") or "").strip()
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    stored = load_stored_aws_credentials()
    if stored:
        return boto3.Session(aws_access_key_id=stored[0],
                             aws_secret_access_key=stored[1],
                             region_name=region)
    return boto3.Session(region_name=region)

def has_aws_credentials(cfg: dict) -> bool:
    try:
        return _aws_session(cfg).get_credentials() is not None
    except Exception:
        return False

def get_s3_client(cfg: dict):
    return _aws_session(cfg).client("s3")

def ensure_bucket(s3, bucket_name: str, region: str):
    try:
        s3.head_bucket(Bucket=bucket_name)
    except ClientError as e:
        code = int(e.response["Error"]["Code"])
        if code == 404:
            if region == "us-east-1":
                s3.create_bucket(Bucket=bucket_name)
            else:
                s3.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": region},
                )
            log.info(f"Created bucket: {bucket_name}")
        else:
            raise

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def file_hash(filepath: str, block_size: int = 65536) -> str:
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                buf = f.read(block_size)
                if not buf:
                    break
                h.update(buf)
    except (PermissionError, OSError):
        return ""
    return h.hexdigest()

def should_exclude(rel_path: str, patterns: list) -> bool:
    parts = Path(rel_path).parts
    for pattern in patterns:
        if fnmatch(rel_path, pattern):
            return True
        for part in parts:
            if fnmatch(part, pattern):
                return True
    return False

def format_bytes(b: int) -> str:
    if not b or b == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    val = float(b)
    while val >= 1024 and i < len(units) - 1:
        val /= 1024
        i += 1
    return f"{val:.1f} {units[i]}"

def format_dt(iso_str: str) -> str:
    if not iso_str:
        return "—"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return iso_str[:16]

# ═══════════════════════════════════════════════════════════════════════════════
# BACKUP ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class BackupEngine:
    def __init__(self):
        self.cfg = load_config()
        init_db()
        self._running = False
        self._cancel = False
        self.progress = {
            "status": "idle", "current_file": "",
            "processed": 0, "total": 0, "bytes_done": 0,
            "uploaded": 0,
        }

    def reload_config(self):
        self.cfg = load_config()

    def _get_last_hashes(self) -> dict:
        db = get_db()
        rows = db.execute(
            "SELECT relative_path, file_hash, is_encrypted FROM files "
            "WHERE is_deleted = 0 ORDER BY backed_up_at DESC"
        ).fetchall()
        db.close()
        # Only an ENCRYPTED latest copy lets an incremental run skip a file.
        # If the newest stored copy is plaintext (made before encryption was
        # mandatory), record None so the unchanged file is re-uploaded encrypted.
        seen = {}
        for r in rows:
            if r["relative_path"] not in seen:
                seen[r["relative_path"]] = r["file_hash"] if r["is_encrypted"] else None
        return seen

    def cancel_backup(self):
        self._cancel = True

    def run_backup(self, backup_type: str = "incremental"):
        if self._running:
            return
        self._running = True
        self._cancel = False
        self.progress = {
            "status": "scanning", "current_file": "",
            "processed": 0, "total": 0, "bytes_done": 0,
            "uploaded": 0,
        }

        cfg = self.cfg
        # Encryption is mandatory and fails closed: if the key is unavailable
        # (not set up, locked, cryptography missing), abort BEFORE touching AWS.
        # Plaintext is never uploaded.
        use_encryption = True
        reason = encryption_block_reason(cfg)
        if reason:
            self.progress["status"] = f"error: backup refused - {reason}"
            self._running = False
            log.error(f"Backup aborted, nothing uploaded: {reason}")
            return
        backup_id = f"{backup_type}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        home = cfg["home_folder"]
        prefix = cfg["backup_prefix"]
        exclude = cfg["exclude_patterns"]

        try:
            s3 = get_s3_client(cfg)
            ensure_bucket(s3, cfg["bucket_name"], cfg["aws_region"])
        except Exception as e:
            self.progress["status"] = f"error: {e}"
            self._running = False
            log.error(f"AWS connection failed: {e}")
            return

        db = get_db()
        db.execute(
            "INSERT INTO backups (backup_id, backup_type, started_at) VALUES (?, ?, ?)",
            (backup_id, backup_type, datetime.now(timezone.utc).isoformat()),
        )
        db.commit()

        # Scan files
        all_files = []
        for root_dir, dirs, files_list in os.walk(home):
            dirs[:] = [d for d in dirs if not d.startswith(".") or d == ".ssh"]
            for fname in files_list:
                full = os.path.join(root_dir, fname)
                rel = os.path.relpath(full, home)
                if not should_exclude(rel, exclude):
                    all_files.append((full, rel))

        self.progress["total"] = len(all_files)
        self.progress["status"] = "uploading"

        existing_hashes = {} if backup_type == "full" else self._get_last_hashes()
        uploaded = 0
        total_bytes = 0
        aborted = False

        # Temp dir for encrypted files
        tmp_dir = tempfile.mkdtemp(prefix="cloudvault_")

        try:
            for full_path, rel_path in all_files:
                if self._cancel:
                    self.progress["status"] = "cancelled"
                    break

                self.progress["current_file"] = rel_path
                try:
                    fhash = file_hash(full_path)
                    if not fhash:
                        self.progress["processed"] += 1
                        continue

                    if backup_type == "incremental" and existing_hashes.get(rel_path) == fhash:
                        self.progress["processed"] += 1
                        continue

                    fsize = os.path.getsize(full_path)
                    mtime = datetime.fromtimestamp(
                        os.path.getmtime(full_path), tz=timezone.utc
                    ).isoformat()
                    s3_key = f"{prefix}/{backup_id}/{rel_path.replace(os.sep, '/')}"

                    # Encrypt if enabled
                    if use_encryption:
                        if not encryptor.is_ready:
                            # Key vanished mid-run (e.g. encryption disabled/locked
                            # in the GUI): stop rather than upload plaintext.
                            raise EncryptionUnavailable("encryption key no longer available")
                        enc_tmp = os.path.join(tmp_dir, f"enc_{uploaded}")
                        encryptor.encrypt_file(full_path, enc_tmp)
                        s3.upload_file(enc_tmp, cfg["bucket_name"], s3_key)
                        try:
                            os.remove(enc_tmp)
                        except OSError:
                            pass
                    else:
                        s3.upload_file(full_path, cfg["bucket_name"], s3_key)

                    db.execute(
                        """INSERT INTO files
                           (backup_id, relative_path, s3_key, file_hash, file_size,
                            modified_at, backed_up_at, is_encrypted)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (backup_id, rel_path, s3_key, fhash, fsize, mtime,
                         datetime.now(timezone.utc).isoformat(),
                         1 if use_encryption else 0),
                    )
                    uploaded += 1
                    total_bytes += fsize

                except EncryptionUnavailable as e:
                    aborted = True
                    log.error(f"Backup aborted at {rel_path}: {e}")
                    break
                except (PermissionError, OSError) as e:
                    log.warning(f"Skipped {rel_path}: {e}")
                except Exception as e:
                    log.error(f"Error uploading {rel_path}: {e}")

                self.progress["processed"] += 1
                self.progress["bytes_done"] = total_bytes
                self.progress["uploaded"] = uploaded
        finally:
            # Clean up temp dir
            try:
                import shutil
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass

        # Mark deletions
        self._mark_deletions(db, home)

        final_status = ("aborted" if aborted
                        else "cancelled" if self._cancel else "completed")
        db.execute(
            """UPDATE backups SET finished_at=?, status=?, files_count=?, bytes_total=?
               WHERE backup_id=?""",
            (datetime.now(timezone.utc).isoformat(), final_status, uploaded,
             total_bytes, backup_id),
        )
        db.commit()
        db.close()

        self.progress["status"] = (
            "error: encryption key became unavailable; backup aborted"
            if aborted else final_status)
        self._running = False
        enc_label = " (encrypted)" if use_encryption else ""
        log.info(f"Backup {backup_id} {final_status}: {uploaded} files, "
                 f"{format_bytes(total_bytes)}{enc_label}")

    def _mark_deletions(self, db, home: str):
        rows = db.execute(
            "SELECT DISTINCT relative_path FROM files WHERE is_deleted = 0"
        ).fetchall()
        now = datetime.now(timezone.utc).isoformat()
        for row in rows:
            rp = row["relative_path"]
            if not os.path.exists(os.path.join(home, rp)):
                db.execute(
                    "UPDATE files SET is_deleted=1, deleted_at=? WHERE relative_path=? AND is_deleted=0",
                    (now, rp),
                )

    def cleanup_expired(self):
        cfg = self.cfg
        cutoff = (datetime.now(timezone.utc) - timedelta(days=cfg["retention_days"])).isoformat()
        db = get_db()
        rows = db.execute(
            "SELECT id, s3_key FROM files WHERE is_deleted=1 AND deleted_at < ?", (cutoff,)
        ).fetchall()
        if not rows:
            db.close()
            return 0
        s3 = get_s3_client(cfg)
        removed = 0
        for row in rows:
            try:
                s3.delete_object(Bucket=cfg["bucket_name"], Key=row["s3_key"])
                db.execute("DELETE FROM files WHERE id=?", (row["id"],))
                removed += 1
            except Exception as e:
                log.error(f"Cleanup error {row['s3_key']}: {e}")
        db.commit()
        db.close()
        log.info(f"Cleaned up {removed} expired files")
        return removed

    def browse(self, path_prefix: str = "", include_deleted: bool = False):
        db = get_db()
        if include_deleted:
            rows = db.execute(
                "SELECT relative_path, file_size, modified_at, backed_up_at, "
                "is_deleted, deleted_at, is_encrypted FROM files ORDER BY backed_up_at DESC"
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT relative_path, file_size, modified_at, backed_up_at, "
                "is_deleted, deleted_at, is_encrypted FROM files "
                "WHERE is_deleted=0 ORDER BY backed_up_at DESC"
            ).fetchall()
        db.close()

        entries = {}
        prefix_parts = [p for p in path_prefix.replace("\\", "/").split("/") if p]
        prefix_depth = len(prefix_parts)

        for row in rows:
            rp = row["relative_path"].replace("\\", "/")
            parts = rp.split("/")
            if prefix_parts and parts[:prefix_depth] != prefix_parts:
                continue
            remaining = parts[prefix_depth:]
            if not remaining:
                continue
            name = remaining[0]
            if len(remaining) == 1:
                if name not in entries or entries[name]["type"] == "folder":
                    entries[name] = {
                        "type": "file", "name": name, "size": row["file_size"],
                        "modified": row["modified_at"], "backed_up": row["backed_up_at"],
                        "is_deleted": bool(row["is_deleted"]),
                        "deleted_at": row["deleted_at"], "path": rp,
                        "is_encrypted": bool(row["is_encrypted"]),
                    }
            else:
                if name not in entries:
                    entries[name] = {
                        "type": "folder", "name": name,
                        "path": "/".join(prefix_parts + [name]),
                        "is_deleted": False, "is_encrypted": False,
                    }

        return sorted(entries.values(), key=lambda x: (x["type"] == "file", x["name"].lower()))

    def get_versions(self, relative_path: str):
        db = get_db()
        rows = db.execute(
            """SELECT backup_id, s3_key, file_hash, file_size, modified_at,
                      backed_up_at, is_deleted, is_encrypted
               FROM files WHERE relative_path=? ORDER BY backed_up_at DESC""",
            (relative_path,),
        ).fetchall()
        db.close()
        return [dict(r) for r in rows]

    def restore_file(self, s3_key: str, is_encrypted: int = 0,
                     dest_path: Optional[str] = None):
        """Download a file from S3, decrypt if needed, write to disk."""
        cfg = self.cfg
        if dest_path is None:
            parts = s3_key.split("/")
            rel = "/".join(parts[2:])
            dest_path = os.path.join(cfg["home_folder"], rel)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        s3 = get_s3_client(cfg)

        if is_encrypted and encryptor.is_ready:
            # Download to temp, decrypt to destination
            tmp_fd, tmp_path = tempfile.mkstemp(prefix="cvrestore_")
            os.close(tmp_fd)
            try:
                s3.download_file(cfg["bucket_name"], s3_key, tmp_path)
                encryptor.decrypt_file(tmp_path, dest_path)
            finally:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
        elif is_encrypted and not encryptor.is_ready:
            raise RuntimeError(
                "This file is encrypted. Please unlock encryption in Settings first."
            )
        else:
            s3.download_file(cfg["bucket_name"], s3_key, dest_path)

        log.info(f"Restored {s3_key} -> {dest_path}"
                 f"{' (decrypted)' if is_encrypted else ''}")
        return dest_path

    def restore_folder(self, path_prefix: str, dest_folder: Optional[str] = None):
        cfg = self.cfg
        db = get_db()
        rows = db.execute(
            "SELECT relative_path, s3_key, backed_up_at, is_encrypted "
            "FROM files WHERE is_deleted = 0 ORDER BY backed_up_at DESC"
        ).fetchall()
        db.close()

        seen = set()
        restored = 0
        for row in rows:
            rp = row["relative_path"].replace("\\", "/")
            if not rp.startswith(path_prefix):
                continue
            if rp in seen:
                continue
            seen.add(rp)
            if dest_folder:
                dest = os.path.join(dest_folder, rp)
            else:
                dest = os.path.join(cfg["home_folder"], rp)
            try:
                self.restore_file(row["s3_key"], row["is_encrypted"], dest)
                restored += 1
            except Exception as e:
                log.error(f"Failed restoring {rp}: {e}")
        return {"restored_count": restored}

    def get_backup_history(self):
        db = get_db()
        rows = db.execute("SELECT * FROM backups ORDER BY started_at DESC LIMIT 50").fetchall()
        db.close()
        return [dict(r) for r in rows]

    def get_stats(self):
        db = get_db()
        total_files = db.execute(
            "SELECT COUNT(DISTINCT relative_path) FROM files WHERE is_deleted=0"
        ).fetchone()[0]
        total_bytes = db.execute(
            "SELECT COALESCE(SUM(file_size),0) FROM files WHERE is_deleted=0"
        ).fetchone()[0]
        deleted_files = db.execute(
            "SELECT COUNT(DISTINCT relative_path) FROM files WHERE is_deleted=1"
        ).fetchone()[0]
        backup_count = db.execute("SELECT COUNT(*) FROM backups").fetchone()[0]
        encrypted_count = db.execute(
            "SELECT COUNT(DISTINCT relative_path) FROM files WHERE is_encrypted=1 AND is_deleted=0"
        ).fetchone()[0]
        last = db.execute(
            "SELECT finished_at FROM backups WHERE status='completed' ORDER BY finished_at DESC LIMIT 1"
        ).fetchone()
        db.close()
        return {
            "total_files": total_files, "total_bytes": total_bytes,
            "deleted_pending": deleted_files, "backup_count": backup_count,
            "last_backup": last[0] if last else None,
            "encrypted_files": encrypted_count,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# THEME COLORS
# ═══════════════════════════════════════════════════════════════════════════════

C = {
    "bg":         "#0f1419",
    "bg_panel":   "#151c25",
    "bg_card":    "#1b2432",
    "bg_input":   "#111820",
    "bg_hover":   "#222e3e",
    "border":     "#2a3a50",
    "fg":         "#dce4ee",
    "fg2":        "#8899af",
    "fg3":        "#556678",
    "accent":     "#3b82f6",
    "accent_dim": "#1e3a5f",
    "green":      "#22c55e",
    "green_dim":  "#0f3d22",
    "amber":      "#f59e0b",
    "amber_dim":  "#3d2e08",
    "red":        "#ef4444",
    "red_dim":    "#3d1111",
    "purple":     "#a78bfa",
    "purple_dim": "#2d1f5e",
}

# ═══════════════════════════════════════════════════════════════════════════════
# GUI APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

class CloudVaultApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.engine = BackupEngine()
        self.browse_path = ""
        self.show_deleted = tk.BooleanVar(value=False)

        self._setup_window()
        self._setup_styles()
        self._build_ui()
        self._show_page("dashboard")
        self._refresh_dashboard()

        # Auto-configure encryption state from config
        cfg = self.engine.cfg
        if HAS_CRYPTO:
            encryptor.configure(True)

    # ── Window setup ──────────────────────────────────────────────────────────

    def _setup_window(self):
        self.root.title("CloudVault — Home Backup to AWS S3")
        self.root.configure(bg=C["bg"])
        self.root.minsize(1050, 700)
        w, h = 1200, 780
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=C["bg"], foreground=C["fg"],
                         fieldbackground=C["bg_input"], borderwidth=0,
                         font=("Segoe UI", 10))
        style.configure("Treeview",
                         background=C["bg_card"], foreground=C["fg"],
                         fieldbackground=C["bg_card"], rowheight=30,
                         borderwidth=0, font=("Segoe UI", 9))
        style.configure("Treeview.Heading",
                         background=C["bg_panel"], foreground=C["fg3"],
                         font=("Segoe UI", 8, "bold"), borderwidth=0, relief="flat")
        style.map("Treeview",
                   background=[("selected", C["accent_dim"])],
                   foreground=[("selected", C["accent"])])
        style.map("Treeview.Heading", background=[("active", C["bg_hover"])])
        style.configure("blue.Horizontal.TProgressbar",
                         troughcolor=C["bg_input"], background=C["accent"],
                         borderwidth=0, thickness=10)
        style.configure("Vertical.TScrollbar",
                         background=C["bg_panel"], troughcolor=C["bg"],
                         borderwidth=0, arrowsize=0)

    # ── Build UI ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Sidebar
        sidebar = tk.Frame(self.root, bg=C["bg_panel"], width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        brand_frame = tk.Frame(sidebar, bg=C["bg_panel"])
        brand_frame.pack(fill="x", padx=16, pady=(20, 12))
        tk.Label(brand_frame, text=" ☁ ", bg=C["accent"], fg="white",
                 font=("Segoe UI", 13, "bold"), width=3, relief="flat",
                 padx=2, pady=2).pack(side="left")
        brand_text = tk.Frame(brand_frame, bg=C["bg_panel"])
        brand_text.pack(side="left", padx=(10, 0))
        tk.Label(brand_text, text="CloudVault", bg=C["bg_panel"], fg=C["fg"],
                 font=("Consolas", 13, "bold")).pack(anchor="w")
        tk.Label(brand_text, text="Encrypted Backup", bg=C["bg_panel"], fg=C["fg3"],
                 font=("Segoe UI", 8)).pack(anchor="w")

        tk.Frame(sidebar, bg=C["border"], height=1).pack(fill="x", padx=16, pady=(8, 12))

        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "▣  Dashboard"),
            ("browse",    "📁  Browse & Restore"),
            ("history",   "⏱  Backup History"),
            ("settings",  "⚙  Settings"),
            ("logs",      "📋  Logs"),
        ]
        for key, label in nav_items:
            btn = tk.Label(sidebar, text=label, bg=C["bg_panel"], fg=C["fg2"],
                           font=("Segoe UI", 10), anchor="w", padx=18, pady=8,
                           cursor="hand2")
            btn.pack(fill="x", padx=8, pady=1)
            btn.bind("<Enter>", lambda e, b=btn: b.configure(bg=C["bg_hover"]))
            btn.bind("<Leave>", lambda e, b=btn, k=key:
                     b.configure(bg=C["accent_dim"] if self._current_page == k else C["bg_panel"]))
            btn.bind("<Button-1>", lambda e, k=key: self._show_page(k))
            self.nav_buttons[key] = btn

        tk.Frame(sidebar, bg=C["bg_panel"]).pack(fill="both", expand=True)

        # Encryption status indicator in sidebar footer
        self.sidebar_enc_label = tk.Label(sidebar, text="🔓 Not Encrypted",
                                           bg=C["bg_panel"], fg=C["fg3"],
                                           font=("Segoe UI", 8))
        self.sidebar_enc_label.pack(pady=(0, 6))
        tk.Label(sidebar, text="v1.1 — AES-256 Encrypted Backups",
                 bg=C["bg_panel"], fg=C["fg3"], font=("Segoe UI", 7)).pack(pady=(0, 14))

        # Main content
        self.main_frame = tk.Frame(self.root, bg=C["bg"])
        self.main_frame.pack(side="left", fill="both", expand=True)
        self.pages = {}
        self._current_page = None

        self._build_dashboard_page()
        self._build_browse_page()
        self._build_history_page()
        self._build_settings_page()
        self._build_logs_page()

    def _update_enc_indicator(self):
        cfg = self.engine.cfg
        if encryptor.is_ready:
            self.sidebar_enc_label.configure(text="🔒 Encrypted (Unlocked)", fg=C["green"])
        elif cfg.get("encryption_salt"):
            self.sidebar_enc_label.configure(text="🔐 Locked — backups blocked", fg=C["amber"])
        else:
            self.sidebar_enc_label.configure(text="⚠ Setup needed — backups blocked", fg=C["red"])

    # ── Page switching ────────────────────────────────────────────────────────

    def _show_page(self, name: str):
        for page in self.pages.values():
            page.pack_forget()
        for key, btn in self.nav_buttons.items():
            btn.configure(bg=C["accent_dim"] if key == name else C["bg_panel"],
                          fg=C["accent"] if key == name else C["fg2"])
        self._current_page = name
        self.pages[name].pack(fill="both", expand=True, padx=32, pady=24)
        self._update_enc_indicator()
        if name == "dashboard":  self._refresh_dashboard()
        elif name == "browse":   self._refresh_browse()
        elif name == "history":  self._refresh_history()
        elif name == "settings": self._load_settings()
        elif name == "logs":     self._refresh_logs()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _make_btn(self, parent, text, command, style="primary", **kw):
        colors = {
            "primary":   (C["accent"], "#ffffff", "#2563eb"),
            "secondary": (C["bg_card"], C["fg2"],  C["bg_hover"]),
            "danger":    (C["red_dim"], C["red"],   C["red"]),
            "green":     (C["green_dim"], C["green"], C["green"]),
            "purple":    (C["purple_dim"], C["purple"], C["purple"]),
        }
        bg, fg, hover_bg = colors.get(style, colors["primary"])
        hover_fg = "#ffffff" if style in ("primary", "danger", "green", "purple") else C["fg"]
        btn = tk.Label(parent, text=text, bg=bg, fg=fg,
                       font=("Segoe UI", 9, "bold"), padx=16, pady=7,
                       cursor="hand2", relief="flat", **kw)
        btn.bind("<Enter>", lambda e: btn.configure(bg=hover_bg, fg=hover_fg))
        btn.bind("<Leave>", lambda e: btn.configure(bg=bg, fg=fg))
        btn.bind("<Button-1>", lambda e: command())
        return btn

    def _make_card(self, parent, **kw):
        return tk.Frame(parent, bg=C["bg_card"], highlightbackground=C["border"],
                        highlightthickness=1, **kw)

    # ══════════════════════════════════════════════════════════════════════════
    # DASHBOARD
    # ══════════════════════════════════════════════════════════════════════════

    def _build_dashboard_page(self):
        page = tk.Frame(self.main_frame, bg=C["bg"])
        self.pages["dashboard"] = page

        tk.Label(page, text="Dashboard", bg=C["bg"], fg=C["fg"],
                 font=("Segoe UI Semibold", 20)).pack(anchor="w", pady=(0, 4))
        tk.Label(page, text="Overview of your backup status",
                 bg=C["bg"], fg=C["fg3"], font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 18))

        stats_frame = tk.Frame(page, bg=C["bg"])
        stats_frame.pack(fill="x", pady=(0, 18))
        stats_frame.columnconfigure((0, 1, 2, 3, 4), weight=1)

        self.stat_labels = {}
        stat_defs = [
            ("files", "PROTECTED FILES", "—"),
            ("size", "BACKUP SIZE", "—"),
            ("encrypted", "ENCRYPTED", "—"),
            ("deleted", "PENDING DELETION", "—"),
            ("last", "LAST BACKUP", "—"),
        ]
        for i, (key, label, default) in enumerate(stat_defs):
            card = self._make_card(stats_frame)
            card.grid(row=0, column=i, padx=(0, 10) if i < 4 else 0, sticky="nsew")
            inner = tk.Frame(card, bg=C["bg_card"])
            inner.pack(padx=14, pady=14, fill="both")
            tk.Label(inner, text=label, bg=C["bg_card"], fg=C["fg3"],
                     font=("Segoe UI", 7, "bold")).pack(anchor="w")
            val = tk.Label(inner, text=default, bg=C["bg_card"], fg=C["fg"],
                           font=("Consolas", 16 if key != "last" else 10, "bold"))
            val.pack(anchor="w", pady=(4, 0))
            self.stat_labels[key] = val

        # Actions
        action_card = self._make_card(page)
        action_card.pack(fill="x", pady=(0, 18))
        action_inner = tk.Frame(action_card, bg=C["bg_card"])
        action_inner.pack(fill="x", padx=20, pady=16)
        tk.Label(action_inner, text="Backup Actions", bg=C["bg_card"], fg=C["fg"],
                 font=("Segoe UI Semibold", 12)).pack(anchor="w", pady=(0, 12))

        btn_row = tk.Frame(action_inner, bg=C["bg_card"])
        btn_row.pack(anchor="w")
        self._make_btn(btn_row, "⬆  Full Backup",
                       lambda: self._start_backup("full"), "primary").pack(side="left", padx=(0, 8))
        self._make_btn(btn_row, "⬆  Incremental",
                       lambda: self._start_backup("incremental"), "secondary").pack(side="left", padx=(0, 8))
        self._make_btn(btn_row, "✕  Cancel",
                       self._cancel_backup, "danger").pack(side="left", padx=(0, 8))
        self._make_btn(btn_row, "🗑  Purge Expired",
                       self._run_cleanup, "secondary").pack(side="left")

        prog_frame = tk.Frame(action_inner, bg=C["bg_card"])
        prog_frame.pack(fill="x", pady=(14, 0))
        self.progress_bar = ttk.Progressbar(prog_frame, style="blue.Horizontal.TProgressbar",
                                             mode="determinate", length=400)
        self.progress_bar.pack(fill="x")
        self.progress_label = tk.Label(prog_frame, text="Idle", bg=C["bg_card"],
                                        fg=C["fg2"], font=("Consolas", 8), anchor="w")
        self.progress_label.pack(fill="x", pady=(6, 0))

        # Recent backups
        hist_card = self._make_card(page)
        hist_card.pack(fill="both", expand=True)
        hist_inner = tk.Frame(hist_card, bg=C["bg_card"])
        hist_inner.pack(fill="both", expand=True, padx=4, pady=4)
        tk.Label(hist_inner, text="Recent Backups", bg=C["bg_card"], fg=C["fg"],
                 font=("Segoe UI Semibold", 12)).pack(anchor="w", padx=16, pady=(12, 8))

        cols = ("id", "type", "status", "files", "size", "started")
        self.dash_tree = ttk.Treeview(hist_inner, columns=cols, show="headings", height=5)
        for c, w, t in zip(cols, [260, 90, 90, 60, 90, 140],
                           ["Backup ID", "Type", "Status", "Files", "Size", "Started"]):
            self.dash_tree.heading(c, text=t)
            self.dash_tree.column(c, width=w, minwidth=50)
        self.dash_tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _refresh_dashboard(self):
        stats = self.engine.get_stats()
        self.stat_labels["files"].configure(text=f"{stats['total_files']:,}")
        self.stat_labels["size"].configure(text=format_bytes(stats["total_bytes"]))
        self.stat_labels["encrypted"].configure(
            text=f"{stats.get('encrypted_files', 0):,}",
            fg=C["green"] if stats.get("encrypted_files", 0) > 0 else C["fg"])
        self.stat_labels["deleted"].configure(text=f"{stats['deleted_pending']:,}")
        self.stat_labels["last"].configure(
            text=format_dt(stats["last_backup"]) if stats["last_backup"] else "Never")

        self.dash_tree.delete(*self.dash_tree.get_children())
        for b in self.engine.get_backup_history()[:8]:
            self.dash_tree.insert("", "end", values=(
                b["backup_id"], b["backup_type"], b["status"],
                b["files_count"], format_bytes(b["bytes_total"]),
                format_dt(b["started_at"]),
            ))

    def _start_backup(self, btype: str):
        if self.engine._running:
            messagebox.showwarning("CloudVault", "A backup is already running.")
            return
        cfg = self.engine.cfg
        if not cfg.get("bucket_name") or not has_aws_credentials(cfg):
            messagebox.showwarning("CloudVault",
                                   "Please set a bucket and AWS credentials in Settings first\n"
                                   "(saved keys, an AWS profile, or the standard AWS credential chain).")
            self._show_page("settings")
            return
        reason = encryption_block_reason(cfg)
        if reason:
            messagebox.showwarning("CloudVault",
                                   f"Backups are always encrypted, and {reason}.\n"
                                   "Backup was NOT started.")
            self._show_page("settings")
            return

        threading.Thread(target=lambda: self.engine.run_backup(btype), daemon=True).start()
        self._poll_progress()

    def _cancel_backup(self):
        if self.engine._running:
            self.engine.cancel_backup()

    def _poll_progress(self):
        p = self.engine.progress
        total = max(p["total"], 1)
        self.progress_bar["value"] = int((p["processed"] / total) * 100)
        status = p["status"]
        enc_tag = " 🔒" if encryptor.is_ready else ""
        if status == "uploading":
            txt = (f"Uploading{enc_tag} — {p['processed']}/{p['total']} scanned, "
                   f"{p['uploaded']} uploaded ({format_bytes(p['bytes_done'])})  "
                   f"▸ {p['current_file'][:55]}")
        elif status == "scanning":
            txt = "Scanning files..."
        elif status == "completed":
            txt = f"✓ Completed{enc_tag} — {p['uploaded']} files ({format_bytes(p['bytes_done'])})"
            self._refresh_dashboard()
        elif status == "cancelled":
            txt = "Backup cancelled."
            self._refresh_dashboard()
        elif status.startswith("error"):
            txt = f"✕ {status}"
        else:
            txt = "Idle"
        self.progress_label.configure(text=txt)
        if status in ("uploading", "scanning"):
            self.root.after(500, self._poll_progress)

    def _run_cleanup(self):
        def do():
            removed = self.engine.cleanup_expired()
            self.root.after(0, lambda: (
                messagebox.showinfo("CloudVault", f"Purged {removed} expired files."),
                self._refresh_dashboard(),
            ))
        threading.Thread(target=do, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    # BROWSE & RESTORE
    # ══════════════════════════════════════════════════════════════════════════

    def _build_browse_page(self):
        page = tk.Frame(self.main_frame, bg=C["bg"])
        self.pages["browse"] = page
        tk.Label(page, text="Browse & Restore", bg=C["bg"], fg=C["fg"],
                 font=("Segoe UI Semibold", 20)).pack(anchor="w", pady=(0, 4))
        tk.Label(page, text="Navigate your backed-up files and restore any version",
                 bg=C["bg"], fg=C["fg3"], font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 14))

        toolbar = tk.Frame(page, bg=C["bg"])
        toolbar.pack(fill="x", pady=(0, 10))
        self.breadcrumb_label = tk.Label(toolbar, text="🏠 Home", bg=C["bg"], fg=C["accent"],
                                          font=("Consolas", 10))
        self.breadcrumb_label.pack(side="left")
        chk = tk.Checkbutton(toolbar, text="Show deleted",
                             variable=self.show_deleted, bg=C["bg"], fg=C["fg2"],
                             selectcolor=C["bg_input"], activebackground=C["bg"],
                             activeforeground=C["fg"], font=("Segoe UI", 9),
                             command=self._refresh_browse)
        chk.pack(side="right")
        self._make_btn(toolbar, "⬆  Go Up", self._browse_up, "secondary").pack(side="right", padx=(0, 10))

        tree_card = self._make_card(page)
        tree_card.pack(fill="both", expand=True)
        tree_frame = tk.Frame(tree_card, bg=C["bg_card"])
        tree_frame.pack(fill="both", expand=True, padx=4, pady=4)

        cols = ("name", "type", "size", "modified", "status")
        self.browse_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=18)
        for c, w, t in zip(cols, [340, 70, 100, 150, 110],
                           ["Name", "Type", "Size", "Modified", "Status"]):
            self.browse_tree.heading(c, text=t)
            self.browse_tree.column(c, width=w, minwidth=50)
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.browse_tree.yview)
        self.browse_tree.configure(yscrollcommand=scroll.set)
        self.browse_tree.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=12)
        scroll.pack(side="right", fill="y", pady=12, padx=(0, 4))
        self.browse_tree.bind("<Double-1>", self._on_browse_double_click)

        browse_btns = tk.Frame(page, bg=C["bg"])
        browse_btns.pack(fill="x", pady=(10, 0))
        self._make_btn(browse_btns, "📥  Restore Selected",
                       self._restore_selected, "primary").pack(side="left", padx=(0, 8))
        self._make_btn(browse_btns, "📋  Show Versions",
                       self._show_versions, "secondary").pack(side="left", padx=(0, 8))
        self._make_btn(browse_btns, "📥  Restore to...",
                       self._restore_to_custom, "secondary").pack(side="left")

    def _update_breadcrumb(self):
        if not self.browse_path:
            text = "🏠  Home"
        else:
            text = "🏠 Home  ▸  " + "  ▸  ".join(self.browse_path.split("/"))
        self.breadcrumb_label.configure(text=text)

    def _refresh_browse(self):
        self._update_breadcrumb()
        items = self.engine.browse(self.browse_path, self.show_deleted.get())
        self.browse_tree.delete(*self.browse_tree.get_children())
        for item in items:
            if item["type"] == "folder":
                self.browse_tree.insert("", "end", iid=item["path"],
                    values=("📁  " + item["name"], "Folder", "", "", ""))
            else:
                if item.get("is_deleted"):
                    status = "🗑 Deleted"
                elif item.get("is_encrypted"):
                    status = "🔒 Encrypted"
                else:
                    status = "✓ Active"
                self.browse_tree.insert("", "end", iid=item["path"],
                    values=("📄  " + item["name"], "File",
                            format_bytes(item.get("size", 0)),
                            format_dt(item.get("modified")), status))

    def _on_browse_double_click(self, event):
        sel = self.browse_tree.selection()
        if not sel: return
        values = self.browse_tree.item(sel[0], "values")
        if values and values[1] == "Folder":
            self.browse_path = sel[0]
            self._refresh_browse()

    def _browse_up(self):
        if "/" in self.browse_path:
            self.browse_path = "/".join(self.browse_path.split("/")[:-1])
        else:
            self.browse_path = ""
        self._refresh_browse()

    def _restore_selected(self):
        sel = self.browse_tree.selection()
        if not sel:
            messagebox.showinfo("CloudVault", "Select a file to restore.")
            return
        values = self.browse_tree.item(sel[0], "values")
        if values[1] == "Folder":
            messagebox.showinfo("CloudVault", "Use 'Restore to...' for folders.")
            return
        versions = self.engine.get_versions(sel[0])
        if not versions: return
        v = versions[0]
        def do():
            try:
                dest = self.engine.restore_file(v["s3_key"], v.get("is_encrypted", 0))
                self.root.after(0, lambda: messagebox.showinfo("CloudVault", f"Restored to:\n{dest}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("CloudVault", f"Restore failed:\n{e}"))
        threading.Thread(target=do, daemon=True).start()

    def _restore_to_custom(self):
        sel = self.browse_tree.selection()
        if not sel:
            messagebox.showinfo("CloudVault", "Select a file first.")
            return
        dest_dir = filedialog.askdirectory(title="Choose restore destination")
        if not dest_dir: return
        values = self.browse_tree.item(sel[0], "values")
        if values[1] == "Folder":
            def do():
                try:
                    result = self.engine.restore_folder(sel[0], dest_dir)
                    self.root.after(0, lambda: messagebox.showinfo(
                        "CloudVault", f"Restored {result.get('restored_count', 0)} files."))
                except Exception as e:
                    self.root.after(0, lambda: messagebox.showerror("CloudVault", str(e)))
            threading.Thread(target=do, daemon=True).start()
        else:
            versions = self.engine.get_versions(sel[0])
            if not versions: return
            v = versions[0]
            fname = sel[0].split("/")[-1]
            dest_path = os.path.join(dest_dir, fname)
            def do():
                try:
                    self.engine.restore_file(v["s3_key"], v.get("is_encrypted", 0), dest_path)
                    self.root.after(0, lambda: messagebox.showinfo("CloudVault", f"Restored to:\n{dest_path}"))
                except Exception as e:
                    self.root.after(0, lambda: messagebox.showerror("CloudVault", str(e)))
            threading.Thread(target=do, daemon=True).start()

    def _show_versions(self):
        sel = self.browse_tree.selection()
        if not sel:
            messagebox.showinfo("CloudVault", "Select a file first.")
            return
        item_id = sel[0]
        values = self.browse_tree.item(item_id, "values")
        if values[1] == "Folder":
            messagebox.showinfo("CloudVault", "Versions are for files only.")
            return
        versions = self.engine.get_versions(item_id)
        if not versions:
            messagebox.showinfo("CloudVault", "No versions found.")
            return

        win = tk.Toplevel(self.root)
        win.title(f"Versions — {item_id.split('/')[-1]}")
        win.configure(bg=C["bg"])
        win.geometry("750x380")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text=f"File: {item_id}", bg=C["bg"], fg=C["fg"],
                 font=("Consolas", 9)).pack(anchor="w", padx=16, pady=(14, 10))

        cols = ("backup", "size", "modified", "backed_up", "enc")
        tree = ttk.Treeview(win, columns=cols, show="headings", height=10)
        for c, w, t in zip(cols, [220, 80, 140, 140, 80],
                           ["Backup ID", "Size", "Modified", "Backed Up", "Encrypted"]):
            tree.heading(c, text=t)
            tree.column(c, width=w)
        for v in versions:
            tree.insert("", "end", iid=v["s3_key"], values=(
                v["backup_id"], format_bytes(v["file_size"]),
                format_dt(v["modified_at"]), format_dt(v["backed_up_at"]),
                "🔒 Yes" if v.get("is_encrypted") else "No",
            ))
        tree.pack(fill="both", expand=True, padx=16, pady=(0, 10))

        btn_frame = tk.Frame(win, bg=C["bg"])
        btn_frame.pack(fill="x", padx=16, pady=(0, 14))

        # Store versions for lookup
        ver_map = {v["s3_key"]: v for v in versions}

        def restore_ver():
            s = tree.selection()
            if not s: return
            v = ver_map[s[0]]
            def do():
                try:
                    dest = self.engine.restore_file(v["s3_key"], v.get("is_encrypted", 0))
                    self.root.after(0, lambda: messagebox.showinfo("CloudVault", f"Restored to:\n{dest}"))
                except Exception as e:
                    self.root.after(0, lambda: messagebox.showerror("CloudVault", str(e)))
            threading.Thread(target=do, daemon=True).start()

        self._make_btn(btn_frame, "📥  Restore Version", restore_ver, "primary").pack(side="left", padx=(0, 8))
        self._make_btn(btn_frame, "Close", win.destroy, "secondary").pack(side="right")

    # ══════════════════════════════════════════════════════════════════════════
    # HISTORY
    # ══════════════════════════════════════════════════════════════════════════

    def _build_history_page(self):
        page = tk.Frame(self.main_frame, bg=C["bg"])
        self.pages["history"] = page
        tk.Label(page, text="Backup History", bg=C["bg"], fg=C["fg"],
                 font=("Segoe UI Semibold", 20)).pack(anchor="w", pady=(0, 4))
        tk.Label(page, text="Complete log of all backup runs",
                 bg=C["bg"], fg=C["fg3"], font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 14))

        card = self._make_card(page)
        card.pack(fill="both", expand=True)
        cols = ("id", "type", "status", "files", "size", "started", "finished")
        self.hist_tree = ttk.Treeview(card, columns=cols, show="headings", height=20)
        for c, w, t in zip(cols, [240, 80, 80, 60, 80, 140, 140],
                           ["Backup ID", "Type", "Status", "Files", "Size", "Started", "Finished"]):
            self.hist_tree.heading(c, text=t)
            self.hist_tree.column(c, width=w, minwidth=50)
        self.hist_tree.pack(fill="both", expand=True, padx=12, pady=12)

    def _refresh_history(self):
        self.hist_tree.delete(*self.hist_tree.get_children())
        for b in self.engine.get_backup_history():
            self.hist_tree.insert("", "end", values=(
                b["backup_id"], b["backup_type"], b["status"],
                b["files_count"], format_bytes(b["bytes_total"]),
                format_dt(b["started_at"]), format_dt(b["finished_at"]),
            ))

    # ══════════════════════════════════════════════════════════════════════════
    # SETTINGS
    # ══════════════════════════════════════════════════════════════════════════

    def _build_settings_page(self):
        page = tk.Frame(self.main_frame, bg=C["bg"])
        self.pages["settings"] = page
        tk.Label(page, text="Settings", bg=C["bg"], fg=C["fg"],
                 font=("Segoe UI Semibold", 20)).pack(anchor="w", pady=(0, 4))
        tk.Label(page, text="AWS connection, encryption, and backup preferences",
                 bg=C["bg"], fg=C["fg3"], font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 14))

        canvas = tk.Canvas(page, bg=C["bg"], highlightthickness=0)
        scroll = ttk.Scrollbar(page, orient="vertical", command=canvas.yview)
        settings_frame = tk.Frame(canvas, bg=C["bg"])
        settings_frame.bind("<Configure>",
                            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=settings_frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.cfg_entries = {}

        def add_field(parent, key, label, show="", hint="", browse=False):
            row = tk.Frame(parent, bg=C["bg_card"])
            row.pack(fill="x", pady=(0, 12))
            tk.Label(row, text=label, bg=C["bg_card"], fg=C["fg3"],
                     font=("Segoe UI", 8, "bold")).pack(anchor="w")
            entry_row = tk.Frame(row, bg=C["bg_card"])
            entry_row.pack(fill="x", pady=(4, 0))
            entry = tk.Entry(entry_row, bg=C["bg_input"], fg=C["fg"],
                             insertbackground=C["fg"], relief="flat",
                             font=("Consolas", 10), highlightthickness=1,
                             highlightbackground=C["border"], highlightcolor=C["accent"])
            if show:
                entry.configure(show=show)
            entry.pack(side="left", fill="x", expand=True, ipady=6)
            self.cfg_entries[key] = entry
            if browse:
                def pick():
                    d = filedialog.askdirectory()
                    if d:
                        entry.delete(0, "end")
                        entry.insert(0, d)
                self._make_btn(entry_row, "Browse", pick, "secondary").pack(side="left", padx=(8, 0))
            if key in ("aws_secret_key",):
                visible = [False]
                def toggle(e=entry):
                    visible[0] = not visible[0]
                    e.configure(show="" if visible[0] else "●")
                    toggle_btn.configure(text="Hide" if visible[0] else "Show")
                toggle_btn = self._make_btn(entry_row, "Show", toggle, "secondary")
                toggle_btn.pack(side="left", padx=(8, 0))
            if hint:
                tk.Label(row, text=hint, bg=C["bg_card"], fg=C["fg3"],
                         font=("Segoe UI", 7)).pack(anchor="w", pady=(2, 0))

        # ── AWS Credentials card ──
        aws_card = self._make_card(settings_frame)
        aws_card.pack(fill="x", pady=(0, 16), padx=(0, 16))
        aws_inner = tk.Frame(aws_card, bg=C["bg_card"])
        aws_inner.pack(fill="x", padx=20, pady=16)
        tk.Label(aws_inner, text="AWS Credentials", bg=C["bg_card"], fg=C["fg"],
                 font=("Segoe UI Semibold", 13)).pack(anchor="w", pady=(0, 14))

        row1 = tk.Frame(aws_inner, bg=C["bg_card"])
        row1.pack(fill="x")
        row1.columnconfigure((0, 1), weight=1)
        left = tk.Frame(row1, bg=C["bg_card"])
        left.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        right = tk.Frame(row1, bg=C["bg_card"])
        right.grid(row=0, column=1, sticky="ew", padx=(8, 0))

        add_field(left, "bucket_name", "S3 BUCKET NAME", hint="Will be created if it doesn't exist")

        tk.Label(right, text="AWS REGION", bg=C["bg_card"], fg=C["fg3"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        region_frame = tk.Frame(right, bg=C["bg_card"])
        region_frame.pack(fill="x", pady=(4, 12))
        self.region_var = tk.StringVar(value="us-east-1")
        ttk.Combobox(region_frame, textvariable=self.region_var,
                     values=["us-east-1","us-east-2","us-west-1","us-west-2",
                             "eu-west-1","eu-central-1","ap-southeast-1","ap-northeast-1"],
                     state="readonly", font=("Consolas", 10)).pack(fill="x", ipady=4)

        add_field(aws_inner, "aws_profile", "AWS PROFILE (OPTIONAL, RECOMMENDED)",
                  hint="Named profile from ~/.aws/config. Leave blank to use saved keys, "
                       "then the standard AWS credential chain (env vars, SSO, role)")
        add_field(aws_inner, "aws_access_key", "AWS ACCESS KEY ID (OPTIONAL)",
                  hint="Only needed if you are not using a profile or the AWS credential chain")
        add_field(aws_inner, "aws_secret_key", "AWS SECRET ACCESS KEY (OPTIONAL)", show="●",
                  hint="Saved to Windows Credential Manager only — never written to config.json")
        self.cred_store_label = tk.Label(aws_inner, text="", bg=C["bg_card"], fg=C["fg3"],
                                         font=("Segoe UI", 8), justify="left")
        self.cred_store_label.pack(anchor="w", pady=(0, 8))

        aws_btns = tk.Frame(aws_inner, bg=C["bg_card"])
        aws_btns.pack(anchor="w", pady=(4, 0))
        self._make_btn(aws_btns, "💾  Save Settings", self._save_settings, "primary").pack(side="left", padx=(0, 8))
        self._make_btn(aws_btns, "🔌  Test Connection", self._test_connection, "green").pack(side="left", padx=(0, 8))
        self._make_btn(aws_btns, "🗑  Remove Saved Keys", self._remove_saved_keys, "danger").pack(side="left")
        self.connection_status = tk.Label(aws_inner, text="", bg=C["bg_card"], fg=C["fg3"], font=("Segoe UI", 9))
        self.connection_status.pack(anchor="w", pady=(10, 0))

        # ── Encryption card ──
        enc_card = self._make_card(settings_frame)
        enc_card.pack(fill="x", pady=(0, 16), padx=(0, 16))
        enc_inner = tk.Frame(enc_card, bg=C["bg_card"])
        enc_inner.pack(fill="x", padx=20, pady=16)
        tk.Label(enc_inner, text="🔒  Client-Side Encryption (AES-256-GCM)", bg=C["bg_card"], fg=C["fg"],
                 font=("Segoe UI Semibold", 13)).pack(anchor="w", pady=(0, 6))

        if not HAS_CRYPTO:
            tk.Label(enc_inner, text="⚠  The 'cryptography' package is not installed.\n"
                     "Run: pip install cryptography",
                     bg=C["bg_card"], fg=C["amber"], font=("Segoe UI", 9),
                     justify="left").pack(anchor="w", pady=(6, 0))
        else:
            tk.Label(enc_inner,
                     text="Files are encrypted on your machine before upload. Without your\n"
                          "passphrase, the data on S3 is unreadable — even to AWS.",
                     bg=C["bg_card"], fg=C["fg3"], font=("Segoe UI", 8),
                     justify="left").pack(anchor="w", pady=(0, 12))

            # Passphrase entry
            pp_row = tk.Frame(enc_inner, bg=C["bg_card"])
            pp_row.pack(fill="x", pady=(0, 10))
            tk.Label(pp_row, text="ENCRYPTION PASSPHRASE", bg=C["bg_card"], fg=C["fg3"],
                     font=("Segoe UI", 8, "bold")).pack(anchor="w")
            pp_entry_row = tk.Frame(pp_row, bg=C["bg_card"])
            pp_entry_row.pack(fill="x", pady=(4, 0))
            self.passphrase_entry = tk.Entry(pp_entry_row, bg=C["bg_input"], fg=C["fg"],
                                              insertbackground=C["fg"], relief="flat",
                                              font=("Consolas", 10), show="●",
                                              highlightthickness=1,
                                              highlightbackground=C["border"],
                                              highlightcolor=C["accent"])
            self.passphrase_entry.pack(side="left", fill="x", expand=True, ipady=6)

            pp_visible = [False]
            def toggle_pp():
                pp_visible[0] = not pp_visible[0]
                self.passphrase_entry.configure(show="" if pp_visible[0] else "●")
                pp_toggle_btn.configure(text="Hide" if pp_visible[0] else "Show")
            pp_toggle_btn = self._make_btn(pp_entry_row, "Show", toggle_pp, "secondary")
            pp_toggle_btn.pack(side="left", padx=(8, 0))

            tk.Label(pp_row, text="Choose a strong passphrase. If you lose it, encrypted backups are irrecoverable.",
                     bg=C["bg_card"], fg=C["red"], font=("Segoe UI", 7)).pack(anchor="w", pady=(4, 0))

            # Confirm passphrase (for setup)
            cp_row = tk.Frame(enc_inner, bg=C["bg_card"])
            cp_row.pack(fill="x", pady=(0, 12))
            tk.Label(cp_row, text="CONFIRM PASSPHRASE (for initial setup only)",
                     bg=C["bg_card"], fg=C["fg3"], font=("Segoe UI", 8, "bold")).pack(anchor="w")
            self.passphrase_confirm = tk.Entry(cp_row, bg=C["bg_input"], fg=C["fg"],
                                                insertbackground=C["fg"], relief="flat",
                                                font=("Consolas", 10), show="●",
                                                highlightthickness=1,
                                                highlightbackground=C["border"],
                                                highlightcolor=C["accent"])
            self.passphrase_confirm.pack(fill="x", ipady=6, pady=(4, 0))

            enc_btns = tk.Frame(enc_inner, bg=C["bg_card"])
            enc_btns.pack(anchor="w", pady=(4, 0))
            self._make_btn(enc_btns, "🔐  Enable & Lock Encryption",
                           self._enable_encryption, "purple").pack(side="left", padx=(0, 8))
            self._make_btn(enc_btns, "🔓  Unlock",
                           self._unlock_encryption, "green").pack(side="left")

            self.enc_status = tk.Label(enc_inner, text="", bg=C["bg_card"], fg=C["fg3"],
                                        font=("Segoe UI", 9))
            self.enc_status.pack(anchor="w", pady=(10, 0))

        # ── Backup Preferences card ──
        pref_card = self._make_card(settings_frame)
        pref_card.pack(fill="x", pady=(0, 16), padx=(0, 16))
        pref_inner = tk.Frame(pref_card, bg=C["bg_card"])
        pref_inner.pack(fill="x", padx=20, pady=16)
        tk.Label(pref_inner, text="Backup Preferences", bg=C["bg_card"], fg=C["fg"],
                 font=("Segoe UI Semibold", 13)).pack(anchor="w", pady=(0, 14))

        add_field(pref_inner, "home_folder", "HOME FOLDER TO BACK UP",
                  hint="The root folder whose contents will be backed up", browse=True)
        add_field(pref_inner, "backup_prefix", "S3 KEY PREFIX",
                  hint="Prefix for all objects in the bucket")

        ret_row = tk.Frame(pref_inner, bg=C["bg_card"])
        ret_row.pack(fill="x", pady=(0, 12))
        tk.Label(ret_row, text="RETENTION DAYS", bg=C["bg_card"], fg=C["fg3"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self.retention_entry = tk.Entry(ret_row, bg=C["bg_input"], fg=C["fg"],
                                         insertbackground=C["fg"], relief="flat",
                                         font=("Consolas", 10), width=8,
                                         highlightthickness=1,
                                         highlightbackground=C["border"],
                                         highlightcolor=C["accent"])
        self.retention_entry.pack(anchor="w", ipady=6, pady=(4, 0))
        tk.Label(ret_row, text="Days to keep deleted files before permanent removal",
                 bg=C["bg_card"], fg=C["fg3"], font=("Segoe UI", 7)).pack(anchor="w", pady=(2, 0))

        add_field(pref_inner, "exclude_patterns", "EXCLUDE PATTERNS (comma-separated)",
                  hint="Files & folders matching these globs are skipped")

    # ── Encryption actions ────────────────────────────────────────────────────

    def _enable_encryption(self):
        if not HAS_CRYPTO:
            messagebox.showerror("CloudVault", "Install 'cryptography' first:\npip install cryptography")
            return
        pp = self.passphrase_entry.get()
        pp2 = self.passphrase_confirm.get()
        if len(pp) < 8:
            messagebox.showwarning("CloudVault", "Passphrase must be at least 8 characters.")
            return
        if pp != pp2:
            messagebox.showwarning("CloudVault", "Passphrases don't match. Try again.")
            return

        existing = load_config()
        if existing.get("encryption_salt") and existing.get("encryption_verify"):
            messagebox.showwarning(
                "CloudVault",
                "Encryption is already set up. Re-running setup would make your existing\n"
                "encrypted backups permanently unreadable.\n\n"
                "Enter your passphrase and click Unlock instead.")
            return
        confirm = messagebox.askyesno(
            "Set Up Encryption",
            "All backups are encrypted before upload.\n\n"
            "⚠  If you lose your passphrase, backups are\n"
            "PERMANENTLY IRRECOVERABLE.\n\n"
            "Existing unencrypted backups will remain accessible.\n\n"
            "Continue?")
        if not confirm:
            return

        salt_b64, verify_b64 = encryptor.setup_new(pp)
        cfg = load_config()
        cfg["encryption_enabled"] = True
        cfg["encryption_salt"] = salt_b64
        cfg["encryption_verify"] = verify_b64
        save_config(cfg)
        self.engine.reload_config()
        self.enc_status.configure(text="✓ Encryption enabled and unlocked", fg=C["green"])
        self._update_enc_indicator()
        log.info("Encryption enabled with AES-256-GCM")

    def _unlock_encryption(self):
        if not HAS_CRYPTO:
            return
        pp = self.passphrase_entry.get()
        if not pp:
            messagebox.showwarning("CloudVault", "Enter your passphrase.")
            return
        cfg = load_config()
        if not cfg.get("encryption_salt") or not cfg.get("encryption_verify"):
            messagebox.showinfo("CloudVault",
                                "Encryption is not set up yet.\nUse 'Enable & Lock Encryption' first.")
            return
        ok = encryptor.unlock(pp, cfg["encryption_salt"], cfg["encryption_verify"])
        if ok:
            self.enc_status.configure(text="✓ Passphrase correct — encryption unlocked", fg=C["green"])
            self._update_enc_indicator()
            log.info("Encryption unlocked")
        else:
            self.enc_status.configure(text="✕ Wrong passphrase", fg=C["red"])

    # ── Settings load/save ────────────────────────────────────────────────────

    def _load_settings(self):
        cfg = load_config()
        for key, val in {
            "bucket_name": cfg.get("bucket_name", ""),
            "aws_profile": cfg.get("aws_profile", ""),
            "aws_access_key": get_stored_access_key_id(),
            "aws_secret_key": "",   # never loaded back into the UI
            "home_folder": cfg.get("home_folder", ""),
            "backup_prefix": cfg.get("backup_prefix", ""),
            "exclude_patterns": ", ".join(cfg.get("exclude_patterns", [])),
        }.items():
            entry = self.cfg_entries[key]
            entry.delete(0, "end")
            entry.insert(0, val)
        self.region_var.set(cfg.get("aws_region", "us-east-1"))
        self.retention_entry.delete(0, "end")
        self.retention_entry.insert(0, str(cfg.get("retention_days", 90)))
        self.connection_status.configure(text="", fg=C["fg3"])
        if load_stored_aws_credentials():
            self.cred_store_label.configure(
                text="🔑 Keys saved in Windows Credential Manager (secret not shown)", fg=C["green"])
        elif keyring_available():
            self.cred_store_label.configure(
                text="No keys saved. Using AWS profile / credential chain.", fg=C["fg3"])
        else:
            self.cred_store_label.configure(
                text="Secure key storage unavailable (pip install keyring). "
                     "Use an AWS profile or the AWS credential chain.", fg=C["amber"])

        # Update encryption status display
        if HAS_CRYPTO:
            if encryptor.is_ready:
                self.enc_status.configure(text="🔒 Encryption is ON and unlocked", fg=C["green"])
            elif cfg.get("encryption_salt"):
                self.enc_status.configure(text="🔐 Locked — enter passphrase and click Unlock to back up",
                                           fg=C["amber"])
            else:
                self.enc_status.configure(text="⚠ Not set up — backups are blocked until you create a passphrase",
                                           fg=C["red"])

    def _save_settings(self):
        cfg = load_config()
        cfg["bucket_name"] = self.cfg_entries["bucket_name"].get().strip()
        cfg["aws_region"] = self.region_var.get()
        cfg["aws_profile"] = self.cfg_entries["aws_profile"].get().strip()
        access = self.cfg_entries["aws_access_key"].get().strip()
        secret = self.cfg_entries["aws_secret_key"].get().strip()
        key_msg = ""
        if secret:
            if not access:
                messagebox.showwarning("CloudVault",
                                       "Enter the Access Key ID together with the secret key.")
                return
            try:
                store_aws_credentials(access, secret)
                self.cfg_entries["aws_secret_key"].delete(0, "end")
                key_msg = " (keys saved to Credential Manager)"
            except Exception as e:
                messagebox.showerror("CloudVault",
                                     f"Keys were NOT saved:\n{e}")
                return
        elif access and access != get_stored_access_key_id():
            messagebox.showwarning("CloudVault",
                                   "Enter the secret key too, or clear the Access Key ID field. "
                                   "Keys were not changed.")
            return
        cfg["home_folder"] = self.cfg_entries["home_folder"].get().strip()
        cfg["backup_prefix"] = self.cfg_entries["backup_prefix"].get().strip()
        cfg["exclude_patterns"] = [
            p.strip() for p in self.cfg_entries["exclude_patterns"].get().split(",") if p.strip()
        ]
        try:
            cfg["retention_days"] = int(self.retention_entry.get())
        except ValueError:
            cfg["retention_days"] = 90
        save_config(cfg)
        self.engine.reload_config()
        self._load_settings()
        self.connection_status.configure(text=f"✓ Settings saved{key_msg}", fg=C["green"])

    def _remove_saved_keys(self):
        if not messagebox.askyesno(
                "Remove Saved Keys",
                "Delete the AWS keys saved in Windows Credential Manager?\n\n"
                "CloudVault will then use the AWS profile or standard credential chain."):
            return
        delete_stored_aws_credentials()
        self._load_settings()
        self.connection_status.configure(text="Saved keys removed", fg=C["amber"])

    def _test_connection(self):
        self.connection_status.configure(text="Testing...", fg=C["amber"])
        self.root.update_idletasks()
        def do():
            try:
                cfg = load_config()
                s3 = get_s3_client(cfg)
                ensure_bucket(s3, cfg["bucket_name"], cfg["aws_region"])
                msg = f"✓ Connected to bucket: {cfg['bucket_name']}"
                color = C["green"]
            except Exception as e:
                msg = f"✕ Connection failed: {e}"
                color = C["red"]
            self.root.after(0, lambda: self.connection_status.configure(text=msg, fg=color))
        threading.Thread(target=do, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    # LOGS
    # ══════════════════════════════════════════════════════════════════════════

    def _build_logs_page(self):
        page = tk.Frame(self.main_frame, bg=C["bg"])
        self.pages["logs"] = page
        header = tk.Frame(page, bg=C["bg"])
        header.pack(fill="x", pady=(0, 14))
        tk.Label(header, text="Activity Logs", bg=C["bg"], fg=C["fg"],
                 font=("Segoe UI Semibold", 20)).pack(side="left")
        self._make_btn(header, "🔄  Refresh", self._refresh_logs, "secondary").pack(side="right")

        card = self._make_card(page)
        card.pack(fill="both", expand=True)
        self.log_text = tk.Text(card, bg=C["bg_input"], fg=C["fg2"],
                                 font=("Consolas", 9), relief="flat", wrap="word",
                                 padx=14, pady=14, insertbackground=C["fg"],
                                 highlightthickness=1, highlightbackground=C["border"],
                                 state="disabled")
        log_scroll = ttk.Scrollbar(card, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=12)
        log_scroll.pack(side="right", fill="y", pady=12, padx=(0, 4))

    def _refresh_logs(self):
        try:
            with open(LOG_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
            text = "".join(lines[-300:])
        except FileNotFoundError:
            text = "(No log file found yet.)"
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.insert("end", text)
        self.log_text.configure(state="disabled")
        self.log_text.see("end")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    root = tk.Tk()
    try:
        import ctypes
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 20, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int))
    except Exception:
        pass
    migration = migrate_legacy_credentials()
    app = CloudVaultApp(root)
    if migration == "unmigrated":
        messagebox.showwarning(
            "CloudVault — plaintext AWS keys found",
            "Older versions saved your AWS keys in plaintext in config.json.\n\n"
            "They are being ignored. Install secure storage (pip install keyring) "
            "and restart to migrate them, or use an AWS profile / the standard AWS "
            "credential chain, then delete the keys from:\n" + str(CONFIG_PATH))
    root.mainloop()

if __name__ == "__main__":
    main()
