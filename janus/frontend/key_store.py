# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
Frontend Key Store

SQLite-backed registry of attested back-end servers.
The database file lives in Gramine's sealed directory so its contents are
encrypted by the SGX sealing key and never leave the enclave.

Reads (``list_backends`` / ``get_backend``) are served from an in-memory
cache so the read-heavy routing/forward hot path never re-opens the sealed
file.  Re-opening it is expensive in SGX: every ``sqlite3.connect`` triggers
a sealed-file open plus AES decryption through enclave OCALLs (~14 ms per
call on our platform).  The sealed DB stays the persistent source of truth
(it survives enclave restarts); the cache is a write-through read accelerator.

Schema:
  backends  – one row per attested backend (ip, port, mode)
"""

import os
import sqlite3
import logging
import threading
from typing import Optional, Dict, List


_SCHEMA = """
CREATE TABLE IF NOT EXISTS backends (
    cvm_id         TEXT PRIMARY KEY,
    ip_address     TEXT NOT NULL,
    port           INTEGER NOT NULL DEFAULT 443,
    cvm_mode       TEXT NOT NULL DEFAULT 'in-update',
    public_key_pem TEXT NOT NULL DEFAULT '',
    cert_fp        TEXT NOT NULL DEFAULT ''
);
"""

# public_key_pem: the backend's TLS public key from its CSR, kept so the
#   frontend can re-sign the backend's DC when its own certificate is renewed
#   (design §4.3).
# cert_fp: SHA-256 of the backend's self-signed X.509 certificate (same key),
#   the pin for the frontend's proxy-mode hop (design §4.4).
_BACKEND_COLS = ['cvm_id', 'ip_address', 'port', 'cvm_mode', 'public_key_pem', 'cert_fp']


class FrontendKeyStore:
    """
    Registry of attested back-end servers.

    In SGX mode the db_path should point to Gramine's sealed directory so
    SQLite writes are transparently encrypted by the hardware sealing key.

    The server runs single-process (``app.run(threaded=True)``), so a single
    process-wide in-memory cache is consistent across worker threads; a lock
    guards the read-vs-refresh race.
    """

    def __init__(self, sealed_dir: str, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        os.makedirs(sealed_dir, exist_ok=True)
        self.db_path = os.path.join(sealed_dir, "keystore.db")
        self._init_db()
        # In-memory cache of the backends table, keyed by cvm_id.  Populated
        # from the sealed DB at startup and refreshed write-through on every
        # mutation, so reads never touch the sealed file.
        self._lock = threading.Lock()
        self._cache: Dict[str, Dict] = {}
        self._refresh_cache()
        self.logger.info(f"Key store initialised at {self.db_path}")

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            # Migrate a key store created before public_key_pem / cert_fp
            # existed (a sealed DB survives frontend restarts, so it may be
            # older than the code).
            have = {r[1] for r in conn.execute("PRAGMA table_info(backends)").fetchall()}
            for col in ("public_key_pem", "cert_fp"):
                if col not in have:
                    conn.execute(f"ALTER TABLE backends ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
                    self.logger.info(f"Key store migrated: added column {col}")
            conn.commit()

    def _refresh_cache(self):
        """Reload the whole table from the sealed DB into memory.  Called
        once at startup and after every mutation (mutations are rare:
        backend registration / mode change / removal)."""
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM backends").fetchall()
        cache = {r[0]: dict(zip(_BACKEND_COLS, r)) for r in rows}
        with self._lock:
            self._cache = cache

    def add_backend(self, cvm_id: str, ip_address: str, port: int,
                    public_key_pem: str = "", cert_fp: str = ""):
        """Insert or replace a back-end record (initial mode: 'in-update')."""
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO backends "
                "(cvm_id, ip_address, port, cvm_mode, public_key_pem, cert_fp) "
                "VALUES (?, ?, ?, 'in-update', ?, ?)",
                (cvm_id, ip_address, port, public_key_pem, cert_fp),
            )
            conn.commit()
        self._refresh_cache()
        self.logger.info(f"Backend {cvm_id} added to key store")

    def get_backend(self, cvm_id: str) -> Optional[Dict]:
        with self._lock:
            row = self._cache.get(cvm_id)
            return dict(row) if row else None

    def list_backends(self, mode: Optional[str] = None) -> List[Dict]:
        with self._lock:
            rows = [dict(r) for r in self._cache.values()]
        if mode:
            rows = [r for r in rows if r["cvm_mode"] == mode]
        return rows

    def set_cvm_mode(self, cvm_id: str, mode: str):
        assert mode in ("in-update", "in-service")
        with self._conn() as conn:
            conn.execute(
                "UPDATE backends SET cvm_mode = ? WHERE cvm_id = ?", (mode, cvm_id)
            )
            conn.commit()
        self._refresh_cache()
        self.logger.info(f"Backend {cvm_id} mode → {mode}")

    def remove_backend(self, cvm_id: str):
        with self._conn() as conn:
            conn.execute("DELETE FROM backends WHERE cvm_id = ?", (cvm_id,))
            conn.commit()
        self._refresh_cache()
        self.logger.info(f"Backend {cvm_id} removed from key store")
