# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
Janus Frontend Admin Client

CLI tool for managing CVMs via the Janus frontend server.
Mirrors the predecessor project's admin client, adapted for the Janus frontend.

Privileged operations (start-cvm, stop-cvm, mark-cvm) must be signed with
the service owner's RSA private key.  The frontend verifies the signature
with the matching public key that was loaded at startup.

Usage
─────
# Generate a service owner keypair (one-time setup):
    python3 -m janus.admin_client --action generate-owner-key

# Start a backend CVM:
    python3 -m janus.admin_client \\
        --url https://127.0.0.1:6037 \\
        --key service_owner_private_key.pem \\
        --action start-cvm --cvm-type snp

# Show pool status (no signature required):
    python3 -m janus.admin_client \\
        --url https://127.0.0.1:6037 \\
        --action pool-status

# Mark a backend in-service:
    python3 -m janus.admin_client \\
        --url https://127.0.0.1:6037 \\
        --key service_owner_private_key.pem \\
        --action mark-cvm \\
        --cvm-id <id> --cvm-mode in-service

# Stop and delete a backend CVM:
    python3 -m janus.admin_client \\
        --url https://127.0.0.1:6037 \\
        --key service_owner_private_key.pem \\
        --action stop-cvm --cvm-id <id>
"""

from argparse import ArgumentParser
import base64
import json
import logging
import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    format="[%(asctime)s] %(levelname)s: %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Key generation helper
# ─────────────────────────────────────────────────────────────────────────────

def generate_owner_keypair(
    private_key_path: str = "service_owner_private_key.pem",
    public_key_path:  str = "service_owner_public_key.pub",
) -> None:
    """Generate an RSA-4096 service owner keypair and write both files."""
    key = rsa.generate_private_key(65537, 4096, default_backend())

    with open(private_key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    os.chmod(private_key_path, 0o600)

    with open(public_key_path, "wb") as f:
        f.write(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(f"Service owner private key → {private_key_path}")
    print(f"Service owner public key  → {public_key_path}")
    print()
    print("Next steps:")
    print(f"  1. Copy {public_key_path} to the frontend's sealed directory")
    print(f"     (or set SERVICE_OWNER_PUBLIC_KEY_PATH env var)")
    print(f"  2. Keep {private_key_path} secure — it authorises privileged ops")


# ─────────────────────────────────────────────────────────────────────────────
# Admin client
# ─────────────────────────────────────────────────────────────────────────────

class FrontendAdminClient:
    """
    Client for the Janus frontend server's admin API.

    Privileged operations are signed with the service owner's RSA private key
    (same RSA-PSS scheme as the predecessor project's admin client).
    """

    def __init__(
        self,
        base_url: str,
        private_key_path: str = None,
        verify_tls: bool = False,
    ):
        self._base_url    = base_url.rstrip("/")
        self._verify_tls  = verify_tls
        self._private_key = None

        if private_key_path:
            with open(private_key_path, "rb") as f:
                self._private_key = load_pem_private_key(f.read(), None, default_backend())
            logger.info(f"Loaded service owner private key from {private_key_path}")

    # ── signing ───────────────────────────────────────────────────────────────

    def _sign(self, params: dict) -> str:
        """RSA-PSS sign JSON(params, sort_keys=True), return base64 string."""
        if not self._private_key:
            raise RuntimeError("No private key loaded — cannot sign privileged request")
        message   = json.dumps(params, sort_keys=True).encode()
        signature = self._private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode()

    def _post(self, path: str, params: dict, privileged: bool = True) -> dict:
        body = {"params": params}
        if privileged:
            body["signature"] = self._sign(params)
        resp = requests.post(
            self._base_url + path,
            json=body,
            verify=self._verify_tls,
            timeout=300,   # CVM provisioning can take several minutes
        )
        return resp.json()

    def _get(self, path: str) -> dict:
        resp = requests.get(
            self._base_url + path,
            verify=self._verify_tls,
            timeout=30,
        )
        return resp.json()

    # ── public API ────────────────────────────────────────────────────────────

    def pool_status(self) -> dict:
        return self._get("/pool_status")

    def start_cvm(self, cvm_type: str) -> dict:
        return self._post("/start_cvm", {"cvm_type": cvm_type})

    def stop_cvm(self, cvm_id: str) -> dict:
        return self._post("/stop_cvm", {"cvm_id": cvm_id})

    def mark_cvm(self, cvm_id: str, cvm_mode: str) -> dict:
        return self._post("/mark_cvm", {"cvm_id": cvm_id, "cvm_mode": cvm_mode})


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = ArgumentParser(description="Janus Frontend Admin Client")
    p.add_argument("--url",      default="https://127.0.0.1:6037",
                   help="Frontend base URL (default: https://127.0.0.1:6037)")
    p.add_argument("--key",      metavar="PRIVATE_KEY_FILE",
                   help="Service owner RSA private key (required for privileged ops)")
    p.add_argument("--verify-tls", action="store_true",
                   help="Verify the frontend's TLS certificate (off by default)")
    p.add_argument("--action", required=True,
                   choices=["generate-owner-key", "start-cvm", "stop-cvm",
                            "mark-cvm", "pool-status"],
                   help="Action to perform")
    p.add_argument("--cvm-type", choices=["snp", "tdx"],
                   help="CVM type (required for start-cvm)")
    p.add_argument("--cvm-id",
                   help="Backend cvm_id (required for stop-cvm and mark-cvm)")
    p.add_argument("--cvm-mode", choices=["in-service", "in-update"],
                   help="Target mode (required for mark-cvm)")
    p.add_argument("--private-key-out", default="service_owner_private_key.pem",
                   help="Output path for generated private key")
    p.add_argument("--public-key-out",  default="service_owner_public_key.pub",
                   help="Output path for generated public key")
    return p.parse_args()


def main():
    args = parse_args()

    # ── generate-owner-key is local, no network needed ────────────────────────
    if args.action == "generate-owner-key":
        generate_owner_keypair(args.private_key_out, args.public_key_out)
        return 0

    # ── all other actions need a client ───────────────────────────────────────
    client = FrontendAdminClient(
        base_url=args.url,
        private_key_path=args.key,
        verify_tls=args.verify_tls,
    )

    if args.action == "pool-status":
        result = client.pool_status()
        print(json.dumps(result, indent=2))

    elif args.action == "start-cvm":
        if not args.cvm_type:
            print("ERROR: --cvm-type required for start-cvm")
            return 1
        if not args.key:
            print("ERROR: --key required for start-cvm (privileged operation)")
            return 1
        print(f"Provisioning {args.cvm_type.upper()} CVM… (this may take several minutes)")
        result = client.start_cvm(args.cvm_type)
        if result.get("success"):
            print(f"CVM provisioned:")
            print(f"  cvm_id     = {result.get('cvm_id', '?')}")
            print(f"  ip_address = {result.get('ip_address', '?')}")
            print()
            print("The backend will register with the frontend automatically.")
            print("Use --action pool-status to check when it appears as 'in-service'.")
        else:
            print(f"ERROR: {result.get('error', 'Unknown error')}")
            return 1

    elif args.action == "stop-cvm":
        if not args.cvm_id:
            print("ERROR: --cvm-id required for stop-cvm")
            return 1
        if not args.key:
            print("ERROR: --key required for stop-cvm (privileged operation)")
            return 1
        result = client.stop_cvm(args.cvm_id)
        if result.get("success"):
            print(f"CVM {args.cvm_id[:16]}… stopped and Azure resources deleted.")
        else:
            print(f"ERROR: {result.get('error', 'Unknown error')}")
            return 1

    elif args.action == "mark-cvm":
        if not args.cvm_id:
            print("ERROR: --cvm-id required for mark-cvm")
            return 1
        if not args.cvm_mode:
            print("ERROR: --cvm-mode required for mark-cvm")
            return 1
        if not args.key:
            print("ERROR: --key required for mark-cvm (privileged operation)")
            return 1
        result = client.mark_cvm(args.cvm_id, args.cvm_mode)
        if result.get("success"):
            print(f"CVM {args.cvm_id[:16]}… → {args.cvm_mode}")
        else:
            print(f"ERROR: {result.get('error', 'Unknown error')}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
