# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
BackendProvisioner — CVM provisioning for the Janus frontend server

Adapts the predecessor project's start_cvm() to provision AMD SEV-SNP / Intel TDX
Confidential VMs and deploy the Janus back-end server onto them.

Provisioning flow
─────────────────
1.  Load Azure config from environment variables
2.  Generate an ephemeral RSA keypair for SSH access (discarded after setup)
3.  Call AzureClient.provision_resources() to create the VM, NIC, IP, NSG
4.  Add an HTTPS inbound NSG rule (port 8443) alongside the existing SSH rule
5.  Wait 30 s for Azure to apply firewall rules (same as the external provisioning library)
6.  SSH into the CVM and run install_backend.sh:
      - installs Python 3 + pip + required packages
      - copies backend_server.py and its dependencies
      - starts the backend server (nohup, pointing at the frontend URL)
7.  The backend server bootstraps itself:
      - generates its own keypair
      - reads SNP/TDX attestation quote
      - POSTs CSR + quote to frontend /register_backend
      - receives signed cert and starts HTTPS service
8.  Store the CVM object in the caller-supplied CVMs dict
9.  Delete Azure resources on stop_cvm()

Environment variables (same as the external provisioning library):
    SUBSCRIPTION_ID, MANAGED_IDENTITY_CLIENT_ID, LOCATION,
    RESOURCE_GROUP_NAME, VNET_NAME, SUBNET_NAME, PREFIX, VM_IMAGE
"""

import os
import random
import sys
import time
import logging
from typing import Optional

from dotenv import load_dotenv

# ── import the external provisioning library's AzureClient + ConfidentialVM (optional, not shipped) ─────────────────────────────
_HERE     = os.path.dirname(os.path.abspath(__file__))
_REPO     = os.path.join(_HERE, '..', '..')  # repo root
_TEE_DUET = os.path.join(_REPO, 'cvm-provisioner')  # optional external library (parent of AdminEnclave package); absent in the artifact
sys.path.insert(0, _TEE_DUET)

try:
    from AdminEnclave.azure_client import AzureClient
    from AdminEnclave.cvm import ConfidentialVM
    from AdminEnclave.utils.crypto import generate_ephemeral_rsa_key_for_cvm
    _AZURE_AVAILABLE = True
except ImportError as e:
    logging.getLogger(__name__).debug(f"provisioning library import failed: {e}")
    _AZURE_AVAILABLE = False

# ── path to backend code that will be deployed to the CVM ────────────────────
_BACKEND_DIR  = os.path.join(_HERE, '..', 'backend')
_INSTALL_SH   = os.path.join(_BACKEND_DIR, 'install_backend.sh')

# ── Azure VM images ───────────────────────────────────────────────────────────
_VM_IMAGE_DEFAULT = (
    "canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest"
)
_VM_SIZES = {"snp": "Standard_DC2ads_v5", "tdx": "Standard_DC2eds_v5"}


def _load_azure_config(env_path: Optional[str] = None) -> Optional[dict]:
    """Load Azure configuration from environment / .env file."""
    if env_path:
        load_dotenv(dotenv_path=env_path)

    cfg = {
        "subscription_id":            os.getenv("SUBSCRIPTION_ID"),
        "managed_identity_client_id": os.getenv("MANAGED_IDENTITY_CLIENT_ID"),
        "location":                   os.getenv("LOCATION"),
        "resource_group_name":        os.getenv("RESOURCE_GROUP_NAME"),
        "vnet_name":                  os.getenv("VNET_NAME"),
        "subnet_name":                os.getenv("SUBNET_NAME"),
        "prefix":                     os.getenv("PREFIX"),
    }
    if any(v is None for v in cfg.values()):
        return None
    return cfg


def _extend_config(cfg: dict, cvm_type: str) -> dict:
    """Add CVM-type-specific fields to config (mirrors the provisioning library's _extend_config)."""
    cfg["vm_image"]        = os.getenv("VM_IMAGE", _VM_IMAGE_DEFAULT)
    cfg["vm_image_tokens"] = cfg["vm_image"].split(":")
    cfg["username"]        = os.environ.get("CVM_ADMIN_USER", "janus")
    cfg["cvm_type"]        = cvm_type
    cfg["vm_size"]         = _VM_SIZES[cvm_type]
    cfg["vm_name"]         = f"{cfg['prefix']}-janus-{cvm_type}-{random.randint(1000, 9999)}"
    vm                     = cfg["vm_name"]
    cfg["nsg_name"]        = f"{vm}-nsg"
    cfg["nic_name"]        = f"{vm}-nic"
    cfg["ip_name"]         = f"{vm}-ip"
    cfg["ip_config_name"]  = f"{vm}-ip-config"
    return cfg


class BackendProvisioner:
    """
    Provisions back-end CVMs and deploys the Janus backend server.

    One BackendProvisioner is shared by the frontend server; it keeps a reference
    to the caller-supplied CVMs dict so stop_cvm() can delete Azure resources.

    Two ID spaces:
      - SSH-key ID  (ConfidentialVM.get_cvm_id()): SHA256 of the ephemeral SSH
                    public key, used as the primary key in self._cvms at provision
                    time.
      - TLS-key ID  (key_store cvm_id): SHA256 of the backend's TLS public key,
                    only known after the backend calls /register_backend.

    link_backend_to_cvm() maps a TLS-key ID to its CVM object so that
    delete_cvm() works when called with the TLS-key ID from the key store.
    """

    def __init__(
        self,
        frontend_url: str,
        frontend_https_port: int,
        cvms: dict,
        frontend_server=None,
        logger: Optional[logging.Logger] = None,
    ):
        self._frontend_url        = frontend_url
        self._frontend_https_port = frontend_https_port
        self._cvms          = cvms
        self._cvms_by_ip: dict = {}   # ip_address → CVM (for cross-referencing)
        self._frontend_server = frontend_server  # for registering nonces
        self._logger        = logger or logging.getLogger(__name__)

        if not _AZURE_AVAILABLE:
            self._logger.warning(
                "provisioning library (AzureClient) not importable — "
                "CVM provisioning will be unavailable"
            )

    # ── public API ────────────────────────────────────────────────────────────

    def provision_cvm(
        self,
        cvm_type: str,
        env_path: Optional[str] = None,
    ) -> dict:
        """
        Provision a new CVM and deploy the Janus backend server.

        Returns:
            dict with keys: success, cvm_id, ip_address, error
        """
        if not _AZURE_AVAILABLE:
            return {"success": False, "error": "Azure SDK / provisioning library not available"}

        assert cvm_type in ("snp", "tdx"), f"Unknown cvm_type: {cvm_type}"

        # 1. Load Azure config
        cfg = _load_azure_config(env_path)
        if not cfg:
            return {"success": False, "error": "Azure config not set (missing env vars)"}
        cfg = _extend_config(cfg, cvm_type)

        try:
            # 2. Ephemeral SSH keypair
            ssh_pub_key, ssh_priv_key = generate_ephemeral_rsa_key_for_cvm()

            # 3. Generate attestation nonce
            nonce = os.urandom(32).hex()
            self._logger.info(f"Generated attestation nonce: {nonce[:16]}…")

            # 4. Provision Azure resources
            self._logger.info(f"Provisioning {cvm_type} CVM '{cfg['vm_name']}'…")
            azure = AzureClient(cfg, self._logger)
            cvm   = azure.provision_resources(ssh_pub_key)
            cvm.set_private_key(ssh_priv_key)
            cvm.set_config(cfg)

            # 5. Open HTTPS port on the NSG
            self._add_https_nsg_rule(azure, cfg)

            # 6. Wait for Azure networking
            self._logger.info("Waiting 30 s for Azure to apply firewall rules…")
            time.sleep(30)

            # 7. SSH: install deps + deploy backend (with nonce)
            cvm.connect()
            self._deploy_backend(cvm, cfg, nonce=nonce)
            cvm.disconnect()

            # 8. Register nonce with frontend server
            ip = cvm._ip_address
            if self._frontend_server is not None:
                self._frontend_server.register_nonce(nonce, ip, cvm_type)

            # 9. Store CVM
            cvm_id = cvm.get_cvm_id()
            self._cvms[cvm_id] = cvm
            self._cvms_by_ip[ip] = cvm
            self._logger.info(
                f"CVM provisioned: id={cvm_id[:16]}… ip={ip}"
            )
            return {"success": True, "cvm_id": cvm_id, "ip_address": ip}

        except Exception as exc:
            self._logger.error(f"CVM provisioning failed: {exc}")
            return {"success": False, "error": str(exc)}

    def delete_cvm(self, cvm_id: str) -> dict:
        """Delete a CVM's Azure resources and remove it from the CVMs dict."""
        if cvm_id not in self._cvms:
            return {"success": False, "error": f"Unknown cvm_id: {cvm_id}"}

        cvm = self._cvms[cvm_id]
        cfg = cvm.get_config()
        try:
            azure = AzureClient(cfg, self._logger)
            azure.delete_resources()
            del self._cvms[cvm_id]
            self._logger.info(f"CVM {cvm_id[:16]}… deleted")
            return {"success": True}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def link_backend_to_cvm(self, ip_address: str, tls_cvm_id: str):
        """
        Cross-reference a TLS-key-based cvm_id to the CVM provisioned at ip_address.

        Called by the frontend when a CVM's backend registers via /register_backend.
        After this call, delete_cvm(tls_cvm_id) will work correctly.
        """
        cvm = self._cvms_by_ip.get(ip_address)
        if cvm:
            self._cvms[tls_cvm_id] = cvm
            self._logger.info(
                f"Linked backend {tls_cvm_id[:16]}… ↔ CVM at {ip_address}"
            )
        else:
            self._logger.debug(
                f"No provisioned CVM found at {ip_address} — "
                "backend may not be running on an Azure CVM"
            )

    # ── internal helpers ──────────────────────────────────────────────────────

    def _add_https_nsg_rule(self, azure: "AzureClient", cfg: dict):
        """Add inbound NSG rule for HTTPS (port 8443)."""
        try:
            azure._network_client.security_rules.begin_create_or_update(
                cfg["resource_group_name"],
                cfg["nsg_name"],
                security_rule_name="allow-https-backend",
                security_rule_parameters={
                    "properties": {
                        "access": "Allow",
                        "destinationAddressPrefix": "*",
                        "destinationPortRange": "8443",
                        "direction": "Inbound",
                        "priority": 310,
                        "protocol": "Tcp",
                        "sourceAddressPrefix": "Internet",
                        "sourcePortRange": "*",
                    }
                },
            ).result()
            self._logger.info("NSG rule allow-https-backend added (port 8443)")
        except Exception as exc:
            self._logger.warning(f"Could not add HTTPS NSG rule: {exc}")

    def _deploy_backend(self, cvm: "ConfidentialVM", cfg: dict, nonce: str = ""):
        """
        Copy backend code to the CVM and start the backend server.

        Files copied:
          install_backend.sh  – installs Python deps, starts backend_server.py
          backend_server.py   – the backend HTTPS server
        """
        username = cfg["username"]

        # Copy install script
        if os.path.isfile(_INSTALL_SH):
            cvm.copy_file(_BACKEND_DIR + os.sep, "install_backend.sh")
        else:
            self._logger.warning(
                f"install_backend.sh not found at {_INSTALL_SH} — skipping copy"
            )

        # Copy backend_server.py
        backend_py = os.path.join(_BACKEND_DIR, "backend_server.py")
        if os.path.isfile(backend_py):
            cvm.copy_file(_BACKEND_DIR + os.sep, "backend_server.py")

        # Copy static directory contents
        static_dir = os.path.join(_BACKEND_DIR, "static")
        if os.path.isdir(static_dir):
            for fname in os.listdir(static_dir):
                src = os.path.join(static_dir, fname)
                if os.path.isfile(src):
                    cvm.copy_file(static_dir + os.sep, fname)

        # Run install script
        commands = [
            "chmod +x install_backend.sh",
            f"FRONTEND_URL={self._frontend_url} "
            f"FRONTEND_HTTPS_PORT={self._frontend_https_port} "
            f"CVM_TYPE={cfg['cvm_type']} "
            f"NONCE={nonce} "
            f"./install_backend.sh",
        ]
        for cmd in commands:
            cvm.execute_command(cmd)
            time.sleep(3)
