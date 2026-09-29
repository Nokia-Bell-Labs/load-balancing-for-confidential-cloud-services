# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
Setup script for RATLS Python Bridge C extension.

Builds the ratls_bridge module that connects Python to RATLS's patched OpenSSL.
"""

from setuptools import setup, Extension
import os

# Path to RATLS installation (custom OpenSSL 1.1.1m)
RATLS_BASE = os.path.join(os.path.dirname(__file__), '..', '..', 'ratls-external')
RATLS_INSTALL = os.path.join(RATLS_BASE, 'install')

ratls_bridge = Extension(
    'ratls_bridge',
    sources=['ratls_python_bridge.c'],
    include_dirs=[
        os.path.join(RATLS_INSTALL, 'include'),
    ],
    library_dirs=[
        os.path.join(RATLS_INSTALL, 'lib'),
    ],
    libraries=['ssl', 'crypto'],
    runtime_library_dirs=[
        os.path.join(RATLS_INSTALL, 'lib'),
    ],
    extra_compile_args=[
        '-Wall',
        '-Wextra',
        '-O2',
    ],
)

setup(
    name='ratls-bridge',
    version='1.0.0',
    description='Python bridge to RATLS OpenSSL for per-connection attestation',
    author='Duet Project',
    ext_modules=[ratls_bridge],
    python_requires='>=3.8',
)
