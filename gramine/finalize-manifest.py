#!/usr/bin/python3

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import os
import sys
import site
import pkg_resources
import time

from dotenv import load_dotenv
from graminelibos import Manifest

def main():
    load_dotenv()
    # Need to add user and potential pyenv pip installation sites to PYTHONPATH 
    # for the gramine SGX environment to find installed modules
    installation_sites = set()
    # Get user site-packages directory
    user_site_packages = site.getusersitepackages()
    installation_sites.add(user_site_packages)

    # Get pyenv environment
    venv_path = os.getenv('VIRTUAL_ENV')
    if venv_path:
        site_packages_dirs = []
        #site_packages_path = os.path.join(venv_path, 'lib', 'python' + sys.version[:4], 'site-packages')
        for root, dirs, files in os.walk(venv_path):
            for dir in dirs:
                site_packages_dirs.append(os.path.join(root, dir))
        installation_sites.update(site_packages_dirs)

    py_package_dirs = set()

#    py_packages_path = "/usr/lib/python3.10"
#    if os.path.exists(py_packages_path):
        #for root, dirs, files in os.walk(py_packages_path):
        #    for dir in dirs:
        #        py_package_dirs.add(os.path.join(root, dir))
#        py_package_dirs.add(py_packages_path)

    dist_packages_path = "/usr/local/lib/python3.10/dist-packages"
    if os.path.exists(dist_packages_path):
        #for root, dirs, files in os.walk(dist_packages_path):
        #    for dir in dirs:
        #        py_package_dirs.add(os.path.join(root, dir))
        py_package_dirs.add(dist_packages_path)

    dist_packages_path2 = "/usr/lib/python3.10/dist-packages"
    if os.path.exists(dist_packages_path2):
        #for root, dirs, files in os.walk(dist_packages_path2):
        #    for dir in dirs:
        #        py_package_dirs.add(os.path.join(root, dir))
        py_package_dirs.add(dist_packages_path2)
    
    installation_sites.update(py_package_dirs)

    # Add parent of app_home to Python path for module resolution (home.<user>.module.name pattern)
    # This allows "home.<user>.module.name" to resolve to "/home/janus/module/name.py"
    app_home = os.getenv('app_home', '/home/janus')
    python_module_root = os.path.dirname(app_home)  # Get "/home" from "/home/janus"
    if python_module_root and python_module_root != '/':
        installation_sites.add(python_module_root)

    # Add module-specific directories for C extensions and local modules
    module_name = os.getenv('module_name')
    if module_name == 'ratls':
        # Add RATLS server directory to find ratls_bridge.so C extension
        installation_sites.add(f"{app_home}/ratls/server")
    elif module_name == 'admin':
        # Add the (legacy) AdminEnclave server directory for any C extensions
        installation_sites.add(f"{app_home}/archived/legacy/admin_enclave")

    installation_dirs = list(installation_sites)

    manifest_vars = {
        'python_path': installation_dirs,
        'log_level': os.getenv('log_level'),
        'arch_libdir': os.getenv('arch_libdir'),
        'entrypoint': os.getenv('entrypoint'),
        'work_dir': os.getenv('work_dir'),
        'app_home': os.getenv('app_home'),
        'ra_type': os.getenv('ra_type'),
        'ra_client_spid': os.getenv('ra_client_spid'),
        'ra_client_linkable': os.getenv('ra_client_linkable'),
        'module_name': os.getenv('module_name'),
        'loader_args': os.getenv('loader_args').split(',')
    }
    infile = os.getenv('GRAMINE_TEMPLATE')
    outfile = os.getenv('MANIFEST_FILE')
    with open(infile, 'r') as file:
        template = file.read()
    manifest = Manifest.from_template(template, manifest_vars)
    with open(outfile, 'wb') as file:
        manifest.dump(file)

if __name__ == '__main__':
    main()
