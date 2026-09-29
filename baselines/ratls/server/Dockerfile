# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Dockerfile for RATLS-enabled Admin Enclave
# Includes custom Python 3.10.12 built with RATLS OpenSSL 1.1.1m

FROM ubuntu:22.04 AS ratls-builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies for Python and RATLS
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    wget \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    libffi-dev \
    liblzma-dev \
    libncurses5-dev \
    libgdbm-dev \
    libnss3-dev \
    tk-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-built RATLS OpenSSL 1.1.1m and Python 3.10.12
WORKDIR /build
COPY ratls-external/install /build/ratls/install
COPY python-ratls /opt/python-ratls

# Main application image
FROM ubuntu:22.04

ENV app_user=janus

RUN groupadd -o -g 1000 -r ${app_user} && useradd -d /home/${app_user} -u 1000 -m -r -g ${app_user} ${app_user}

RUN apt-get update --fix-missing \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python-is-python3 \
    curl \
    procps \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy RATLS OpenSSL and Python from builder
COPY --from=ratls-builder /build/ratls/install /home/${app_user}/ratls/install
COPY --from=ratls-builder /opt/python-ratls /home/${app_user}/python-ratls

# Set LD_LIBRARY_PATH for RATLS OpenSSL (needed before using python-ratls)
ENV LD_LIBRARY_PATH=/home/${app_user}/ratls/install/lib:$LD_LIBRARY_PATH

# Install Python packages for both system and RATLS Python
RUN /usr/bin/python3 -m pip install --upgrade pip
ADD ratls/server/requirements.txt /tmp/
RUN /usr/bin/python3 -m pip install -r /tmp/requirements.txt
RUN /home/${app_user}/python-ratls/bin/python3 -m pip install -r /tmp/requirements.txt

# Create directory structure
RUN mkdir -p /home/${app_user}/ratls/server/sealed /home/${app_user}/ratls/server/utils /home/${app_user}/ratls/server/static /home/${app_user}/ratls/server/certs
RUN mkdir -p /home/${app_user}/ctls/server/utils
RUN mkdir -p /home/${app_user}/common
RUN mkdir -p /home/${app_user}/tmp
RUN mkdir -p /home/${app_user}/pebble

# Add RA-TLS server files
ADD ratls/server/*.py /home/${app_user}/ratls/server/
ADD ratls/server/*.so /home/${app_user}/ratls/server/
ADD ratls/server/*.sh /home/${app_user}/ratls/server/

# Add common files (needed for attestation verification and ACME)
ADD common/*.py /home/${app_user}/common/

# Add cTLS server files (cert_generator needed only if using SGX-embedded certificates)
ADD ctls/server/cert_generator.py /home/${app_user}/ctls/server/
ADD ctls/server/utils/*.py /home/${app_user}/ctls/server/utils/

# Add Pebble CA with persistent certificates
ADD pebble/pebble /home/${app_user}/pebble/pebble
ADD pebble/test/config/pebble-config.json /home/${app_user}/pebble/pebble-config.json
ADD pebble/test/certs /home/${app_user}/pebble/test/certs
ADD pebble/ca_certs/*.pem /home/${app_user}/pebble/ca_certs/

# Add startup scripts (RA-TLS has its own startup scripts)
RUN chmod +x /home/${app_user}/ratls/server/*.sh

# Set PATH for RATLS Python
ENV PATH=/home/${app_user}/python-ratls/bin:$PATH

RUN rm -rf /home/${app_user}/.cache
RUN chown ${app_user}:${app_user} -R /home/${app_user}
USER ${app_user}

WORKDIR /home/${app_user}

# Set APP_HOME environment variable for runtime
ENV APP_HOME=/home/${app_user}

# Default: Start RA-TLS server
# Run: python-ratls/bin/python3 ratls/server/ratls_http_server.py
CMD ["/bin/bash", "-c", "${APP_HOME}/python-ratls/bin/python3 ${APP_HOME}/ratls/server/ratls_http_server.py"]
