# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

FROM ubuntu:22.04

# Build from the repository root:
#   docker build -f janus/backend/Dockerfile -t janus-backend:latest .

ENV app_user=janus

RUN groupadd -o -g 1000 -r ${app_user} && \
    useradd -d /home/${app_user} -u 1000 -m -r -g ${app_user} ${app_user}

RUN apt-get update --fix-missing && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 python3-pip python-is-python3 \
        curl procps libstdc++6 && \
    apt-get clean

RUN python3 -m pip install --upgrade pip --quiet

ADD janus/backend/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install -r /tmp/requirements.txt --quiet

# ── directory structure ───────────────────────────────────────────────────────
RUN mkdir -p /home/${app_user}/janus/backend/sealed \
             /home/${app_user}/janus/backend/static \
             /home/${app_user}/janus/common \
             /home/${app_user}/tmp

# ── application code ──────────────────────────────────────────────────────────
ADD janus/backend/backend_server.py   /home/${app_user}/janus/backend/backend_server.py
ADD janus/backend/__init__.py         /home/${app_user}/janus/backend/__init__.py
ADD janus/backend/static/             /home/${app_user}/janus/backend/static/
ADD janus/__init__.py                 /home/${app_user}/janus/__init__.py
ADD janus/common/*.py                 /home/${app_user}/janus/common/

# ── dc_proxy binary (pre-built on host using BoringSSL) ──────────────────────
ADD janus/backend/dc_proxy/dc_proxy /home/${app_user}/dc_proxy
RUN chmod +x /home/${app_user}/dc_proxy

# ── startup script ────────────────────────────────────────────────────────────
ADD janus/backend/start_backend.sh /home/${app_user}/start_backend.sh
RUN chmod +x /home/${app_user}/start_backend.sh

RUN chown ${app_user}:${app_user} -R /home/${app_user}
USER ${app_user}

WORKDIR /home/${app_user}

ENV APP_HOME=/home/${app_user}
ENV FRONTEND_URL=https://frontend:6037
ENV FRONTEND_CA_CERT_PATH=insecure
ENV CVM_TYPE=snp
ENV BACKEND_PORT=8443

EXPOSE 8443

CMD ["/home/janus/start_backend.sh"]
