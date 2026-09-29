# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

FROM ubuntu:22.04

# Build from the repository root:
#   docker build -f janus/frontend/Dockerfile -t janus-frontend:latest .

ENV app_user=janus

RUN groupadd -o -g 1000 -r ${app_user} && \
    useradd -d /home/${app_user} -u 1000 -m -r -g ${app_user} ${app_user}

RUN apt-get update --fix-missing && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 python3-pip python-is-python3 \
        curl openssl procps && \
    apt-get clean

RUN python3 -m pip install --upgrade pip --quiet

ADD janus/frontend/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install -r /tmp/requirements.txt --quiet

# ── directory structure ───────────────────────────────────────────────────────
RUN mkdir -p /home/${app_user}/janus/frontend/sealed \
             /home/${app_user}/janus/common \
             /home/${app_user}/tmp \
             /home/${app_user}/pebble/test/certs \
             /home/${app_user}/pebble/ca_certs

# ── application code ──────────────────────────────────────────────────────────
ADD janus/frontend/*.py        /home/${app_user}/janus/frontend/
ADD janus/__init__.py          /home/${app_user}/janus/__init__.py
ADD janus/common/*.py          /home/${app_user}/janus/common/

# ── Pebble CA ─────────────────────────────────────────────────────────────────
ADD ca/pebble/pebble                               /home/${app_user}/pebble/pebble
ADD ca/pebble/test/config/pebble-config.json       /home/${app_user}/pebble/pebble-config.json
ADD ca/pebble/test/certs/generate_pebble_cert.sh   /home/${app_user}/pebble/test/certs/generate_pebble_cert.sh
ADD ca/pebble/ca_certs/*.pem                       /home/${app_user}/pebble/ca_certs/

RUN chmod +x /home/${app_user}/pebble/pebble && \
    cd /home/${app_user}/pebble/test/certs && \
    chmod +x generate_pebble_cert.sh && \
    ./generate_pebble_cert.sh

# ── startup script ────────────────────────────────────────────────────────────
ADD janus/frontend/start_with_pebble.sh /home/${app_user}/start_with_pebble.sh
RUN chmod +x /home/${app_user}/start_with_pebble.sh

RUN chown ${app_user}:${app_user} -R /home/${app_user}
USER ${app_user}

WORKDIR /home/${app_user}

ENV APP_HOME=/home/${app_user}
ENV SERVER_TYPE=direct
ENV FRONTEND_PORT=6037

EXPOSE 6037

CMD ["/home/janus/start_with_pebble.sh"]
