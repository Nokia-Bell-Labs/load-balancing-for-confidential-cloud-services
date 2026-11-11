# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# OHTTP+KMS baseline — KMS base image: the Janus frontend image plus the
# baseline package.  Build from the repository root:
#   docker build -f baselines/ohttp/Dockerfile -t janus/ohttp_kms .
# then graminize/sign like the frontend:
#   make -C gramine signed-image MODULE=ohttp_kms
FROM janus/frontend:latest

ENV app_user=janus
USER root
RUN python3 -m pip install --quiet pyhpke==0.6.5
ADD baselines/ohttp/ohttp /home/${app_user}/ohttp
ADD baselines/ohttp/start_kms_with_pebble.sh /home/${app_user}/start_kms_with_pebble.sh
RUN chmod +x /home/${app_user}/start_kms_with_pebble.sh \
    && chown ${app_user}:${app_user} -R /home/${app_user}/ohttp
USER ${app_user}
WORKDIR /home/${app_user}
ENV FRONTEND_PORT=6038
EXPOSE 6038
CMD ["/home/janus/start_kms_with_pebble.sh"]
