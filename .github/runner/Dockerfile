FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# ── System deps ───────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git openssh-client gnupg \
      python3 python3-pip \
      jq unzip \
    && rm -rf /var/lib/apt/lists/*

# ── Docker CLI + buildx ───────────────────────────────────────────────────────
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] \
       https://download.docker.com/linux/ubuntu noble stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-buildx-plugin \
    && rm -rf /var/lib/apt/lists/*

# ── Helm ─────────────────────────────────────────────────────────────────────
RUN curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# ── yq ───────────────────────────────────────────────────────────────────────
ARG YQ_VERSION=v4.44.6
RUN curl -fsSL \
      "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64" \
      -o /usr/local/bin/yq \
    && chmod +x /usr/local/bin/yq

# ── GitHub known hosts (baked in — no ssh-keyscan at runtime) ────────────────
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh \
    && ssh-keyscan -t ed25519,rsa github.com >> /root/.ssh/known_hosts 2>/dev/null \
    && chmod 600 /root/.ssh/known_hosts

# ── Python deps (separate layer — only rebuilds when requirements change) ─────
COPY controller/requirements.txt /tmp/controller-requirements.txt
COPY webui/requirements.txt      /tmp/webui-requirements.txt
RUN pip3 install --break-system-packages --quiet \
      -r /tmp/controller-requirements.txt \
      -r /tmp/webui-requirements.txt \
      flake8

# ── GitHub Actions runner binary ──────────────────────────────────────────────
ARG RUNNER_VERSION=2.323.0
RUN mkdir -p /actions-runner \
    && curl -fsSL \
       "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" \
       | tar -xz -C /actions-runner

WORKDIR /actions-runner

# entrypoint: configure + start runner (env vars injected at container start)
COPY .github/runner/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
