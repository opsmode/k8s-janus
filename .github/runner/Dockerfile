FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# ── System deps ───────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git openssh-client gnupg \
      python3 python3-pip \
      jq unzip \
    && rm -rf /var/lib/apt/lists/*

# ── Docker CLI + buildx (arch-aware) ─────────────────────────────────────────
RUN ARCH=$(dpkg --print-architecture) \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
       | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] \
       https://download.docker.com/linux/ubuntu noble stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-buildx-plugin \
    && rm -rf /var/lib/apt/lists/*

# ── Helm ─────────────────────────────────────────────────────────────────────
RUN curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# ── yq (arch-aware) ──────────────────────────────────────────────────────────
ARG YQ_VERSION=v4.44.6
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && curl -fsSL \
       "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${ARCH}" \
       -o /usr/local/bin/yq \
    && chmod +x /usr/local/bin/yq

# ── GitHub known hosts (baked in — no ssh-keyscan at runtime) ────────────────
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh \
    && ssh-keyscan -t ed25519,rsa github.com >> /root/.ssh/known_hosts 2>/dev/null \
    && chmod 600 /root/.ssh/known_hosts

# ── Python deps (separate layer — only rebuilds when requirements change) ─────
COPY controller/requirements.txt /tmp/controller-requirements.txt
COPY webui/requirements.txt      /tmp/webui-requirements.txt
RUN pip3 install --break-system-packages --root-user-action=ignore --quiet -r /tmp/controller-requirements.txt && \
    pip3 install --break-system-packages --root-user-action=ignore --quiet -r /tmp/webui-requirements.txt && \
    pip3 install --break-system-packages --root-user-action=ignore --quiet flake8

# ── GitHub Actions runner binary (arch-aware) ─────────────────────────────────
ARG RUNNER_VERSION=2.323.0
RUN ARCH=$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/') \
    && mkdir -p /actions-runner \
    && curl -fsSL \
       "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${ARCH}-${RUNNER_VERSION}.tar.gz" \
       | tar -xz -C /actions-runner

WORKDIR /actions-runner

# entrypoint: configure + start runner (env vars injected at container start)
COPY .github/runner/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
