# Authoritative Trusted Worker Image for VerifyCI Candidate Execution (§15.10 Component A)
# Pinned by immutable OCI digest. Zero candidate build hooks.
FROM python:3.12-slim@sha256:d81827419f6a15233fb1e721d51a6fb236468758810793750eb01bf9b380f55c

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install git and runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/verifyci-worker

# Install pinned runtime dependencies
COPY docker/worker/requirements.lock /opt/verifyci-worker/requirements.lock
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.lock

# Copy trusted launcher
COPY docker/worker/launch_candidate.py /opt/verifyci-worker/launch_candidate.py
RUN chmod 0755 /opt/verifyci-worker/launch_candidate.py

# Switch to non-root unprivileged UID
USER 10001:10001

ENTRYPOINT ["python", "-I", "/opt/verifyci-worker/launch_candidate.py"]
