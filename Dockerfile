# Flavor-aware Dockerfile for the YggdraSIM suite.
#
# Build examples:
#   docker build -t yggdrasim:clean .
#   docker build --build-arg YGGDRASIM_FLAVOR=full -t yggdrasim:full .
#
# The ``clean`` flavor installs only cross-platform dependencies and skips
# the HIL bridge extras. The ``full`` flavor additionally installs the
# Linux-only ``pyudev`` package and expects the host to provide
# ``osmo-remsim-client-st2`` and a SIMtrace2 board when HIL operation is
# actually needed. See guides/INSTALL_CLEAN.md, guides/INSTALL_FULL.md and
# guides/SIMTRACE2_CARDEM_GUIDE.md for operator-facing onboarding.
#
# Multi-stage build rationale:
# * The ``build`` stage carries the full toolchain (gcc, swig, pcsclite
#   headers) because ``pyscard`` / ``pyudev`` need a C extension build.
# * The ``runtime`` stage starts from the same python:3.11-slim base but
#   skips the -dev packages and the compiler, producing a noticeably
#   smaller final image that only carries the runtime shared libs and the
#   installed site-packages.
# * Source is copied AFTER ``pyproject.toml``/``requirements.txt`` so an
#   unrelated source edit does not invalidate the dependency layer.

ARG YGGDRASIM_FLAVOR=clean

# -----------------------------------------------------------------------------
# Stage 1 — build: compile wheels and populate a self-contained virtualenv
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS build

ARG YGGDRASIM_FLAVOR
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    YGGDRASIM_FLAVOR=${YGGDRASIM_FLAVOR}

WORKDIR /opt/YggdraSIM

# Toolchain + pcsc headers needed by pyscard's C extension. ``libudev1`` is
# pulled in for pyudev only; the runtime stage keeps a copy so ``full``
# images can dlopen it at import time. ``git`` is required because the
# pySim dependency is fetched as ``pip install 'pySim @ git+...'`` and pip
# shells out to the system git binary to clone the upstream tree.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        g++ \
        gcc \
        git \
        libpcsclite-dev \
        libudev1 \
        libudev-dev \
        pkg-config \
        swig \
 && rm -rf /var/lib/apt/lists/*

# Dependency-first copy so edits to Python source do NOT invalidate the
# layer that installs pip packages. That layer is the slowest one in the
# whole build.
COPY pyproject.toml requirements.txt ./

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip setuptools wheel

ENV PATH="/opt/venv/bin:${PATH}"

# Install declared dependencies into the venv WITHOUT the project source.
# We re-install the project in editable mode in the next step after the
# source is copied in; the dependency layer is the expensive one and this
# ordering lets Docker cache it whenever only source changes. The SAIP
# surface (pySim) is fetched from its GitHub mirror here rather than in
# the editable install below so it lives in the dependency layer and
# does not re-download on every source edit.
RUN if [ "${YGGDRASIM_FLAVOR}" = "full" ]; then \
        pip install -r requirements.txt pyudev \
            'pySim @ git+https://github.com/osmocom/pysim.git'; \
    else \
        pip install -r requirements.txt \
            'pySim @ git+https://github.com/osmocom/pysim.git'; \
    fi

COPY . /opt/YggdraSIM

RUN if [ "${YGGDRASIM_FLAVOR}" = "full" ]; then \
        pip install --no-deps -e '.[full]'; \
    else \
        pip install --no-deps -e '.[saip]'; \
    fi

# -----------------------------------------------------------------------------
# Stage 2 — runtime: slim image carrying only shared libs + venv + source
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ARG YGGDRASIM_FLAVOR
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    YGGDRASIM_RUNTIME_ROOT=/opt/YggdraSIM-data \
    YGGDRASIM_FLAVOR=${YGGDRASIM_FLAVOR} \
    PATH="/opt/venv/bin:${PATH}"

# Runtime shared libs only. ``libpcsclite1`` is the .so that pyscard
# dlopen's; the -dev package + compilers stay in the build stage.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        gpg \
        libpcsclite1 \
        libudev1 \
        pcsc-tools \
        pcscd \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/YggdraSIM

COPY --from=build /opt/venv /opt/venv
COPY --from=build /opt/YggdraSIM /opt/YggdraSIM

# Drop to a non-root uid inside the image. Host-side USB / pcscd access
# usually needs ``--user root`` or a privileged mount anyway, but the
# default command surfaces for documentation / CI smoke runs should not
# run as root. Operators who need raw pcscd access can override with
# ``docker run --user 0`` at invocation time.
RUN useradd --create-home --uid 1000 yggdrasim \
 && mkdir -p /opt/YggdraSIM-data \
 && chown -R yggdrasim:yggdrasim /opt/YggdraSIM /opt/YggdraSIM-data

USER yggdrasim

CMD ["yggdrasim-scp11"]
