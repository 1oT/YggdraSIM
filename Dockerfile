# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

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
# * Source is copied AFTER ``pyproject.toml``/``uv.lock`` so an
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

# Toolchain + PC/SC headers needed by pyscard's C extension. udev packages
# are installed only for the full flavor; a clean image must not inherit HIL
# libraries merely because both flavors share this Dockerfile.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        g++ \
        gcc \
        git \
        libpcsclite-dev \
        pkg-config \
        swig \
 && if [ "${YGGDRASIM_FLAVOR}" = "full" ]; then \
        apt-get install -y --no-install-recommends libudev1 libudev-dev; \
    fi \
 && rm -rf /var/lib/apt/lists/*

# Dependency-first copy so edits to Python source do NOT invalidate the
# layer that installs pip packages. That layer is the slowest one in the
# whole build.
COPY pyproject.toml uv.lock README.md LICENSE ./

RUN python -m venv /opt/venv

ENV PATH="/opt/venv/bin:${PATH}"

# Install the exact dependency graph from the hash-bearing ``uv.lock``
# without the project source first, preserving Docker layer reuse.
# ``full`` adds only runtime HIL/server dependencies; build and test tools
# remain outside both production images.
RUN /usr/local/bin/python -m pip install 'uv==0.5.9' \
 && if [ "${YGGDRASIM_FLAVOR}" = "full" ]; then \
        UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --no-install-project --extra full; \
    else \
        UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --no-install-project; \
    fi

COPY . /opt/YggdraSIM

RUN python scripts/release/source_boundary.py \
 && if [ "${YGGDRASIM_FLAVOR}" = "full" ]; then \
        UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --no-editable --extra full; \
    else \
        UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --no-editable; \
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
        pcsc-tools \
        pcscd \
 && if [ "${YGGDRASIM_FLAVOR}" = "full" ]; then \
        apt-get install -y --no-install-recommends libudev1; \
    fi \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/YggdraSIM

COPY --from=build /opt/venv /opt/venv

# Drop to a non-root uid inside the image. Host-side USB / pcscd access
# usually needs ``--user root`` or a privileged mount anyway, but the
# default command surfaces for documentation / CI smoke runs should not
# run as root. Operators who need raw pcscd access can override with
# ``docker run --user 0`` at invocation time.
RUN useradd --create-home --uid 1000 yggdrasim \
 && mkdir -p /opt/YggdraSIM /opt/YggdraSIM-data \
 && chown -R yggdrasim:yggdrasim /opt/YggdraSIM /opt/YggdraSIM-data

USER yggdrasim

CMD ["yggdrasim-scp11"]
