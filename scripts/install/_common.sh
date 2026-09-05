#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Shared helpers for the YggdraSIM POSIX install scripts.
#
# This file is sourced by install-linux.sh, install-macos.sh, and
# install-raspberrypi.sh. It intentionally avoids any hard dependency on
# bashisms that zsh/dash users would trip on beyond ``set -e`` and simple
# function definitions.

# ``set -e`` already fails on any unchecked command; ``-u`` catches typos
# in variable names before a half-run install tries to ``rm -rf`` the
# wrong directory, and ``-o pipefail`` propagates non-zero status through
# pipelines (e.g. ``curl | tar`` would otherwise silently succeed when
# curl returns a 404).
set -eu
set -o pipefail

# Helper so callers do not have to rewrite every apt-get invocation when
# running as root (e.g. Docker build, CI). When EUID=0 we do not need
# ``sudo``; when ``sudo`` is missing and we are non-root, fall back to a
# clear error rather than dying with the usual shell ``command not found``.
yg_sudo() {
    if [ "$(id -u)" = "0" ]; then
        "$@"
        return $?
    fi
    if command -v sudo >/dev/null 2>&1; then
        sudo "$@"
        return $?
    fi
    printf '[%s] error: sudo not available and not running as root; cannot execute: %s\n' \
        "${YGGDRASIM_SCRIPT_NAME:-install}" "$*" >&2
    return 2
}

# ---------------------------------------------------------------------------
# Default configuration knobs (callers may override via environment or CLI).
# ---------------------------------------------------------------------------

: "${YGGDRASIM_REPO:=1oT/YggdraSIM}"
: "${YGGDRASIM_RELEASE_BASE:=https://github.com/${YGGDRASIM_REPO}/releases}"
: "${YGGDRASIM_DEFAULT_INSTALL_DIR:=${HOME}/.local/bin}"
: "${YGGDRASIM_PYTHON:=python3}"

YGGDRASIM_SCRIPT_NAME="${YGGDRASIM_SCRIPT_NAME:-$(basename "${0}")}"


# ---------------------------------------------------------------------------
# Terminal helpers.
# ---------------------------------------------------------------------------

yg_emit() {
    printf '[%s] %s\n' "${YGGDRASIM_SCRIPT_NAME}" "$*"
}

yg_warn() {
    printf '[%s] warning: %s\n' "${YGGDRASIM_SCRIPT_NAME}" "$*" >&2
}

yg_die() {
    printf '[%s] error: %s\n' "${YGGDRASIM_SCRIPT_NAME}" "$*" >&2
    exit 2
}

yg_need_cmd() {
    command -v "${1}" >/dev/null 2>&1 || yg_die "required command not found: ${1}"
}


# ---------------------------------------------------------------------------
# Host detection.
# ---------------------------------------------------------------------------

yg_detect_os() {
    # Canonical labels used by release assets and by the flavor module.
    case "$(uname -s)" in
        Linux*)   printf 'linux' ;;
        Darwin*)  printf 'macos' ;;
        *)        printf 'unknown' ;;
    esac
}

yg_detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   printf 'x86_64' ;;
        aarch64|arm64)  printf 'arm64' ;;
        armv7l)         printf 'armv7' ;;
        *)              printf 'unknown' ;;
    esac
}


# ---------------------------------------------------------------------------
# Flavor / host compatibility.
# ---------------------------------------------------------------------------

yg_validate_flavor_for_host() {
    local flavor="${1}"
    local host_os="${2}"
    case "${flavor}" in
        clean)
            return 0
            ;;
        full)
            if [ "${host_os}" != "linux" ]; then
                yg_die "flavor 'full' is Linux-only (detected host: ${host_os})"
            fi
            return 0
            ;;
        *)
            yg_die "unknown flavor '${flavor}' (supported: clean, full)"
            ;;
    esac
}

yg_validate_release_arch() {
    # Fail before any package-manager or filesystem mutation when the release
    # matrix does not publish a binary for this host.
    local host_os="${1}"
    local host_arch="${2}"
    case "${host_os}:${host_arch}" in
        linux:x86_64|linux:arm64|macos:arm64)
            return 0
            ;;
        *)
            yg_die "no pre-built release is published for ${host_os}/${host_arch}; use --mode source on a supported Python host"
            ;;
    esac
}


# ---------------------------------------------------------------------------
# Package-manager bootstrapping.
# ---------------------------------------------------------------------------

yg_apt_install() {
    local packages="$*"
    if [ -z "${packages}" ]; then
        return 0
    fi
    if command -v apt-get >/dev/null 2>&1; then
        yg_emit "installing apt packages: ${packages}"
        yg_sudo apt-get update
        # ``env DEBIAN_FRONTEND=...`` survives the ``sudo`` environment scrub
        # because we launch ``env`` as the root child; plain inline
        # ``DEBIAN_FRONTEND=... sudo apt-get`` drops the value on the caller
        # side. The explicit ``env`` invocation keeps dpkg non-interactive
        # on containers without needing ``sudo -E`` on every site.
        yg_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ${packages}
        return 0
    fi
    yg_warn "apt-get not available; skipping package install (${packages})"
}

yg_install_remsim_client() {
    if command -v osmo-remsim-client-st2 >/dev/null 2>&1; then
        return 0
    fi
    # Osmocom repositories publish the SIMtrace2 client under this exact
    # package name. Some distributions bundle it in the broader client
    # package, so retain that as a compatibility fallback and verify the
    # executable instead of assuming either package layout.
    if ! yg_apt_install osmo-remsim-client-st2; then
        yg_warn "osmo-remsim-client-st2 package unavailable; trying the distribution compatibility package"
        yg_apt_install osmo-remsim-client || true
    fi
    if ! command -v osmo-remsim-client-st2 >/dev/null 2>&1; then
        yg_die "required HIL executable 'osmo-remsim-client-st2' is still unavailable; configure the Osmocom package repository or install it manually, then re-run (or use --no-deps only when dependencies are managed separately; see guides/SIMTRACE2_CARDEM_GUIDE.md)"
    fi
}

yg_brew_install() {
    local packages="$*"
    if [ -z "${packages}" ]; then
        return 0
    fi
    if command -v brew >/dev/null 2>&1; then
        yg_emit "installing Homebrew packages: ${packages}"
        brew install ${packages} || true
        return 0
    fi
    yg_warn "Homebrew not detected; install from https://brew.sh and re-run"
}


# ---------------------------------------------------------------------------
# Release artifact handling.
# ---------------------------------------------------------------------------

yg_asset_name() {
    # $1 = os (linux|macos), $2 = arch (x86_64|arm64), $3 = flavor (clean|full)
    printf 'yggdrasim-%s-%s-%s' "${1}" "${2}" "${3}"
}

yg_gui_asset_name() {
    # $1 = os (linux|macos), $2 = arch (x86_64|arm64), $3 = flavor (clean|full)
    printf 'yggdrasim-gui-%s-%s-%s' "${1}" "${2}" "${3}"
}

yg_download_release_asset() {
    # $1 = asset URL, $2 = destination path
    yg_need_cmd curl
    local url="${1}"
    local dest="${2}"
    yg_emit "downloading ${url}"
    curl --fail --location --max-redirs 5 --proto '=https' --tlsv1.2 --silent --show-error --output "${dest}" "${url}"
}

yg_sha256_file() {
    local path="${1}"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${path}" | awk '{print $1}'
        return 0
    fi
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${path}" | awk '{print $1}'
        return 0
    fi
    yg_warn "neither sha256sum nor shasum is available"
    return 2
}

yg_verify_release_checksum() {
    # $1 = SHA256SUMS path, $2 = release asset name, $3 = downloaded asset
    local manifest="${1}"
    local asset_name="${2}"
    local asset_path="${3}"
    local expected
    expected="$(awk -v wanted="${asset_name}" '
        NF >= 2 {
            name = $2
            sub(/^\\*/, "", name)
            if (name == wanted) {
                print $1
                exit
            }
        }
    ' "${manifest}")"
    if [ "${#expected}" -ne 64 ]; then
        yg_warn "SHA256SUMS has no valid entry for ${asset_name}"
        return 2
    fi
    case "${expected}" in
        *[!0-9A-Fa-f]*)
            yg_warn "SHA256SUMS contains an invalid digest for ${asset_name}"
            return 2
            ;;
    esac
    local actual
    actual="$(yg_sha256_file "${asset_path}")" || return $?
    expected="$(printf '%s' "${expected}" | tr '[:upper:]' '[:lower:]')"
    actual="$(printf '%s' "${actual}" | tr '[:upper:]' '[:lower:]')"
    if [ "${actual}" != "${expected}" ]; then
        yg_warn "checksum mismatch for ${asset_name}"
        return 2
    fi
    yg_emit "verified SHA-256 for ${asset_name}"
}

yg_download_verified_release_asset() {
    # $1 = release tag/latest, $2 = asset name, $3 = destination
    local version="${1}"
    local asset_name="${2}"
    local destination="${3}"
    local manifest_tmp
    manifest_tmp="$(mktemp -t yggdrasim-SHA256SUMS.XXXXXX)"
    local manifest_url
    manifest_url="$(yg_resolve_release_url "${version}" "SHA256SUMS")"
    if ! yg_download_release_asset "${manifest_url}" "${manifest_tmp}"; then
        rm -f "${manifest_tmp}"
        return 2
    fi
    local asset_url
    asset_url="$(yg_resolve_release_url "${version}" "${asset_name}")"
    if ! yg_download_release_asset "${asset_url}" "${destination}"; then
        rm -f "${manifest_tmp}"
        return 2
    fi
    if ! yg_verify_release_checksum "${manifest_tmp}" "${asset_name}" "${destination}"; then
        rm -f "${manifest_tmp}" "${destination}"
        return 2
    fi
    rm -f "${manifest_tmp}"
}

yg_install_executable() {
    # $1 = source path, $2 = target directory, $3 = target filename (without .exe)
    local source="${1}"
    local target_dir="${2}"
    local target_name="${3}"
    mkdir -p "${target_dir}"
    install -m 0755 "${source}" "${target_dir}/${target_name}"
    yg_emit "installed ${target_dir}/${target_name}"
    case ":${PATH}:" in
        *":${target_dir}:"*) : ;;
        *)
            yg_warn "${target_dir} is not on your PATH; add it to ~/.profile / ~/.zshrc"
            ;;
    esac
}


# ---------------------------------------------------------------------------
# Source (editable) install.
# ---------------------------------------------------------------------------

yg_source_install() {
    # $1 = repo root, $2 = flavor, $3 = venv path ("" to skip venv
    # creation), $4 = with GUI (0|1), $5 = expose system site packages
    # to the venv (0|1; required for Debian's ARM PyQt5 binding).
    local repo_root="${1}"
    local flavor="${2}"
    local venv_dir="${3}"
    local with_gui="${4:-0}"
    local system_site_packages="${5:-0}"
    yg_need_cmd "${YGGDRASIM_PYTHON}"
    if [ -n "${venv_dir}" ]; then
        if [ ! -d "${venv_dir}" ]; then
            yg_emit "creating virtualenv at ${venv_dir}"
            if [ "${system_site_packages}" = "1" ]; then
                "${YGGDRASIM_PYTHON}" -m venv --system-site-packages "${venv_dir}"
            else
                "${YGGDRASIM_PYTHON}" -m venv "${venv_dir}"
            fi
        elif [ "${system_site_packages}" = "1" ]; then
            if ! grep -Eiq \
                '^include-system-site-packages[[:space:]]*=[[:space:]]*true$' \
                "${venv_dir}/pyvenv.cfg"; then
                yg_die "ARM GUI source installs require a system-site-packages virtualenv; choose a fresh --venv path or remove ${venv_dir}"
            fi
        fi
        # shellcheck source=/dev/null
        . "${venv_dir}/bin/activate"
    fi
    if [ "${system_site_packages}" = "1" ]; then
        if ! python -c "from PyQt5 import QtWebEngineWidgets" >/dev/null 2>&1; then
            yg_die "ARM GUI source install cannot import Debian PyQt5 QtWebEngineWidgets"
        fi
    fi
    (
        cd "${repo_root}"
        python -m pip install --upgrade pip
        if [ "${with_gui}" = "1" ]; then
            case "${flavor}" in
                clean) python -m pip install -e '.[saip,gui]' ;;
                full)  python -m pip install -e '.[full,gui]' ;;
                *)     yg_die "internal: unexpected flavor ${flavor}" ;;
            esac
        else
            case "${flavor}" in
                clean) python -m pip install -e '.[saip]' ;;
                full)  python -m pip install -e '.[full]' ;;
                *)     yg_die "internal: unexpected flavor ${flavor}" ;;
            esac
        fi
    )
    yg_emit "editable install complete (flavor=${flavor})"
}


# ---------------------------------------------------------------------------
# CLI plumbing shared by the POSIX install scripts.
# ---------------------------------------------------------------------------

yg_print_posix_usage() {
    cat <<USAGE
Usage: ${YGGDRASIM_SCRIPT_NAME} [options]

Options:
  --flavor clean|full         Which flavor to install (default: clean)
  --mode release|source       Choose between GitHub release binary or
                              editable source install (default: release)
  --version <tag>             Release tag to download (default: latest)
  --install-dir <path>        Binary install directory for release mode
                              (default: ${YGGDRASIM_DEFAULT_INSTALL_DIR})
  --repo-root <path>          Repository root for source mode
                              (default: current working directory)
  --venv <path>               Virtualenv path for source mode
                              (default: <repo-root>/.venv)
  --no-deps                   Skip host package-manager prerequisites
  --with-gui                  Also install GUI extras / GUI release binary
  --no-venv                   Source mode: install into the current Python
                              environment instead of creating a venv
  -h, --help                  Show this help and exit

Environment:
  YGGDRASIM_REPO              Override upstream repo (owner/name)
  YGGDRASIM_PYTHON            Python interpreter used for source installs
USAGE
}

yg_parse_posix_args() {
    YG_FLAVOR="clean"
    YG_MODE="release"
    YG_VERSION="latest"
    YG_INSTALL_DIR="${YGGDRASIM_DEFAULT_INSTALL_DIR}"
    YG_REPO_ROOT=""
    YG_VENV_DIR=""
    YG_SKIP_DEPS="0"
    YG_SKIP_VENV="0"
    YG_WITH_GUI="0"

    while [ "${#}" -gt 0 ]; do
        case "${1}" in
            --flavor)
                YG_FLAVOR="${2:-}"
                shift 2
                ;;
            --mode)
                YG_MODE="${2:-}"
                shift 2
                ;;
            --version)
                YG_VERSION="${2:-}"
                shift 2
                ;;
            --install-dir)
                YG_INSTALL_DIR="${2:-}"
                shift 2
                ;;
            --repo-root)
                YG_REPO_ROOT="${2:-}"
                shift 2
                ;;
            --venv)
                YG_VENV_DIR="${2:-}"
                shift 2
                ;;
            --no-deps)
                YG_SKIP_DEPS="1"
                shift 1
                ;;
            --with-gui)
                YG_WITH_GUI="1"
                shift 1
                ;;
            --no-venv)
                YG_SKIP_VENV="1"
                shift 1
                ;;
            -h|--help)
                yg_print_posix_usage
                exit 0
                ;;
            *)
                yg_print_posix_usage
                yg_die "unknown argument: ${1}"
                ;;
        esac
    done

    if [ "${YG_MODE}" != "release" ] && [ "${YG_MODE}" != "source" ]; then
        yg_die "--mode must be 'release' or 'source' (got '${YG_MODE}')"
    fi
    if [ -z "${YG_REPO_ROOT}" ]; then
        YG_REPO_ROOT="$(pwd)"
    fi
    if [ -z "${YG_VENV_DIR}" ] && [ "${YG_SKIP_VENV}" = "0" ]; then
        YG_VENV_DIR="${YG_REPO_ROOT}/.venv"
    fi
    if [ "${YG_SKIP_VENV}" = "1" ]; then
        YG_VENV_DIR=""
    fi
}


yg_resolve_release_url() {
    # $1 = version tag ("latest" or explicit tag)
    # $2 = asset name (without extension)
    # Writes the download URL to stdout.
    local version="${1}"
    local asset_name="${2}"
    if [ "${version}" = "latest" ]; then
        printf '%s/latest/download/%s' "${YGGDRASIM_RELEASE_BASE}" "${asset_name}"
    else
        printf '%s/download/%s/%s' "${YGGDRASIM_RELEASE_BASE}" "${version}" "${asset_name}"
    fi
}
