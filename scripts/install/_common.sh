#!/usr/bin/env bash
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

: "${YGGDRASIM_REPO:=hampushellsberg-dev/YggdraSIM}"
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

yg_download_release_asset() {
    # $1 = asset URL, $2 = destination path
    yg_need_cmd curl
    local url="${1}"
    local dest="${2}"
    yg_emit "downloading ${url}"
    curl --fail --location --max-redirs 5 --proto '=https' --tlsv1.2 --silent --show-error --output "${dest}" "${url}"
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
    # $1 = repo root, $2 = flavor, $3 = venv path ("" to skip venv creation)
    local repo_root="${1}"
    local flavor="${2}"
    local venv_dir="${3}"
    yg_need_cmd "${YGGDRASIM_PYTHON}"
    if [ -n "${venv_dir}" ]; then
        if [ ! -d "${venv_dir}" ]; then
            yg_emit "creating virtualenv at ${venv_dir}"
            "${YGGDRASIM_PYTHON}" -m venv "${venv_dir}"
        fi
        # shellcheck source=/dev/null
        . "${venv_dir}/bin/activate"
    fi
    (
        cd "${repo_root}"
        python -m pip install --upgrade pip
        case "${flavor}" in
            clean) python -m pip install -e '.[saip]' ;;
            full)  python -m pip install -e '.[full]' ;;
            *)     yg_die "internal: unexpected flavor ${flavor}" ;;
        esac
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
