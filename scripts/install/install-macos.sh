#!/usr/bin/env bash
# YggdraSIM installer for macOS (x86_64 or arm64).
#
# Only the clean flavor is published for macOS. The HIL bridge depends
# on Linux-specific tooling (udev + osmo-remsim-client-st2) and cannot
# be installed on macOS.
#
# Examples:
#   scripts/install/install-macos.sh                 # latest clean release
#   scripts/install/install-macos.sh --mode source   # editable source install

set -e

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
# shellcheck source=scripts/install/_common.sh
. "${SCRIPT_DIR}/_common.sh"

yg_parse_posix_args "$@"

if [ "${YG_FLAVOR}" = "full" ]; then
    yg_die "flavor 'full' is Linux-only; macOS only ships the 'clean' bundle"
fi

YG_HOST_OS="$(yg_detect_os)"
YG_HOST_ARCH="$(yg_detect_arch)"

if [ "${YG_HOST_OS}" != "macos" ]; then
    yg_die "this installer is for macOS only (detected: ${YG_HOST_OS})"
fi
if [ "${YG_HOST_ARCH}" = "unknown" ]; then
    yg_die "unsupported CPU architecture: $(uname -m)"
fi

yg_validate_flavor_for_host "${YG_FLAVOR}" "${YG_HOST_OS}"


install_macos_prereqs() {
    if [ "${YG_SKIP_DEPS}" = "1" ]; then
        yg_emit "skipping Homebrew package install (--no-deps)"
        return 0
    fi
    case "${YG_MODE}" in
        release)
            yg_brew_install swig || true
            ;;
        source)
            yg_brew_install python@3.11 swig pkg-config || true
            ;;
    esac
    yg_emit "PC/SC on macOS uses the built-in CryptoTokenKit; no daemon install required"
}


install_from_release() {
    local asset
    asset="$(yg_asset_name "macos" "${YG_HOST_ARCH}" "${YG_FLAVOR}")"
    local asset_tmp
    asset_tmp="$(mktemp -t "${asset}.XXXXXX")"
    trap 'rm -f "${asset_tmp}"' EXIT

    local url
    url="$(yg_resolve_release_url "${YG_VERSION}" "${asset}")"
    yg_download_release_asset "${url}" "${asset_tmp}"
    yg_install_executable "${asset_tmp}" "${YG_INSTALL_DIR}" "yggdrasim"
    yg_emit "if Gatekeeper complains, right-click the binary once to approve it"
    yg_emit "run 'yggdrasim --version' to verify"
}


install_from_source() {
    yg_source_install "${YG_REPO_ROOT}" "${YG_FLAVOR}" "${YG_VENV_DIR}"
    if [ -n "${YG_VENV_DIR}" ]; then
        yg_emit "activate later with: source \"${YG_VENV_DIR}/bin/activate\""
    fi
}


yg_emit "target host: macos/${YG_HOST_ARCH}"
yg_emit "flavor=${YG_FLAVOR}, mode=${YG_MODE}, version=${YG_VERSION}"

install_macos_prereqs

case "${YG_MODE}" in
    release) install_from_release ;;
    source)  install_from_source ;;
esac

yg_emit "done"
