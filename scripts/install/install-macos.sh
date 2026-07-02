#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# YggdraSIM installer for macOS.
#
# Only the clean flavor is published for macOS, and prebuilt release
# bundles are currently published for Apple Silicon arm64. Intel macOS
# hosts remain supported through ``--mode source``. The HIL bridge depends
# on Linux-specific tooling (udev + osmo-remsim-client-st2) and cannot
# be installed on macOS.
#
# Examples:
#   scripts/install/install-macos.sh --with-gui      # latest clean CLI + GUI release
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
    if [ "${YG_HOST_ARCH}" = "x86_64" ]; then
        yg_die "macOS Intel release bundles are not published; use --mode source on this host"
    fi
    local asset
    asset="$(yg_asset_name "macos" "${YG_HOST_ARCH}" "${YG_FLAVOR}")"
    local asset_tmp
    asset_tmp="$(mktemp -t "${asset}.XXXXXX")"
    local gui_asset=""
    local gui_asset_tmp=""
    if [ "${YG_WITH_GUI}" = "1" ]; then
        gui_asset="$(yg_gui_asset_name "macos" "${YG_HOST_ARCH}" "${YG_FLAVOR}")"
        gui_asset_tmp="$(mktemp -t "${gui_asset}.XXXXXX")"
    fi
    trap "rm -f '${asset_tmp}' '${gui_asset_tmp}'" EXIT

    local url
    url="$(yg_resolve_release_url "${YG_VERSION}" "${asset}")"
    yg_download_release_asset "${url}" "${asset_tmp}"
    yg_install_executable "${asset_tmp}" "${YG_INSTALL_DIR}" "yggdrasim"
    if [ "${YG_WITH_GUI}" = "1" ]; then
        local gui_url
        gui_url="$(yg_resolve_release_url "${YG_VERSION}" "${gui_asset}")"
        yg_download_release_asset "${gui_url}" "${gui_asset_tmp}"
        yg_install_executable "${gui_asset_tmp}" "${YG_INSTALL_DIR}" "yggdrasim-gui"
    fi
    yg_emit "if Gatekeeper complains, right-click the binary once to approve it"
    yg_emit "run 'yggdrasim --version' to verify"
    if [ "${YG_WITH_GUI}" = "1" ]; then
        yg_emit "run 'yggdrasim-gui' to launch the desktop GUI"
    fi
}


install_from_source() {
    yg_source_install "${YG_REPO_ROOT}" "${YG_FLAVOR}" "${YG_VENV_DIR}" "${YG_WITH_GUI}"
    if [ -n "${YG_VENV_DIR}" ]; then
        yg_emit "activate later with: source \"${YG_VENV_DIR}/bin/activate\""
    fi
}


yg_emit "target host: macos/${YG_HOST_ARCH}"
yg_emit "flavor=${YG_FLAVOR}, mode=${YG_MODE}, version=${YG_VERSION}, with_gui=${YG_WITH_GUI}"

install_macos_prereqs

case "${YG_MODE}" in
    release) install_from_release ;;
    source)  install_from_source ;;
esac

yg_emit "done"
