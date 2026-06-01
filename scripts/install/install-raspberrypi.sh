#!/usr/bin/env bash
# YggdraSIM installer for Raspberry Pi OS 64-bit (arm64).
#
# Both clean and full flavors are supported on Raspberry Pi. The full
# flavor bundles the HIL bridge; on-Pi usage still requires the SIMtrace2
# toolchain (osmo-remsim-client-st2 + dfu-util); see the guides folder
# for the exact setup.
#
# Examples:
#   scripts/install/install-raspberrypi.sh                # latest clean release
#   scripts/install/install-raspberrypi.sh --flavor full  # HIL-capable release
#   scripts/install/install-raspberrypi.sh --mode source  # editable source install

set -e

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
# shellcheck source=scripts/install/_common.sh
. "${SCRIPT_DIR}/_common.sh"

yg_parse_posix_args "$@"

YG_HOST_OS="$(yg_detect_os)"
YG_HOST_ARCH="$(yg_detect_arch)"

if [ "${YG_HOST_OS}" != "linux" ]; then
    yg_die "this installer is for Raspberry Pi OS (Linux) only (detected: ${YG_HOST_OS})"
fi
if [ "${YG_HOST_ARCH}" != "arm64" ] && [ "${YG_HOST_ARCH}" != "armv7" ]; then
    yg_warn "expected arm64 / armv7 host; continuing anyway (detected: ${YG_HOST_ARCH})"
fi
if [ "${YG_HOST_ARCH}" = "armv7" ]; then
    yg_warn "no pre-built release asset exists for armv7; --mode source is recommended"
fi

yg_validate_flavor_for_host "${YG_FLAVOR}" "${YG_HOST_OS}"


install_rpi_prereqs() {
    if [ "${YG_SKIP_DEPS}" = "1" ]; then
        yg_emit "skipping apt package install (--no-deps)"
        return 0
    fi
    local common_packages="python3 python3-pip python3-venv libpcsclite1 pcscd gpg"
    local build_packages="libpcsclite-dev swig pkg-config build-essential"
    local hil_packages="libudev-dev dfu-util usbutils"

    case "${YG_MODE}:${YG_FLAVOR}" in
        release:clean)
            yg_apt_install ${common_packages}
            ;;
        release:full)
            yg_apt_install ${common_packages} ${hil_packages}
            yg_apt_install osmo-remsim-client || \
                yg_warn "osmo-remsim-client not in default apt sources; see guides/SIMTRACE2_CARDEM_GUIDE.md"
            ;;
        source:clean)
            yg_apt_install ${common_packages} ${build_packages}
            ;;
        source:full)
            yg_apt_install ${common_packages} ${build_packages} ${hil_packages}
            yg_apt_install osmo-remsim-client || \
                yg_warn "osmo-remsim-client not in default apt sources; see guides/SIMTRACE2_CARDEM_GUIDE.md"
            ;;
    esac
}


install_from_release() {
    local asset
    asset="$(yg_asset_name "linux" "${YG_HOST_ARCH}" "${YG_FLAVOR}")"
    local asset_tmp
    asset_tmp="$(mktemp -t "${asset}.XXXXXX")"
    local extract_dir
    extract_dir="$(mktemp -d -t "yggdrasim-extract.XXXXXX")"
    trap 'rm -rf "${asset_tmp}" "${extract_dir}"' EXIT

    local url
    url="$(yg_resolve_release_url "${YG_VERSION}" "${asset}")"
    yg_download_release_asset "${url}" "${asset_tmp}"
    local binary
    binary="$(yg_extract_release_zip "${asset_tmp}" "${extract_dir}")"
    yg_install_executable "${binary}" "${YG_INSTALL_DIR}" "yggdrasim"
    yg_emit "run 'yggdrasim --version' to verify"
}


install_from_source() {
    yg_source_install "${YG_REPO_ROOT}" "${YG_FLAVOR}" "${YG_VENV_DIR}"
    if [ -n "${YG_VENV_DIR}" ]; then
        yg_emit "activate later with: source \"${YG_VENV_DIR}/bin/activate\""
    fi
}


yg_emit "target host: raspberry-pi/${YG_HOST_ARCH}"
yg_emit "flavor=${YG_FLAVOR}, mode=${YG_MODE}, version=${YG_VERSION}"

install_rpi_prereqs

case "${YG_MODE}" in
    release) install_from_release ;;
    source)  install_from_source ;;
esac

if [ "${YG_FLAVOR}" = "full" ]; then
    yg_emit "next: flash SIMtrace2 cardem (guides/SIMTRACE2_CARDEM_GUIDE.md) before opening the HIL bridge"
fi
yg_emit "done"
