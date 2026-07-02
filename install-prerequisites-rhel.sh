#!/bin/bash
#
# install-prerequisites-rhel.sh
#
# RHEL / Rocky / AlmaLinux 9 & 10 counterpart of install-prerequisites.sh.
# Installs every system package the Nexus Dashboard needs via dnf, enabling the
# CRB and EPEL repositories first, then best-effort installs ZFS from the
# OpenZFS repo. Run this as root BEFORE install-rhel.sh:
#
#     sudo ./install-prerequisites-rhel.sh
#     sudo ./install-rhel.sh
#
# install-rhel.sh also calls this script automatically, so the package list
# lives here in one place (mirroring the Debian/Ubuntu split).
#
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [ "$(id -u)" -ne 0 ]; then
    error "Please run as root (e.g. sudo $0)"
    exit 1
fi

if ! command -v dnf >/dev/null 2>&1; then
    error "dnf not found. This installer targets RHEL/Rocky/AlmaLinux 9 & 10."
    error "For Debian/Ubuntu use install-prerequisites.sh instead."
    exit 1
fi

# Identify the EL release (el9 / el10) for the OpenZFS repo URL.
. /etc/os-release
EL_DIST="$(rpm --eval '%{dist}' | tr -d '.')"   # e.g. el9, el10
info "Detected ${PRETTY_NAME:-$ID $VERSION_ID} (${EL_DIST})"

# ── Repositories ──────────────────────────────────────────────────────
# CRB (CodeReady Builder / PowerTools) + EPEL provide several tools (lsscsi,
# exfatprogs, ledmon on some releases). dnf-plugins-core gives config-manager.
info "Enabling CRB + EPEL repositories..."
dnf install -y dnf-plugins-core >/dev/null
# CRB is named 'crb' on EL9/10 (was 'powertools' on EL8). Enable whichever exists.
dnf config-manager --set-enabled crb 2>/dev/null \
    || dnf config-manager --set-enabled powertools 2>/dev/null \
    || warn "Could not enable CRB/PowerTools (continuing — most packages are in base/EPEL)."
dnf install -y epel-release >/dev/null \
    || warn "epel-release not installable; some tools (lsscsi/exfatprogs/ledmon) may be missing."

# ── Package list (RHEL/Rocky names) ───────────────────────────────────
# Mirrors install-prerequisites.sh; see that file for the per-package rationale.
PACKAGES=(
    python3                  # Flask app runtime (venv is bundled)
    python3-pip              # pip inside the venv
    targetcli                # iSCSI (LIO) targets
    python3-rtslib           # rtslib backing targetcli (saveconfig)
    nfs-utils                # exportfs, nfsd, nfsdclnts -> NFS exports
    samba                    # smbd/smbpasswd/pdbedit/smbstatus/testparm -> SMB
    samba-client             # smbclient
    cifs-utils               # mount.cifs
    lsscsi                   # SCSI/transport details on the Disks page (EPEL)
    smartmontools            # smartctl -> SMART health
    gdisk                    # sgdisk -> clear partition tables (wipe/format)
    mdadm                    # MD RAID + stop/zero stale metadata on wipe
    lvm2                     # pvs/vgs/lvs ... -> LVM management
    xfsprogs                 # mkfs.xfs
    e2fsprogs                # mkfs.ext4
    dosfstools               # mkfs.vfat -> FAT32 (USB)
    exfatprogs               # mkfs.exfat -> exFAT (USB) (EPEL)
    parted                   # partprobe -> re-read partition table
    ledmon                   # ledctl -> enclosure locate LED
    sg3_utils                # SCSI generic utilities
    iproute                  # ip -> Network page
    openssl                  # self-signed TLS cert generation / validation
    openssh-clients          # ssh, ssh-keygen -> ZFS replication
    acl                      # POSIX ACL tooling
    curl                     # health checks / convenience
    policycoreutils-python-utils  # semanage/audit2allow for SELinux tuning
)

info "Installing ${#PACKAGES[@]} prerequisite packages..."
# EL9 dnf has no portable --skip-unavailable, and one unresolvable name aborts a
# whole transaction. Try the fast batch first; if it fails, fall back to a
# per-package install so a single missing name can't block everything. Verify
# and warn per-package at the end either way.
if ! dnf install -y "${PACKAGES[@]}"; then
    warn "Batch install failed (likely one unavailable name) — retrying per package..."
    for p in "${PACKAGES[@]}"; do
        rpm -q "$p" >/dev/null 2>&1 || dnf install -y "$p" >/dev/null 2>&1 || true
    done
fi

MISSING=()
for p in "${PACKAGES[@]}"; do
    rpm -q "$p" >/dev/null 2>&1 || MISSING+=("$p")
done
if [ "${#MISSING[@]}" -gt 0 ]; then
    warn "These packages could not be installed (feature may be unavailable): ${MISSING[*]}"
fi

# ── ZFS from the OpenZFS repo (best-effort) ───────────────────────────
# Red Hat never ships ZFS (CDDL/GPL). Install the OpenZFS kABI-tracking kmod,
# which (unlike DKMS) survives kernel updates without a rebuild. This can fail
# on a brand-new EL release before OpenZFS publishes a matching repo (e.g. EL10
# at the time of writing) or under Secure Boot — fail loudly, never silently.
install_zfs() {
    if command -v zpool >/dev/null 2>&1 && modprobe zfs 2>/dev/null; then
        info "ZFS already present and loadable."
        echo zfs > /etc/modules-load.d/zfs.conf 2>/dev/null || true
        return 0
    fi
    local rel_url="https://zfsonlinux.org/epel/zfs-release-2-3.${EL_DIST}.noarch.rpm"
    info "Installing OpenZFS repo: $rel_url"
    if ! dnf install -y "$rel_url" 2>/dev/null; then
        warn "OpenZFS release RPM not available for ${EL_DIST} (it may not be published yet)."
        warn "ZFS features will be unavailable. Disable the ZFS module in the dashboard,"
        warn "or install ZFS manually once OpenZFS supports ${EL_DIST}."
        return 1
    fi
    # Prefer the kABI-tracking kmod over DKMS: it ships a prebuilt module that
    # loads without kernel-devel or a per-kernel build, so it can't fall out of
    # sync with the running kernel (the common DKMS failure mode on EL).
    dnf config-manager --disable zfs        >/dev/null 2>&1 || true
    dnf config-manager --enable  zfs-kmod   >/dev/null 2>&1 || true
    if ! dnf install -y zfs 2>/dev/null; then
        warn "Failed to install the 'zfs' kmod package from the OpenZFS repo."
        return 1
    fi
    if modprobe zfs 2>/dev/null; then
        info "ZFS installed and the kernel module loaded."
        echo zfs > /etc/modules-load.d/zfs.conf 2>/dev/null || true
        return 0
    fi
    # The most common reason modprobe is refused on a UEFI host is Secure Boot
    # ("Key was rejected by service"): the OpenZFS module isn't signed by an
    # enrolled key. Detect it and give specific guidance.
    if command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null | grep -qi enabled; then
        warn "Secure Boot is ENABLED — the kernel refuses the unsigned OpenZFS module."
        warn "Fix one of these, then reboot:"
        warn "  (a) disable Secure Boot in the VM/host UEFI firmware (simplest), or"
        warn "  (b) MOK-enroll a key and sign the zfs/spl modules (keeps Secure Boot on)."
    else
        warn "ZFS installed but 'modprobe zfs' failed. A reboot may be required to"
        warn "pick up the module, or check 'dmesg | grep -i zfs' for the reason."
    fi
    return 1
}
install_zfs || warn "Continuing without ZFS (other features are unaffected)."

info "All prerequisites processed."

if [ -z "${SD_SKIP_NEXT_STEP:-}" ]; then
    echo ""
    echo "Next step:"
    echo "  sudo ./install-rhel.sh"
fi
