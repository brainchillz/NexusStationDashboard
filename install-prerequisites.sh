#!/bin/bash
#
# install-prerequisites.sh
#
# Installs every system package the Storage Management Dashboard needs, via
# apt-get. Run this as root BEFORE install.sh:
#
#     sudo ./install-prerequisites.sh
#     sudo ./install.sh
#
# install.sh also calls this script automatically, so the package list lives
# here in one place.
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

if ! command -v apt-get >/dev/null 2>&1; then
    error "apt-get not found. This installer targets Debian/Ubuntu systems."
    exit 1
fi

# Each package and the dashboard feature / binaries it provides:
PACKAGES=(
    python3            # Flask app runtime
    python3-venv       # virtualenv for the app's Python dependencies
    python3-pip        # pip, used inside the venv
    zfsutils-linux     # zpool, zfs        -> ZFS pools / datasets / snapshots
    targetcli-fb       # targetcli         -> iSCSI (LIO) targets
    nfs-kernel-server  # exportfs, nfsd    -> NFS exports
    nfs-common         # NFS client utilities
    samba              # smbd, smbpasswd, pdbedit, smbstatus, testparm -> SMB shares
    smbclient          # SMB client tools
    cifs-utils         # mount.cifs
    lsscsi             # lsscsi            -> SCSI/transport details on the Disks page
    smartmontools      # smartctl          -> SMART disk health on the Disks page
    gdisk              # sgdisk            -> clear partition tables (disk wipe)
    mdadm              # mdadm             -> stop/zero stale RAID metadata (disk wipe)
    lvm2               # pvs/vgs/lvs ...   -> LVM management
    xfsprogs           # mkfs.xfs          -> XFS for LVM + plain-disk format
    e2fsprogs          # mkfs.ext4         -> ext4 plain-disk format
    dosfstools         # mkfs.vfat         -> FAT32 plain-disk format (USB)
    exfatprogs         # mkfs.exfat        -> exFAT plain-disk format (USB)
    parted             # partprobe         -> re-read partition table after wipe
    ledmon             # ledctl            -> enclosure locate LED (disk locate)
    sg3-utils          # SCSI generic utilities
    iproute2           # ip               -> Network page
    openssl            # self-signed TLS cert generation / validation
    openssh-client     # ssh, ssh-keygen   -> ZFS replication to a remote host
    acl                # POSIX ACL tooling
    curl               # health checks / convenience
)

export DEBIAN_FRONTEND=noninteractive

info "Updating package lists..."
apt-get update -qq

info "Installing ${#PACKAGES[@]} prerequisite packages..."
apt-get install -y "${PACKAGES[@]}"

info "All prerequisites installed."

if [ -z "${SD_SKIP_NEXT_STEP:-}" ]; then
    echo ""
    echo "Next step:"
    echo "  sudo ./install.sh"
fi
