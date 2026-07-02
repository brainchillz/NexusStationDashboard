#!/bin/bash
set -e

# Nexus / Storage Management Dashboard installer for RHEL / Rocky / AlmaLinux
# 9 & 10. Counterpart of install.sh (Debian/Ubuntu). It installs all module
# software (via install-prerequisites-rhel.sh), the dashboard itself, the
# root-owned privilege-boundary helpers, the systemd unit + timers, sudoers
# (RHEL binary/config paths), and firewalld rules.
#
# The Network module is netplan-based and Ubuntu-only; on RHEL only the
# hostname/domain part works and the netplan helper is intentionally not
# installed. ZFS comes from the OpenZFS repo (best-effort; see the prereq
# script) and may be unavailable on a brand-new EL release.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD_DIR="/opt/storage-dashboard"
DASHBOARD_USER="dashboard"
DASHBOARD_PORT="${DASHBOARD_PORT:-8443}"

echo "=== Nexus Dashboard Installer (RHEL / Rocky / AlmaLinux 9 & 10) ==="
echo ""

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then
    error "Please run as root or with sudo"
    exit 1
fi

if ! command -v dnf >/dev/null 2>&1; then
    error "dnf not found. This installer targets RHEL/Rocky/AlmaLinux."
    error "For Debian/Ubuntu use install.sh instead."
    exit 1
fi

. /etc/os-release

# Service unit names differ from Debian: NFS is nfs-server, Samba is smb.
NFS_SERVICE="nfs-server"
SMB_SERVICE="smb"
ISCSI_SERVICE="target"

info "Installing prerequisite packages..."
if [ -f "$SCRIPT_DIR/install-prerequisites-rhel.sh" ]; then
    SD_SKIP_NEXT_STEP=1 bash "$SCRIPT_DIR/install-prerequisites-rhel.sh"
else
    error "install-prerequisites-rhel.sh not found next to install-rhel.sh."
    exit 1
fi

info "Creating dashboard user..."
if ! id -u $DASHBOARD_USER &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -M -d $DASHBOARD_DIR $DASHBOARD_USER
fi

info "Deploying application files to $DASHBOARD_DIR..."
mkdir -p "$DASHBOARD_DIR"
if [ "$SCRIPT_DIR" != "$DASHBOARD_DIR" ]; then
    cp -r "$SCRIPT_DIR/app.py" "$SCRIPT_DIR/templates" "$SCRIPT_DIR/static" "$DASHBOARD_DIR/"
    [ -f "$SCRIPT_DIR/requirements.txt" ] && cp "$SCRIPT_DIR/requirements.txt" "$DASHBOARD_DIR/"
else
    info "  (running from $DASHBOARD_DIR — files already in place)"
fi

info "Setting up Python virtual environment..."
python3 -m venv $DASHBOARD_DIR/venv
source $DASHBOARD_DIR/venv/bin/activate
if [ -f "$DASHBOARD_DIR/requirements.txt" ]; then
    pip install -q -r "$DASHBOARD_DIR/requirements.txt"
else
    pip install -q flask
fi
deactivate

info "Setting up sudoers permissions..."
SUDOERS_FILE="/etc/sudoers.d/storage-dashboard"
cat > $SUDOERS_FILE << 'SUDOERS'
# Storage Dashboard - passwordless sudo for the exact commands app.py runs.
# RHEL/Rocky paths (merged /usr). sudo matches the fully-resolved binary path.

# Service control & logs
dashboard ALL=(ALL) NOPASSWD: /usr/bin/systemctl
dashboard ALL=(ALL) NOPASSWD: /usr/bin/journalctl

# Disk / system inventory
dashboard ALL=(ALL) NOPASSWD: /usr/bin/lsblk
dashboard ALL=(ALL) NOPASSWD: /usr/bin/lsscsi
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/ip
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/smartctl
# Disk wipe (blank a free/stale disk). Eligibility is enforced in app.py.
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/mdadm
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/wipefs
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/sgdisk
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/partprobe
# Disk locate: enclosure LED + a root-owned read-only wrapper.
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/ledctl
dashboard ALL=(ALL) NOPASSWD: /usr/local/sbin/storage-dashboard-locate-read
dashboard ALL=(ALL) NOPASSWD: /usr/local/sbin/storage-dashboard-iscsi-sessions
# Snapshot browser / single-file restore (root-owned, self-confining helper).
dashboard ALL=(ALL) NOPASSWD: /usr/local/sbin/storage-dashboard-snap-fs
# Hostname (the netplan helper is Ubuntu-only and intentionally absent here).
dashboard ALL=(ALL) NOPASSWD: /usr/bin/hostnamectl
# Plain-disk mount: root-owned helper that mounts under /mnt|/media and edits
# its own block in /etc/fstab (always nofail). mount/umount/tee /etc/fstab are
# deliberately NOT granted directly.
dashboard ALL=(ALL) NOPASSWD: /usr/local/sbin/storage-dashboard-mount
# llama.cpp model download: root-owned helper that pulls a GGUF from Hugging Face
# into the models dir (re-validates repo/filename, confines output). Trust boundary.
dashboard ALL=(ALL) NOPASSWD: /usr/local/sbin/storage-dashboard-model-fetch

# LVM (read + manage; destructive ops are guarded in app.py)
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/pvs, /usr/sbin/vgs, /usr/sbin/lvs
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/pvcreate, /usr/sbin/pvremove, /usr/sbin/pvresize, /usr/sbin/pvmove
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/vgcreate, /usr/sbin/vgremove, /usr/sbin/vgextend, /usr/sbin/vgreduce
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/lvcreate, /usr/sbin/lvremove, /usr/sbin/lvextend, /usr/sbin/lvresize
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/mkfs.ext4, /usr/sbin/mkfs.xfs
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/mkfs.vfat, /usr/sbin/mkfs.exfat

# ZFS (from the OpenZFS repo)
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/zpool
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/zfs

# iSCSI (LIO / targetcli)
dashboard ALL=(ALL) NOPASSWD: /usr/bin/targetcli

# NFS
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/exportfs

# SMB / Samba
dashboard ALL=(ALL) NOPASSWD: /usr/bin/testparm
dashboard ALL=(ALL) NOPASSWD: /usr/bin/smbpasswd
dashboard ALL=(ALL) NOPASSWD: /usr/bin/smbstatus
dashboard ALL=(ALL) NOPASSWD: /usr/bin/pdbedit
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/useradd
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/groupadd
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/groupdel
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/usermod
dashboard ALL=(ALL) NOPASSWD: /usr/bin/gpasswd

# Config writers — restricted to the exact files/forms app.py invokes. Note the
# RHEL mdadm.conf path (/etc/mdadm.conf, not /etc/mdadm/mdadm.conf) and dracut
# (not update-initramfs).
dashboard ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/exports
dashboard ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/samba/smb.conf
dashboard ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/hosts
dashboard ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/mdadm.conf
dashboard ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/llama.conf
dashboard ALL=(ALL) NOPASSWD: /usr/bin/dracut -f
# Load RAID personalities for array creation (exact modules only, no wildcard).
dashboard ALL=(ALL) NOPASSWD: /usr/sbin/modprobe raid0, /usr/sbin/modprobe raid1, /usr/sbin/modprobe raid456, /usr/sbin/modprobe raid10
dashboard ALL=(ALL) NOPASSWD: /usr/bin/mkdir -p -- *
dashboard ALL=(ALL) NOPASSWD: /usr/bin/rmdir *
dashboard ALL=(ALL) NOPASSWD: /usr/bin/chmod 2775 -- *
SUDOERS
chmod 440 $SUDOERS_FILE
visudo -cf "$SUDOERS_FILE" >/dev/null && info "Sudoers validated at $SUDOERS_FILE" \
    || { error "Sudoers file failed validation; removing it."; rm -f "$SUDOERS_FILE"; exit 1; }

# ── Root-owned privilege-boundary helpers (distro-agnostic) ───────────
info "Installing disk-locate read helper..."
LOCATE_HELPER="/usr/local/sbin/storage-dashboard-locate-read"
cat > "$LOCATE_HELPER" << 'HELPER'
#!/bin/sh
# Generate read-only activity on a disk so its activity LED flashes. Reads 32MB
# from a pseudo-random offset (cache-miss -> real device I/O; HDDs also seek).
# Strictly read-only (output is /dev/null), so it is safe on any disk.
dev="$1"
case "$dev" in ''|*[!a-zA-Z0-9]*) echo "invalid device" >&2; exit 2 ;; esac
[ -b "/dev/$dev" ] || { echo "not a block device" >&2; exit 3; }
bytes=$(blockdev --getsize64 "/dev/$dev" 2>/dev/null) || exit 4
count=32
max=$(( bytes / 1048576 - count ))
skip=0
if [ "$max" -gt 0 ]; then
    rnd=$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')
    skip=$(( rnd % max ))
fi
exec dd if="/dev/$dev" of=/dev/null bs=1M count="$count" skip="$skip" 2>/dev/null
HELPER
chown root:root "$LOCATE_HELPER"; chmod 755 "$LOCATE_HELPER"

info "Installing iSCSI sessions helper..."
SESSIONS_HELPER="/usr/local/sbin/storage-dashboard-iscsi-sessions"
cat > "$SESSIONS_HELPER" << 'HELPER'
#!/bin/sh
base=/sys/kernel/config/target/iscsi
[ -d "$base" ] || exit 0
for t in "$base"/iqn.*; do
    [ -d "$t" ] || continue
    tiqn=$(basename "$t")
    for tpg in "$t"/tpgt_*; do
        [ -d "$tpg" ] || continue
        if [ -f "$tpg/dynamic_sessions" ]; then
            while IFS= read -r init; do
                [ -n "$init" ] && printf '%s\t%s\tdynamic\n' "$tiqn" "$init"
            done < "$tpg/dynamic_sessions"
        fi
        for acl in "$tpg"/acls/iqn.*; do
            [ -d "$acl" ] || continue
            if grep -q 'LOGGED_IN' "$acl/info" 2>/dev/null; then
                printf '%s\t%s\tacl\n' "$tiqn" "$(basename "$acl")"
            fi
        done
    done
done
HELPER
chown root:root "$SESSIONS_HELPER"; chmod 755 "$SESSIONS_HELPER"

info "Installing snapshot browse/restore helper..."
SNAPFS_HELPER="/usr/local/sbin/storage-dashboard-snap-fs"
cat > "$SNAPFS_HELPER" << 'HELPER'
#!/usr/bin/env python3
# Root-owned helper for the Storage Dashboard snapshot browser / file restore.
# SECURITY: this script is the trust boundary and enforces its own confinement
# with realpath() — every resolved path must stay inside the snapshot root (for
# reads) or the live dataset root (for restore writes).
import os
import re
import sys
import json
import time
import shutil
import subprocess

RE_DATASET = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_./-]*$')
RE_SNAPNAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.:-]*$')


def die(msg, code=2):
    sys.stderr.write(str(msg) + '\n')
    sys.exit(code)


def mountpoint(dataset):
    try:
        mp = subprocess.run(['zfs', 'get', '-H', '-o', 'value', 'mountpoint', dataset],
                            capture_output=True, text=True).stdout.strip()
    except OSError as e:
        die('zfs: %s' % e)
    if not mp or mp in ('none', 'legacy', '-') or not mp.startswith('/'):
        die('dataset has no usable mountpoint')
    if not os.path.isdir(mp):
        die('mountpoint not present')
    return mp


def confined(base, *parts):
    base_real = os.path.realpath(base)
    target = os.path.realpath(os.path.join(base_real, *[p.lstrip('/') for p in parts if p]))
    if target != base_real and not target.startswith(base_real + os.sep):
        die('path escapes confinement')
    return target


def confined_parent(base, rel):
    base_real = os.path.realpath(base)
    dest = os.path.normpath(os.path.join(base_real, rel.lstrip('/')))
    parent_real = os.path.realpath(os.path.dirname(dest))
    if parent_real != base_real and not parent_real.startswith(base_real + os.sep):
        die('destination escapes confinement')
    return os.path.join(parent_real, os.path.basename(dest))


def cmd_browse(dataset, snap, rel):
    mp = mountpoint(dataset)
    snaproot = confined(os.path.join(mp, '.zfs', 'snapshot'), snap)
    target = confined(snaproot, rel)
    if not os.path.isdir(target):
        die('not a directory')
    entries = []
    with os.scandir(target) as it:
        for e in it:
            try:
                st = e.stat(follow_symlinks=False)
                entries.append({
                    'name': e.name,
                    'type': 'dir' if e.is_dir(follow_symlinks=False) else
                            ('link' if e.is_symlink() else 'file'),
                    'size': st.st_size,
                    'mtime': int(st.st_mtime),
                })
            except OSError:
                continue
    entries.sort(key=lambda x: (x['type'] != 'dir', x['name'].lower()))
    print(json.dumps({'path': rel, 'entries': entries}))


def cmd_restore(dataset, snap, rel, mode):
    if not rel or rel in ('.', '/'):
        die('refusing to restore the dataset root')
    mp = mountpoint(dataset)
    snaproot = confined(os.path.join(mp, '.zfs', 'snapshot'), snap)
    src = confined(snaproot, rel)
    if not os.path.exists(src):
        die('source not found in snapshot')
    dest = confined_parent(mp, rel)
    if mode == 'copy':
        base = dest + '.restored-' + time.strftime('%Y%m%d-%H%M%S')
        dest = base
        n = 1
        while os.path.exists(dest):
            dest = '%s-%d' % (base, n)
            n += 1
    elif mode == 'inplace':
        if os.path.isdir(dest) and not os.path.islink(dest):
            die('inplace restore of a directory over an existing directory is not allowed')
    else:
        die('invalid mode')
    if os.path.isdir(src) and not os.path.islink(src):
        shutil.copytree(src, dest, symlinks=True)
    else:
        if mode == 'inplace' and os.path.exists(dest):
            os.remove(dest)
        shutil.copy2(src, dest, follow_symlinks=False)
    print(json.dumps({'success': True, 'restored_to': dest}))


def main():
    if len(sys.argv) < 5:
        die('usage: snap-fs <browse|restore> <dataset> <snapshot> <relpath> [mode]')
    action, dataset, snap, rel = sys.argv[1:5]
    mode = sys.argv[5] if len(sys.argv) > 5 else 'copy'
    if not RE_DATASET.match(dataset):
        die('invalid dataset')
    if not RE_SNAPNAME.match(snap):
        die('invalid snapshot')
    if '\x00' in rel or '\n' in rel:
        die('invalid path')
    if action == 'browse':
        cmd_browse(dataset, snap, rel)
    elif action == 'restore':
        cmd_restore(dataset, snap, rel, mode)
    else:
        die('unknown action')


if __name__ == '__main__':
    main()
HELPER
chown root:root "$SNAPFS_HELPER"; chmod 755 "$SNAPFS_HELPER"

info "Installing disk mount helper..."
MOUNT_HELPER="/usr/local/sbin/storage-dashboard-mount"
cat > "$MOUNT_HELPER" << 'HELPER'
#!/usr/bin/env python3
# Root-owned helper for the Storage Dashboard plain-disk mount feature.
# Confines every mount point to /mnt or /media, forces a safe fstab option set
# (always nofail), and only ever edits its own delimited block in /etc/fstab.
import os
import re
import subprocess
import sys

BASES = ('/mnt', '/media')
FSTYPES = {'ext4', 'xfs', 'vfat', 'exfat'}
NON_MOUNTABLE = {'zfs_member', 'LVM2_member', 'linux_raid_member', 'swap'}
FSTAB = '/etc/fstab'
BEGIN = '# >>> storage-dashboard managed >>>'
END = '# <<< storage-dashboard managed <<<'
OPTS = 'defaults,nofail'

RE_PART = re.compile(r'^[a-z0-9]+\Z')
RE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]*\Z')
RE_UUID = re.compile(r'^[A-Za-z0-9-]{1,64}\Z')


def die(msg, code=2):
    sys.stderr.write(msg.rstrip() + '\n')
    sys.exit(code)


def fstype_of(part):
    r = subprocess.run(['lsblk', '-no', 'FSTYPE', '/dev/' + part],
                       capture_output=True, text=True)
    return (r.stdout.splitlines() or [''])[0].strip()


def target_for(name, base):
    if base not in BASES or not RE_NAME.match(name):
        die('invalid mount point')
    mp = os.path.join(base, name)
    if os.path.dirname(os.path.normpath(mp)) != base:
        die('mount point escapes base')
    return mp


def do_mount(part, name, base):
    if not RE_PART.match(part):
        die('invalid device')
    mp = target_for(name, base)
    if not os.path.exists('/dev/' + part):
        die('not a block device')
    fst = fstype_of(part)
    if not fst or fst in NON_MOUNTABLE:
        die('not a mountable filesystem')
    if subprocess.run(['findmnt', '-rno', 'TARGET', '/dev/' + part],
                      capture_output=True, text=True).stdout.strip():
        die('already mounted')
    os.makedirs(mp, exist_ok=True)
    r = subprocess.run(['mount', '/dev/' + part, mp], capture_output=True, text=True)
    if r.returncode != 0:
        die('mount failed: ' + (r.stderr or r.stdout), 1)
    print('mounted ' + mp)


def do_umount(part):
    if not RE_PART.match(part):
        die('invalid device')
    tgt = subprocess.run(['findmnt', '-rno', 'TARGET', '/dev/' + part],
                         capture_output=True, text=True).stdout.strip()
    if not tgt:
        die('not mounted')
    if not any(tgt == b or tgt.startswith(b + '/') for b in BASES):
        die('refusing to unmount %s (not under %s)' % (tgt, '/'.join(BASES)))
    r = subprocess.run(['umount', tgt], capture_output=True, text=True)
    if r.returncode != 0:
        die('umount failed: ' + (r.stderr or r.stdout), 1)
    try:
        os.rmdir(tgt)
    except OSError:
        pass
    print('unmounted ' + tgt)


def _read_managed():
    try:
        lines = open(FSTAB).read().splitlines()
    except OSError:
        return [], {}, []
    if BEGIN in lines and END in lines:
        i, j = lines.index(BEGIN), lines.index(END)
        entries = {}
        for ln in lines[i + 1:j]:
            s = ln.strip()
            if s.startswith('UUID='):
                f = s.split()
                if len(f) >= 3:
                    entries[f[0][len('UUID='):]] = (f[1], f[2])
        return lines[:i], entries, lines[j + 1:]
    return lines, {}, []


def _write_managed(entries):
    before, _, after = _read_managed()
    block = [BEGIN]
    for uuid, (mp, fst) in sorted(entries.items()):
        block.append('UUID=%s %s %s %s 0 2' % (uuid, mp, fst, OPTS))
    block.append(END)
    out = before
    if before and before[-1].strip():
        out = out + ['']
    out = out + block + after
    text = '\n'.join(out).rstrip('\n') + '\n'
    tmp = FSTAB + '.sd-tmp'
    with open(tmp, 'w') as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, FSTAB)


def do_fstab_add(uuid, mp, fst):
    if not RE_UUID.match(uuid):
        die('invalid uuid')
    if fst not in FSTYPES:
        die('invalid fstype')
    if not any(mp == b or mp.startswith(b + '/') for b in BASES) or '..' in mp:
        die('mount point not under an allowed base')
    os.makedirs(mp, exist_ok=True)
    _, entries, _ = _read_managed()
    entries[uuid] = (mp, fst)
    _write_managed(entries)
    print('fstab updated')


def do_fstab_remove(uuid):
    if not RE_UUID.match(uuid):
        die('invalid uuid')
    _, entries, _ = _read_managed()
    if uuid in entries:
        del entries[uuid]
        _write_managed(entries)
    print('fstab updated')


def main():
    a = sys.argv[1:]
    if not a:
        die('usage: storage-dashboard-mount {mount|umount|fstab-add|fstab-remove} ...')
    cmd = a[0]
    if cmd == 'mount' and len(a) == 4:
        do_mount(a[1], a[2], a[3])
    elif cmd == 'umount' and len(a) == 2:
        do_umount(a[1])
    elif cmd == 'fstab-add' and len(a) == 4:
        do_fstab_add(a[1], a[2], a[3])
    elif cmd == 'fstab-remove' and len(a) == 2:
        do_fstab_remove(a[1])
    else:
        die('bad arguments')


if __name__ == '__main__':
    main()
HELPER
chown root:root "$MOUNT_HELPER"; chmod 755 "$MOUNT_HELPER"

info "Installing llama.cpp model-fetch helper..."
# Root-owned: trust boundary for downloading a GGUF into the root-owned models
# dir. Re-validates repo/filename, confines output, atomic rename; optional HF
# token read from stdin and passed to curl via inline config (never on argv).
MODEL_FETCH_HELPER="/usr/local/sbin/storage-dashboard-model-fetch"
cat > "$MODEL_FETCH_HELPER" << 'HELPER'
#!/usr/bin/env python3
# Root-owned helper for the Storage Dashboard llama.cpp model download.
#   storage-dashboard-model-fetch <repo> <filename.gguf>
# An optional Hugging Face token may be supplied on the first line of stdin.
import os, re, sys, subprocess

MODELS = '/usr/share/models'   # the ONLY directory this helper will write
RE_REPO = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$')
RE_FILE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*\.gguf$')


def die(m, c=2):
    sys.stderr.write(str(m).rstrip() + '\n')
    sys.exit(c)


def main():
    if len(sys.argv) != 3:
        die('usage: storage-dashboard-model-fetch <repo> <filename.gguf>')
    repo, fn = sys.argv[1], sys.argv[2]
    if not RE_REPO.match(repo):
        die('invalid repo')
    if not RE_FILE.match(fn):
        die('invalid filename')
    token = ''
    try:
        if not sys.stdin.isatty():
            token = sys.stdin.readline().strip()
    except Exception:
        token = ''
    dest = os.path.join(MODELS, fn)
    if os.path.dirname(os.path.realpath(dest)) != os.path.realpath(MODELS):
        die('path escapes models dir')
    if os.path.exists(dest):
        die('already exists', 1)
    os.makedirs(MODELS, exist_ok=True)
    part = dest + '.partial'
    url = 'https://huggingface.co/%s/resolve/main/%s' % (repo, fn)
    cfg = 'url = "%s"\noutput = "%s"\nfail\nlocation\nretry = 3\n' % (url, part)
    if token:
        cfg += 'header = "Authorization: Bearer %s"\n' % token
    try:
        r = subprocess.run(['curl', '-K', '-'], input=cfg, text=True)
    except FileNotFoundError:
        die('curl not found', 1)
    if r.returncode != 0:
        try:
            os.remove(part)
        except OSError:
            pass
        die('download failed (curl exit %d)' % r.returncode, 1)
    os.replace(part, dest)
    print('ok')


if __name__ == '__main__':
    main()
HELPER
chown root:root "$MODEL_FETCH_HELPER"; chmod 755 "$MODEL_FETCH_HELPER"

info "Setting up log directory..."
mkdir -p /var/log/storage-dashboard
chown $DASHBOARD_USER:$DASHBOARD_USER /var/log/storage-dashboard

info "Setting file ownership..."
chown -R $DASHBOARD_USER:$DASHBOARD_USER $DASHBOARD_DIR

info "Creating systemd service..."
cat > /etc/systemd/system/storage-dashboard.service << SERVICE
[Unit]
Description=Nexus / Storage Management Dashboard
After=network.target zfs.target ${NFS_SERVICE}.service ${SMB_SERVICE}.service
Wants=zfs.target ${NFS_SERVICE}.service ${SMB_SERVICE}.service

[Service]
Type=simple
User=dashboard
Group=dashboard
WorkingDirectory=/opt/storage-dashboard
Environment=FLASK_ENV=production
ExecStart=/opt/storage-dashboard/venv/bin/python /opt/storage-dashboard/app.py
Restart=on-failure
RestartSec=10
StandardOutput=append:/var/log/storage-dashboard/app.log
StandardError=append:/var/log/storage-dashboard/app.log

[Install]
WantedBy=multi-user.target
SERVICE

# Background timers (installed disabled; the dashboard enables each only when
# its feature is configured — identical to the Debian/Ubuntu install).
for unit in autosnap replicate alerts maintenance history; do
    case $unit in
        autosnap)    desc="automatic ZFS snapshots"; tick="autosnap-tick"; cal="hourly" ;;
        replicate)   desc="ZFS replication (send/receive)"; tick="replicate-tick"; cal="hourly" ;;
        alerts)      desc="health-alert notifier"; tick="alerts-tick"; cal="*:0/15" ;;
        maintenance) desc="scheduled maintenance (scrubs + SMART self-tests)"; tick="maintenance-tick"; cal="hourly" ;;
        history)     desc="metrics history sampler"; tick="history-tick"; cal="*:0/5" ;;
    esac
    cat > /etc/systemd/system/storage-dashboard-$unit.service << SERVICE
[Unit]
Description=Storage Dashboard $desc
[Service]
Type=oneshot
User=dashboard
Group=dashboard
WorkingDirectory=/opt/storage-dashboard
ExecStart=/opt/storage-dashboard/venv/bin/python /opt/storage-dashboard/app.py $tick
SERVICE
    cat > /etc/systemd/system/storage-dashboard-$unit.timer << TIMER
[Unit]
Description=Storage Dashboard $desc timer
[Timer]
OnCalendar=$cal
Persistent=true
[Install]
WantedBy=timers.target
TIMER
done

info "Enabling and starting services..."
systemctl daemon-reload
# History sampler is on by default (the feature timers above stay opt-in).
systemctl enable --now storage-dashboard-history.timer 2>/dev/null || true
systemctl enable zfs.target 2>/dev/null || true
systemctl enable $ISCSI_SERVICE 2>/dev/null || true
systemctl enable $NFS_SERVICE 2>/dev/null || true
systemctl enable $SMB_SERVICE 2>/dev/null || true
systemctl start $ISCSI_SERVICE 2>/dev/null || true
systemctl start $NFS_SERVICE 2>/dev/null || true
systemctl start $SMB_SERVICE 2>/dev/null || true
systemctl enable storage-dashboard.service

# ── SELinux ───────────────────────────────────────────────────────────
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
    info "SELinux is Enforcing — applying booleans + policy for the dashboard..."
    # Let Samba/NFS export arbitrary dashboard-managed paths.
    setsebool -P samba_export_all_rw on 2>/dev/null || true
    setsebool -P nfs_export_all_rw on 2>/dev/null || true
    setsebool -P samba_export_all_ro on 2>/dev/null || true
    if [ -f "$SCRIPT_DIR/selinux/storage-dashboard.pp" ]; then
        semodule -i "$SCRIPT_DIR/selinux/storage-dashboard.pp" \
            && info "Installed SELinux policy module storage-dashboard.pp" \
            || warn "Failed to install bundled SELinux policy module."
    else
        warn "No bundled SELinux policy module found. The dashboard service runs"
        warn "as the 'dashboard' user and may hit AVC denials. After exercising"
        warn "the UI, review: ausearch -m avc -ts recent | audit2allow -m mypol"
    fi
fi

# ── Firewall (firewalld) ──────────────────────────────────────────────
info "Configuring firewall (firewalld)..."
if systemctl is-active firewalld >/dev/null 2>&1; then
    for p in $DASHBOARD_PORT 3260 2049 445 139 111; do
        firewall-cmd --permanent --add-port=$p/tcp >/dev/null 2>&1 || true
    done
    firewall-cmd --reload >/dev/null 2>&1 || true
else
    warn "firewalld is not active; skipping firewall rules."
fi

info "Installation complete!"
echo ""
echo "Starting dashboard..."
systemctl start storage-dashboard.service || true

echo ""
echo "=== Summary ==="
echo "Dashboard URL:    https://$(hostname -I | awk '{print $1}'):$DASHBOARD_PORT"
echo "                  (self-signed cert by default — your browser will warn once)"
echo "Log file:         /var/log/storage-dashboard/app.log"
echo "Status command:   sudo systemctl status storage-dashboard.service"
echo ""
echo "Login:            An 'admin' account is created on first start with a"
echo "                  random password, printed to the log file above:"
echo "                    sudo grep -A2 'initial admin account' /var/log/storage-dashboard/app.log"
echo "                  Or set one:"
echo "                    sudo -u $DASHBOARD_USER $DASHBOARD_DIR/venv/bin/python $DASHBOARD_DIR/app.py set-password admin"
echo ""
echo "Notes for RHEL/Rocky:"
echo "  - The Network module is netplan-based (Ubuntu-only); only hostname/domain"
echo "    changes work here. Interface/bridge editing is unsupported on RHEL."
echo "  - ZFS comes from the OpenZFS repo and may be unavailable on a brand-new"
echo "    EL release (e.g. EL10 before OpenZFS publishes a matching repo)."
