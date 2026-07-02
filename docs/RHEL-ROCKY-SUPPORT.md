# Plan: support RHEL / Rocky Linux 9 and 10

## Implementation status — 2026-06-26 (Rocky 9 DONE & verified live)

**Rocky Linux 9.8 is supported and verified end-to-end.** Rocky 10 is
**deferred** (OpenZFS has no `el10` repo yet — see "EL9 vs EL10" below).

Done this session (Phases 0–3 + 6):
- **app.py platform layer** — `_platform_from_osrelease()` (pure, unit-tested) +
  `detect_platform()` → `PLATFORM`/`FAMILY`; a `SERVICE_OVERRIDES['rhel']` table
  that renames Samba's unit (`smbd`→`smb`) and remaps package names
  (`nfs-utils`, `targetcli`, `zfs`); family-driven `MDADM_CONF`
  (`/etc/mdadm.conf` vs `/etc/mdadm/mdadm.conf`) and `INITRAMFS_UPDATE`
  (`dracut -f` vs `update-initramfs -u`); `_pkg_installed()` uses `rpm -q` on
  RHEL. The two hardcoded `smbd` restarts now resolve via `SYSTEM_SERVICES`.
  Tests in `tests/test_platform.py` (suite 119 → 127). **Ubuntu path unchanged.**
- **`install-prerequisites-rhel.sh`** — dnf + CRB + EPEL, the RHEL package map,
  best-effort OpenZFS (**kmod, not DKMS** — see findings), per-package install
  fallback, missing-package report.
- **`install-rhel.sh`** — self-contained (keeps the Ubuntu `install.sh`
  untouched, zero regression risk): user/venv/deploy, RHEL sudoers paths
  (`visudo`-validated), the distro-agnostic root-owned helpers (snap-fs,
  locate-read, iscsi-sessions, mount — **netplan helper intentionally omitted**),
  systemd unit + 4 timers with RHEL service names, firewalld rules, SELinux
  booleans.

Verified on **`192.168.34.98`** (Rocky 9.8) under **SELinux Enforcing**: all of
zfs/iscsi/nfs/smb installed + active; full ZFS pool→dataset→destroy lifecycle via
the API; NFS export + SMB share create/delete (the `tee`-into-config paths);
`/api/{version,me,status,summary,disks,zfs,lvm,mdadm,nfs,smb,network}` all 200.
**Zero AVC denials** — no custom SELinux policy module was needed (the service
runs unconfined; `samba_export_all_rw`/`nfs_export_all_rw` booleans are set).

### Findings (bake into any re-port / Rocky 10 work)
- **Package names:** it's `python3-rtslib` on RHEL (the Debian name
  `python3-rtslib-fb` does NOT exist and one bad name aborts the whole dnf
  transaction). NFS = `nfs-utils`, iSCSI = `targetcli`, Samba unit = `smb`.
- **dnf has no `--skip-unavailable` on EL9** → the prereq script batch-installs,
  then falls back to a per-package loop so one missing name can't block the rest.
- **ZFS = kmod, not DKMS.** The default OpenZFS repo `[zfs]` is DKMS, which built
  against the wrong (newer, un-booted) kernel and wouldn't load. Switch to
  `[zfs-kmod]` (kABI-tracking, prebuilt) — `dnf config-manager --disable zfs
  --enable zfs-kmod`. Current repo RPM: `zfs-release-2-3.el9.noarch.rpm`.
- **Secure Boot blocks the unsigned kmod** (`modprobe: Key was rejected by
  service`). On the test VM Secure Boot was **disabled** in firmware + rebooted →
  module loads (`zfs-kmod-2.2.10`). Otherwise MOK-sign the modules.
- **`nfsdclnts` doesn't exist on Rocky 9** (nfs-utils 2.5) — the `installed`
  check falls back to unit presence, so NFS still reports installed once
  `nfs-utils` is in. (No code change needed.)
- The Rocky 9 minimal image lacks `tar` — `dnf install -y tar` to unpack a
  tarball deploy.

### Remaining / known limitations on RHEL
- **Network module is Ubuntu-only** (netplan). The read view works; interface/
  bridge *apply* is unsupported (no netplan helper installed). Hostname/domain
  still works. Plan: an `nmcli` backend, later.
- **Rocky 10**: blocked on OpenZFS `el10`. Everything else would port (the
  scripts already detect `el10`); revisit when OpenZFS publishes it.

---

Goal: make the Storage Management Dashboard install and run on **RHEL/Rocky 9 and
10** in addition to Ubuntu, without regressing the Debian/Ubuntu path. EL9 and
EL10 are the same family (dnf, firewalld, `systemd`, SELinux), so doing both
together costs little more than doing 9 alone — the differences are repo URLs and
the newer kernel/ZFS situation on 10.

The app itself (`app.py`, the SPA, parsers/validators) is already distro-agnostic.
**All the OS coupling lives in three places:** (a) the apt installer, (b) the
systemd units + service *names* the app references, and (c) the sudoers binary
paths. This plan removes those assumptions behind a small platform layer, then
tackles the two genuinely hard parts (ZFS-on-RHEL, SELinux).

---

## Guiding principle — a platform-abstraction layer

Don't sprinkle `if rhel` everywhere. Detect the platform **once** from
`/etc/os-release` (`ID`, `ID_LIKE`, `VERSION_ID`) and drive everything from
per-family tables:

- **install scripts:** a `PKG_MGR` (`apt`/`dnf`) + a package-name map.
- **app.py:** a `SERVICES` map (key → systemd unit name) instead of the
  hardcoded `nfs-kernel-server`/`smbd`; a few path constants (e.g. iSCSI
  saveconfig).
- **install.sh:** firewall tool (`ufw`/`firewall-cmd`), and the same service map
  for the unit `After=`/`Wants=`.

This makes the *next* distro (openSUSE, Arch) mostly another table entry.

---

## Phase 0 — platform detection scaffolding  ← **start here tomorrow**

Small, safe, no behavior change on Ubuntu. Concrete first task:

1. Add `detect_platform()` to `app.py` returning `{family: 'debian'|'rhel',
   id, version}` from `/etc/os-release` (`ID`, `ID_LIKE`).
2. Add a `SERVICES` dict keyed by family for the service names the app uses
   today — replace the hardcoded `nfs-kernel-server.service` / `smbd.service`
   in `SYSTEM_SERVICES`, `_compute_alerts`, and `api_summary` with a lookup.
   - Debian: `nfs-kernel-server`, `smbd`. RHEL: `nfs-server`, `smb`.
3. Add the matching shell helper to `install.sh`/`install-prerequisites.sh`
   (`. /etc/os-release; case "$ID/$ID_LIKE" in …`) setting `FAMILY`, `PKG_MGR`.
4. Unit-test `detect_platform()` by feeding it sample os-release text (pure
   function — fits the existing `tests/` pattern).

Deliverable: Ubuntu behaves identically; the codebase now *knows* its platform.

---

## Phase 1 — packages (dnf + EPEL + name map)

`install-prerequisites.sh` currently hard-gates on `apt-get`. Add a `dnf` branch:

- Enable **EPEL** (`dnf install -y epel-release`) — several tools live there.
- Package-name map (Debian → RHEL):

  | feature        | Debian            | RHEL/Rocky            |
  |----------------|-------------------|-----------------------|
  | NFS server     | nfs-kernel-server | nfs-utils             |
  | Samba          | samba, smbclient  | samba, samba-client   |
  | iSCSI target   | targetcli-fb      | targetcli (+ python3-rtslib-fb) |
  | SCSI utils     | sg3-utils         | sg3_utils             |
  | ip tooling     | iproute2          | iproute               |
  | ssh client     | openssh-client    | openssh-clients       |
  | gdisk/lsscsi/ledmon | (main/universe) | (EPEL)            |
  | mdadm, lvm2, xfsprogs, parted, smartmontools, openssl, acl, curl | same | same |
  | venv           | python3-venv      | (bundled in python3)  |

- ZFS is **not** in this list — it needs its own repo (Phase 4).

## Phase 2 — service names + units

- App side: done in Phase 0 (the `SERVICES` map).
- `install.sh`: generate the dashboard unit's `After=`/`Wants=` from the family
  map (`nfs-server`/`smb` on RHEL), and `systemctl enable` the right names.
- iSCSI saveconfig path differs: Debian `/etc/rtslib-fb-target/saveconfig.json`
  vs RHEL `/etc/target/saveconfig.json` — make it a platform constant.

## Phase 3 — firewall

`install.sh` uses `ufw allow`. Add a `firewalld` branch:
`firewall-cmd --permanent --add-port=8443/tcp` (+ 3260/2049/445/139/111) then
`firewall-cmd --reload`. Gate on `PKG_MGR`/`FAMILY`.

## Phase 4 — ZFS on RHEL (the first hard part)

Red Hat never ships ZFS (CDDL/GPL). Install from the OpenZFS repo:
- `dnf install -y https://zfsonlinux.org/epel/zfs-release-2-*.noarch.rpm`
  (pick the right `el9`/`el10` release), then `dnf install -y zfs`.
- This builds a **DKMS** module against `kernel-devel` matching the running
  kernel — install `kernel-devel`/`kernel-headers`, then `modprobe zfs`.
- **Risks (document, can't fully automate):** kernel/headers mismatch after an
  update; **Secure Boot** requires signing the module or it won't load; on a
  brand-new EL10 kernel the OpenZFS release may lag. The installer should attempt
  it best-effort and fail loudly with guidance rather than silently.

## Phase 5 — SELinux (the second hard part)

RHEL ships SELinux **enforcing**. The service runs as `dashboard` and shells out
to write `/etc/exports`, `/etc/samba/smb.conf`, `/etc/hosts`, the netplan/
NetworkManager config, run `targetcli`, execute the root-owned helpers, and bind
8443. Expect AVC denials. Approach:
1. Install + run on enforcing Rocky, drive every feature, collect denials
   (`ausearch -m avc -ts recent` / `audit2why`).
2. Ship a small policy module (`.te` → `semodule -i`) OR document the booleans/
   contexts needed. Iterative — only found by running on an enforcing box.
- Networking note: RHEL uses **NetworkManager**, not netplan. The Network module
  would need an `nmcli` backend on RHEL (netplan is Ubuntu-only). Treat the
  Network module as **Ubuntu-only for now**; hide it (or show "unsupported on
  this platform") when `family == rhel`, and add `nmcli` support as a later
  phase.

## Phase 6 — sudoers paths

RHEL uses merged `/usr` (paths already largely covered), but verify every granted
binary resolves on RHEL and re-run `visudo -cf` there. Some live in different
packages/paths (e.g. `targetcli`). Generate the sudoers from the family map too.

---

## EL9 vs EL10

Nearly identical (same family branch). Differences:
- ZFS repo URL (`el9` vs `el10`) and the newer 10 kernel → higher chance the
  OpenZFS build lags; the main 10-specific risk.
- Confirm `dnf` vs `dnf5` CLI on 10 (RHEL 10 default is still `dnf`-compatible).
- Confirm EPEL 10 has gdisk/lsscsi/ledmon.

Doing 10 after 9 is mostly **a second test VM + the ZFS-on-new-kernel check**.

---

## Testing

Mirror the Ubuntu approach: stand up disposable, **snapshotted** Rocky 9 and
Rocky 10 VMs (like `192.168.34.88`), install via the scripts, then run the full
end-to-end pass (the same module-by-module exercise) against scratch resources.
SELinux denials and the DKMS/ZFS build only surface at runtime, so a real VM is
required — can't be validated from Ubuntu.

---

## Effort estimate

- **Phases 0–3 + 6** (platform layer, packages, services, firewall, sudoers):
  ~1 day, low risk, mostly mechanical + table-driven.
- **Phase 4 (ZFS)**: ~0.5–1 day, dominated by DKMS/Secure-Boot/repo edge cases.
- **Phase 5 (SELinux)**: ~1–2 days, iterative policy work on an enforcing box.
- **Network module via nmcli** (optional, later): ~1–2 days.

"Works on Rocky 9/10 with SELinux permissive and ZFS pre-installed" is ~1 day;
"clean install on stock enforcing Rocky with automated ZFS + an SELinux policy"
is ~3–5 days. Cannot be verified without Rocky 9/10 test VMs.

---

## Tomorrow's concrete starting point

1. Create the two Rocky VMs (9 and 10), snapshotted, reachable like the Ubuntu VM.
2. Implement **Phase 0** (`detect_platform()` + `SERVICES` map + os-release
   shell detection + a unit test) — safe, no Ubuntu behavior change.
3. Then Phase 1 (dnf branch + EPEL + package map) and try a first install on
   Rocky 9 with SELinux set permissive, to surface the next round of issues.
