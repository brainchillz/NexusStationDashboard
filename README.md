# Storage Management Dashboard

A web-based management dashboard for Ubuntu Linux that provides a unified interface for managing:

- **ZFS Storage Pools** — Pools, datasets, snapshots, ZVOLs; scrub, capacity/health
  visualization, full device lifecycle (replace/offline/online/detach, add
  spare/cache/log vdevs), pool import/export, snapshot diff, snapshot
  browse + single-file restore, and send/receive replication to a remote host
- **iSCSI Targets** — LIO targets, backstores (fileio/block/ZVOL), LUNs, ACLs,
  CHAP, connected-initiator view, auto-saved config, and a shared multi-initiator
  default for Proxmox/VMware clusters
- **NFS Exports** — Manage NFS exports and client access
- **SMB/CIFS Shares** — Create and manage Samba shares and users
- **Disks** — SMART health, role/usage labeling, drive locate (LED + activity),
  and safe wipe of free/stale disks
- **LVM** — full PV/VG/LV management (create, resize, extend, pvmove) with the
  system/boot LVM protected
- **MD RAID** — Linux software RAID (mdadm): create arrays from free disks,
  add/fail/remove members, hot spares, persisted to mdadm.conf; in-use arrays protected
- **Alerting** — email (SMTP) + webhook (Google Chat / Slack-compatible)
  notifications on degraded/full pools, stopped services, and SMART failures,
  de-duplicated (notify once per condition, with a resolved notice when it clears)
- **Scheduled maintenance** — periodic ZFS scrubs and SMART self-tests
- **Network** — set hostname/domain and per-interface IP (DHCP or static:
  address/gateway/DNS) plus bridges, via netplan. An IP change **adds the new
  address alongside the old one** and only drops the old one when you **Finalize**
  — so you're never locked out mid-change. A one-click **session handoff** link
  logs you straight in on the new address, and Finalize keeps a short
  auto-rollback net in case the committed config is unreachable
- **Monitoring** — Prometheus `/metrics`, live resource overview, a bounded
  on-disk **time-series history** (CPU/mem/load, pool capacity, ARC, GPU,
  inference) feeding sparklines and a pool "full in ~N days" forecast, **GPU/VRAM
  monitoring** (NVIDIA/AMD), a **Scheduled Tasks** console, a **journald log
  viewer**, audit log, RBAC users + API tokens, first-run forced password change

Built with Python/Flask backend and a dark-theme single-page web UI, served over
HTTPS with session authentication.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Web Browser                       │
│         https://<host>:8443                          │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│        Flask Web Server (HTTPS, port 8443)           │
│          /opt/storage-dashboard/app.py               │
│          Runs as: dashboard user                      │
└───────┬──────────┬──────────┬──────────┬────────────┘
        │          │          │          │
   ┌────▼────┐ ┌──▼───┐ ┌───▼────┐ ┌──▼────┐
   │  ZFS    │ │iSCSI │ │  NFS   │ │  SMB  │
   │zfsutils │ │LIO   │ │nfs-ker-│ │samba  │
   │         │ │target│ │nel-svr │ │       │
   └────────┘ └──────┘ └────────┘ └───────┘
   All managed via sudo with passwordless sudoers rules
```

## Prerequisites

- Ubuntu 22.04, 24.04, or 26.04 LTS
- Root or sudo access
- At least one unused disk for ZFS pools (optional)

## Quick Install

Copy the project to `/opt/storage-dashboard`, then from that directory run (as root):

```bash
sudo ./install-prerequisites.sh   # install required apt packages
sudo ./install.sh                 # create user, venv, sudoers, systemd service
```

`install.sh` invokes `install-prerequisites.sh` automatically, so on a host that
already has the packages you can run `install.sh` alone.

On first start an `admin` account is created with a **random password printed to
the log** — see [Authentication](#authentication) below.

### Step-by-step manual install:

```bash
# 1. Install system dependencies (or just run ./install-prerequisites.sh)
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip \
  zfsutils-linux targetcli-fb nfs-kernel-server nfs-common samba \
  smbclient cifs-utils lsscsi smartmontools gdisk mdadm parted ledmon \
  lvm2 xfsprogs sg3-utils iproute2 openssl openssh-client acl curl

# 2. Create the directory and files
sudo mkdir -p /opt/storage-dashboard/static /opt/storage-dashboard/templates
# Copy all project files into /opt/storage-dashboard/

# 3. Create the dashboard user
sudo useradd -r -s /usr/sbin/nologin -M -d /opt/storage-dashboard dashboard

# 4. Set up Python virtual environment
sudo python3 -m venv /opt/storage-dashboard/venv
sudo /opt/storage-dashboard/venv/bin/pip install flask

# 5. Set up sudoers + the disk-locate helper.
# install.sh is the single source of truth for both (the exact, security-scoped
# command list is large and version-specific). Rather than hand-copy it, install
# it from install.sh's heredocs:
#
#   - /etc/sudoers.d/storage-dashboard  (the `SUDOERS` heredoc; chmod 440)
#   - /usr/local/sbin/storage-dashboard-locate-read  (root-owned 0755 helper)
#   - /usr/local/sbin/storage-dashboard-snap-fs       (root-owned 0755 helper)
#
# Easiest: just run ./install.sh, which writes both. Always validate with
# `visudo -cf /etc/sudoers.d/storage-dashboard` before relying on it.

# 6. Set ownership
sudo chown -R dashboard:dashboard /opt/storage-dashboard
sudo mkdir -p /var/log/storage-dashboard
sudo chown dashboard:dashboard /var/log/storage-dashboard

# 7. Create systemd service
sudo tee /etc/systemd/system/storage-dashboard.service << 'SERVICE'
[Unit]
Description=Ubuntu Storage Management Dashboard
After=network.target zfs.target nfs-server.service smbd.service
Wants=zfs.target nfs-server.service smbd.service

[Service]
Type=simple
User=dashboard
Group=dashboard
WorkingDirectory=/opt/storage-dashboard
ExecStart=/opt/storage-dashboard/venv/bin/python /opt/storage-dashboard/app.py
Restart=on-failure
RestartSec=10
StandardOutput=append:/var/log/storage-dashboard/app.log
StandardError=append:/var/log/storage-dashboard/app.log

[Install]
WantedBy=multi-user.target
SERVICE

# 8. Enable and start services
sudo systemctl daemon-reload
sudo systemctl enable zfs.target
sudo systemctl enable target
sudo systemctl enable nfs-server
sudo systemctl enable smbd
sudo systemctl enable storage-dashboard
sudo systemctl start target nfs-server smbd storage-dashboard

# 9. (Optional) Open firewall ports
sudo ufw allow 8443/tcp comment 'Storage Dashboard'
sudo ufw allow 3260/tcp comment 'iSCSI Target'
sudo ufw allow 2049/tcp comment 'NFS'
sudo ufw allow 445/tcp comment 'SMB'
sudo ufw allow 139/tcp comment 'SMB NetBIOS'
```

## Accessing the Dashboard

Once installed, open a web browser to:

```
https://<server-ip>:8443
```

(Self-signed certificate by default — accept the browser warning once, or
install your own cert; see [TLS](#tls).)

The dashboard will show the service status on the main page. Use the sidebar to navigate between:

| Section | Description |
|---------|-------------|
| **Dashboard** | At-a-glance metrics (pool usage, iSCSI/NFS/SMB counts, disks) + health alerts |
| **Disks** | Disks with role/usage, SMART health, locate (LED + activity), and wipe |
| **ZFS Pools** | Pools/datasets/snapshots/ZVOLs, scrub, capacity bars, device lifecycle, import/export, snapshot diff/browse/restore, send/receive replication |
| **LVM** | Physical volumes, volume groups, logical volumes (create/resize/extend/move) |
| **MD RAID** | Linux software RAID arrays (create/manage/replace), members from free disks |
| **iSCSI Targets** | Manage iSCSI targets, backstores, LUNs, ACLs |
| **NFS Exports** | Create and manage NFS shared directories |
| **SMB/CIFS** | Shares (access control, recycle, Previous Versions, Time Machine), users, groups, home dirs, global settings |
| **Auto-Snapshots** | Opt-in scheduled ZFS snapshots (per dataset/pool, with retention) |
| **AI Tools → LLama.cpp** | Manage a local `llama.cpp` `llama-server`: status + start/stop/restart/enable/disable, model switching (GGUF), Hugging Face model pull, named profiles, and a CLI-argument editor. Health / tokens-per-sec surface on the Dashboard. See `contrib/llama/`. |
| **AI Tools → GPU** | GPU/VRAM monitoring (NVIDIA `nvidia-smi` or AMD `rocm-smi`): per-device utilization, VRAM, temperature, power, with a Dashboard card and utilization sparklines from history |
| **System → Scheduled Tasks** | Status of every dashboard-managed timer (armed / last-run / next-run / last-result), a **Run now** trigger, and failed runs surfaced as alerts |
| **System → Logs** | Filtered journald viewer (by unit, priority, and text) over the dashboard, its tasks, and the managed system services |
| **System** | Services, Network (hostname/IP/bridges), My Account, Users & Tokens, Notifications, TLS Certificate, the Audit Log, **Modules** (show/hide feature areas in the nav), and a light/dark **theme** toggle (installable as a PWA) |

## Authentication

The dashboard requires a login. All `/api/*` endpoints (except the login route)
return `401` without a valid session; the session cookie is `HttpOnly` and
`SameSite=Lax`.

On first start, if no account exists, an `admin` user is created:

- If `DASHBOARD_ADMIN_PASSWORD` is set in the environment, that password is used.
- Otherwise a random password is generated and printed to the log. Retrieve it:

  ```bash
  sudo grep -A2 'initial admin account' /var/log/storage-dashboard/app.log
  ```

Additional users with roles can be created in **System → Users & Tokens**:
**administrator** (full access) or **read-only** (can view but not change anything;
enforced server-side — all mutating requests return 403). An optional "SMB user"
checkbox also creates a matching Samba account.

Change your own password from **System → My Account**, or from the CLI:

```bash
sudo -u dashboard /opt/storage-dashboard/venv/bin/python \
  /opt/storage-dashboard/app.py set-password admin
```

Credentials and the session secret are stored in `auth.json` (mode `0600`,
owned by the `dashboard` user) next to `app.py`; override its location with
`DASHBOARD_AUTH_FILE`.

### API tokens (automation)

For scripts that can't carry a session cookie, create tokens in
**System → Users & Tokens** (admin only). Each token has a name and a role
(**administrator** or **read-only**, enforced by the same server-side RBAC as
users), and the secret is shown **once** at creation — only its SHA-256 is stored.
Present it as a header on any API request:

```bash
# read-only example
curl -sk -H "Authorization: Bearer sd_xxxxxxxx" https://host:8443/api/summary
# (the X-API-Token: <token> header works too)
```

Revoke a token any time from the same panel. Token actions are recorded in the
audit log as `token:<name>`. (Tokens are stored in `auth.json`; the metrics
endpoint has its own separate `DASHBOARD_METRICS_TOKEN`.)

## TLS

The dashboard serves **HTTPS on port 8443 by default**. On first start it
generates a **self-signed certificate** (`certs/dashboard.crt` / `.key` next to
`app.py`) — browsers show a one-time warning you can accept.

To install your **own certificate**, any of:
- **System → Certificate** in the UI → paste your PEM cert + private key (validated
  and saved; restart the service to apply).
- Drop your PEM files at `certs/dashboard.crt` / `certs/dashboard.key`
  (replacing the self-signed pair) and restart.
- Point `DASHBOARD_TLS_CERT` / `DASHBOARD_TLS_KEY` at your files.

Relevant environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `DASHBOARD_TLS` | `1` | Set `0` to serve plain HTTP (e.g. behind a TLS-terminating reverse proxy) |
| `DASHBOARD_PORT` | `8443` (TLS) / `8080` (no TLS) | Listen port |
| `DASHBOARD_TLS_CERT` / `DASHBOARD_TLS_KEY` | `certs/dashboard.*` | Certificate / key paths |
| `DASHBOARD_COOKIE_SECURE` | follows `DASHBOARD_TLS` | Force the session cookie to HTTPS-only |
| `DASHBOARD_METRICS_TOKEN` | _(unset)_ | If set, `/metrics` requires this token (`?token=` or Bearer); otherwise open |

## Health alerts

The dashboard computes one set of health alerts from a single source
(`_compute_alerts`). They appear on the **Dashboard** page and, when the email /
webhook channel is configured (System → Notifications), are sent by the
background notifier. The notifier is **de-duplicated**: it sends one notice when a
condition first appears and a **RESOLVED** notice when it clears (keyed by the
stable `key` below).

| Condition | Key | Fires when | Example message |
|-----------|-----|-----------|-----------------|
| **Service down** | `service:<svc>` | A managed service (ZFS, iSCSI, NFS, Samba) is not `active` | `Samba service is inactive` |
| **Pool unhealthy** | `zfs_health:<pool>` | A ZFS pool's health is not `ONLINE` (DEGRADED / FAULTED / …) | `ZFS pool tank is DEGRADED` |
| **Pool nearly full** | `zfs_full:<pool>` | A pool is **≥ 90%** allocated (`ALERT_FULL_PCT`) | `ZFS pool tank is 93% full` |
| **Filesystem nearly full** | `fs_full:<mount>` | Any real mounted filesystem is **≥ 90%** full (covers LVM LVs, plain partitions) | `Filesystem /var is 91% full` |
| **LVM missing PV** | `lvm_pv:<vg>` | A volume group has a missing/failed physical volume (failed disk) | `LVM volume group data has 1 missing PV(s)` |
| **MD array degraded** | `md_degraded:<dev>` | An mdadm array is running degraded (failed/missing member) | `MD RAID array md0 is degraded` |
| **Disk SMART failure** | `smart` | Any disk reports a SMART health failure | `A disk reports SMART failure` |

**Intentional states are not alerted.** A service is skipped when it is turned off
on purpose: its **module is disabled** (System → Modules) or its unit is
**`disabled` / `masked` at boot**. Likewise the LVM and MD alerts are suppressed
when their module is disabled; **filesystem-full** is always checked (it's a
general operational risk). The **llama.cpp** (`llama-server`) service never raises
an alert — it is routinely stopped between sessions. Pseudo/read-only filesystems
(tmpfs, squashfs/snap, overlay, zfs — covered by its own pool alert) are excluded.
SMART is sampled from a 5-minute cache, so a SMART alert can lag a failure by up
to that long.

## API Endpoints

### Authentication
- `POST /api/login` — Log in `{username, password}` (sets session cookie)
- `POST /api/logout` — Log out
- `GET /api/me` — Current session status
- `POST /api/account/password` — Change own password `{old_password, new_password}`
- `GET|POST /api/users` — List / create users `{username, password, role, smb}` (admin)
- `POST /api/users/<u>/role` `{role}` · `/password` `{password}` · `DELETE /api/users/<u>` (admin)
- `GET|POST /api/tokens` — List / create API tokens `{name, role}` (admin; the secret is returned once)
- `DELETE /api/tokens/<id>` — Revoke a token (admin)

### System
- `GET /api/summary` — Aggregated dashboard overview (pools/usage, iSCSI
  targets/LUNs/sessions, NFS exports/mounts, SMB shares/users, disks, alerts)
- `GET /api/system/resources` — Live CPU %, load average, memory/swap, uptime
- `GET /api/history` — Time-series points `?metric=&label=&since=` (raw) or `?res=daily&days=` (rolled-up)
- `GET /api/history/forecast` — Pool fill-rate + "full in ~N days" `?label=<pool>`
- `GET /api/gpu` — GPU/VRAM telemetry (NVIDIA/AMD): per-device util, VRAM, temp, power
- `GET /api/tasks` — Managed timers with armed/last-run/next-run/last-result
- `POST /api/tasks/<id>/run` — Trigger a managed task now (admin)
- `GET /api/status` — Service status overview
- `GET /api/network` — Network interfaces
- `GET /api/logs/<service>` — Service logs
- `GET /api/logs/sources` — Curated log-source list (dashboard, services, tasks)
- `GET /api/logs/query` — Filtered journald tail `?source=&lines=&priority=&grep=`
- `GET /manifest.webmanifest` — PWA manifest (public; install to home screen)
- `GET /metrics` — Prometheus metrics (host resources, ZFS pools, services,
  SMART). **Public** so a scraper can reach it; set `DASHBOARD_METRICS_TOKEN` to
  require a token (`?token=` or `Authorization: Bearer`).
- `GET|POST /api/notifications` — Email/webhook config (SMTP password masked on read)
- `POST /api/notifications/test` — Send a test notification via the saved channels
- `GET /api/modules` — Feature modules with enabled state (any logged-in user)
- `POST /api/modules` — Enable/disable a module `{id, enabled}` (admin); a disabled
  module is hidden from the left nav (cosmetic — no data/service change)
- `GET|POST /api/maintenance` — Scheduled scrubs + SMART self-tests

### AI Tools — llama.cpp
Manages a local `llama-server` systemd unit via `/etc/llama.conf` (validated,
written through the pinned `tee` grant). Service control reuses the shared
`/api/service/<svc>/<action>` endpoints (service key `llamacpp`). See
`contrib/llama/` for the wrapper/unit/config to install on the host.
- `GET /api/llama` — status, current model, parsed args, available GGUF models
- `PUT /api/llama/model` — switch model `{model}` (must resolve inside the models dir)
- `PUT /api/llama/args` — replace CLI args `{args:[{flag,value}]}` (`-m` excluded; managed by model)
- `GET /api/llama/health` — proxy llama-server `/health` + `/metrics` (for the dashboard card;
  also returns an in-memory `tokens_per_sec` derived from the metrics counter between polls)
- `GET|POST /api/llama/presets` — list / save **profiles** `{name, model?, args}` (a profile
  bundles an optional model with CLI args; legacy args-only presets are read too)
- `POST /api/llama/presets/<name>/apply` — apply a profile: write model + args and restart if running
- `DELETE /api/llama/presets/<name>` — delete a profile
- `POST /api/llama/models/pull` — download a GGUF from Hugging Face `{repo, filename, token?}`
  (background job via the root-owned `storage-dashboard-model-fetch` helper; one at a time)
- `GET /api/llama/models/pull/status` — progress of the current/last download
- `POST /api/maintenance/smart-test` — Start a SMART self-test now `{device, type}`
- `GET /api/network` — Hostname/domain, interfaces, gateway, DNS, managed netplan, pending-change status
- `POST /api/network/hostname` — Set `{hostname, domain}` (hostnamectl + /etc/hosts)
- `POST /api/network/interface` — Configure `{iface, mode: dhcp|static, addresses[], gateway, nameservers[]}`
  (`addresses` is a list — bind several IPs to one interface; a single `address` is still accepted. One
  default gateway per host. Adds the new address(es) alongside the old; returns a `new_url` handoff link to finalize on)
- `POST /api/network/bridge` — Create `{name, interfaces[], mode, address, gateway, nameservers[]}`
- `POST /api/network/finalize` `{token}` — Commit the change (drop the old address); arms a short auto-rollback net
- `POST /api/network/confirm` `{token}` — Heartbeat from the new address that confirms the finalized config is reachable
- `POST /api/network/revert` — Roll back to the previous config now
- `POST /api/network/handoff` `{token}` — Exchange a one-time handoff secret for a session on the new address (public)

### Disks
- `GET /api/disks` — List disks (annotated with `usage`, `wipeable`, `wipe_reason`)
- `GET /api/disks/<dev>/smart` — SMART health (ATA + NVMe)
- `POST /api/disks/<dev>/locate` — Flash the drive `{seconds}` or `{stop:true}` (read-only)
- `POST /api/disks/<dev>/wipe` — Blank a free/stale disk (refused on protected disks)
- `POST /api/disks/<dev>/format` — Initialize a free disk: GPT label + one whole-disk
  partition + `mkfs` `{fstype, label?}` (`fstype` ∈ ext4/xfs/vfat/exfat; refused on
  protected disks, re-checked server-side)

### Filesystems & mounts (plain disks)
Standard formatted filesystems — including a plugged-in USB drive — that aren't part
of ZFS/LVM/MD/swap. Mounting, unmounting and `/etc/fstab` edits all go through the
root-owned `storage-dashboard-mount` helper, which confines mount points to `/mnt`
and `/media` and always writes `nofail` fstab entries (a missing/yanked disk can
never block boot).
- `GET /api/filesystems` — List mountable filesystems (fstype, UUID, size, label,
  mount state, and whether a boot/fstab entry exists)
- `POST /api/filesystems/<part>/mount` — Mount `{name, base?, fstab?}` at
  `<base>/<name>`; `fstab:true` adds a UUID-based boot entry
- `POST /api/filesystems/<part>/unmount` — Unmount `{remove_fstab?}` (only mounts
  under `/mnt` or `/media` can be unmounted from here)

### TLS
- `GET /api/tls/info` — Current certificate (subject, issuer, expiry, self-signed?)
- `POST /api/tls/cert` — Install a custom certificate `{cert, key}` (PEM); restart to apply
- `POST /api/tls/regenerate` — Regenerate the self-signed certificate; restart to apply

### ZFS
- `GET /api/zfs/pools` — List pools
- `GET /api/zfs/pools/detail` — Per-pool status (state, scan, devices, errors)
- `POST /api/zfs/pools` — Create pool. Structured form `{name, vdevs:[{role, type, disks[]}]}`
  builds a pool with multiple data vdevs **and** cache/log/spare in one call (`role` ∈
  `''|log|cache|spare`, `type` ∈ `''|mirror|raidz*`); the legacy `{name, vdev_type, disks[]}`
  single-vdev form is still accepted
- `DELETE /api/zfs/pools/<name>` — Destroy pool
- `POST /api/zfs/pools/<name>/scrub` — Scrub `{action: start|stop}`
- `POST /api/zfs/pools/<name>/trim` — TRIM `{action: start|cancel}`
- `POST /api/zfs/pools/<name>/autotrim` — Toggle the `autotrim` pool property `{enabled}`
- `GET /api/zfs/arc` — ARC/L2ARC stats from `/proc` (size, `c_max`, hit ratio, L2ARC)
- `POST /api/zfs/pools/<name>/device` — Device op `{action: replace|offline|online|detach|remove, device, new_device?}`
  (`remove` pulls a cache/log/spare device, and evacuable data vdevs on supported layouts)
- `POST /api/zfs/pools/<name>/vdev` — Add vdev `{role: ''|mirror|raidz*|spare|cache|log, disks[]}`
- `GET /api/zfs/pools/importable` — Scan for importable (not-yet-imported) pools
- `POST /api/zfs/pools/import` — Import `{name|id, new_name?, altroot?, force?}`
- `POST /api/zfs/pools/<name>/export` — Export pool (refused 409 if it backs the system)
- `GET /api/zfs/pools/<name>/datasets` — List datasets
- `POST /api/zfs/datasets` — Create dataset/ZVOL `{name, properties{}, volsize?}`. Optional
  native encryption `{encryption, keyformat:'passphrase', passphrase}` (creation-time only;
  passphrase sent on stdin, never on the command line)
- `POST /api/zfs/datasets/<name>/key/load` — Unlock an encrypted dataset `{passphrase}`
- `POST /api/zfs/datasets/<name>/key/unload` — Lock an encrypted dataset (must be unmounted)
- `POST /api/zfs/datasets/<name>/key/change` — Change the passphrase `{passphrase}`
- `GET /api/zfs/zvols` — List ZVOLs (for iSCSI block backstores)
- `POST /api/zfs/datasets/rename` — Rename `{name, new_name}`
- `GET|PUT /api/zfs/datasets/<name>/properties` — Get / set `{property, value}`
- `DELETE /api/zfs/datasets/<name>` — Destroy dataset
- `GET /api/zfs/snapshots` — List snapshots (each with `used` + `written` space)
- `POST /api/zfs/snapshots` — Create snapshot `{dataset, snap_name, recursive?}`
- `POST /api/zfs/snapshots/clone` — Clone `{snapshot, target}`
- `POST /api/zfs/snapshots/rollback` — Rollback `{snapshot}`
- `DELETE /api/zfs/snapshots/<name>` — Destroy snapshot
- `GET /api/zfs/snapshots/diff?from=<snap>&to=<snap|dataset>` — File-level diff (vs the live filesystem if `to` omitted)
- `GET /api/zfs/snapshots/<snap>/browse?path=` — List a directory inside a snapshot
- `POST /api/zfs/snapshots/<snap>/restore` — Restore `{path, mode: copy|inplace}`
- `GET /api/zfs/datasets/all` — All snapshot targets (pools, datasets, volumes)
- `GET /api/zfs/replication` — Replication jobs + the dashboard's SSH public key
- `POST /api/zfs/replication` — Create/update job `{source, host, user, port, target, recursive?, enabled?}`
- `POST /api/zfs/replication/test` — Test SSH + remote zfs `{host, user, port}`
- `POST /api/zfs/replication/<id>/run` — Run a job now (full or incremental)
- `POST /api/zfs/replication/key/regenerate` — Regenerate the replication keypair
- `DELETE /api/zfs/replication/<id>` — Delete a job

### Snapshot schedules (opt-in)
Automatic snapshots run only while an enabled schedule exists; the systemd timer
is enabled/disabled to match. Pruning only removes `autosnap_*` snapshots.
- `GET /api/snapshots/schedules` — List schedules + timer state
- `POST /api/snapshots/schedules` — Create/update `{dataset, recursive, enabled, keep{hourly,daily,weekly,monthly}}`
- `DELETE /api/snapshots/schedules/<dataset>` — Remove schedule (keeps existing snapshots)
- `POST /api/snapshots/schedules/<dataset>/run` — Run the schedule now

### LVM
Destructive ops are refused on anything backing a mounted filesystem (the
boot/root LVM); new PVs only on free disks.
- `GET /api/lvm` — PVs, VGs, LVs (with protection flags)
- `POST /api/lvm/pv` `{device}` — create PV · `/pv/resize` · `/pv/move {source, dest?}` · `/pv/remove {device}`
- `POST /api/lvm/vg` `{name, devices[]}` · `/vg/<name>/extend {device}` · `/vg/<name>/reduce {device}` · `DELETE /api/lvm/vg/<name>`
- `POST /api/lvm/lv` `{vg, name, size, fstype?}` · `/lv/<vg>/<name>/extend {size, resize_fs}` · `DELETE /api/lvm/lv/<vg>/<name>`

### MD RAID
Members must be free disks; arrays backing a mounted FS / pool / LVM are protected.
- `GET /api/mdadm/arrays` — List arrays (state, members, sync)
- `POST /api/mdadm/arrays` — Create `{name, level, devices[], spares[], persist}`
- `POST /api/mdadm/arrays/<dev>/device` — `{action: add|remove|fail, device}`
- `POST /api/mdadm/arrays/<dev>/stop` · `POST /api/mdadm/assemble` · `DELETE /api/mdadm/arrays/<dev>`

### iSCSI
All mutating iSCSI operations auto-save the LIO config (survives a
`target.service` restart).

- `GET /api/iscsi/targets` — List target IQNs
- `POST /api/iscsi/targets` — Create target `{iqn, access_mode}` where
  `access_mode` is `shared` (default; any initiator, for Proxmox/VMware clusters)
  or `restricted` (explicit ACLs only)
- `GET /api/iscsi/targets/<iqn>` — Target detail (LUNs, ACLs, portals, mode)
- `DELETE /api/iscsi/targets/<iqn>` — Delete target
- `POST /api/iscsi/targets/<iqn>/mode` — Set access mode `{mode: shared|restricted}`
- `GET /api/iscsi/backstores` — List backstores (with size + in-use status)
- `POST /api/iscsi/backstores` — Create backstore `{type, name, path, size}`
  (`type` fileio or block; a ZVOL is a block backstore at `/dev/zvol/<pool>/<vol>`)
- `DELETE /api/iscsi/backstores/<type>/<name>` — Delete backstore
- `POST /api/iscsi/luns` — Create LUN `{iqn, backstore_type, backstore_name, lun_id?}`
- `POST /api/iscsi/luns/delete` — Delete LUN `{iqn, lun}`
- `POST /api/iscsi/acls` — Create ACL `{iqn, initiator_iqn}`
- `POST /api/iscsi/acls/delete` — Delete ACL `{iqn, initiator_iqn}`
- `POST /api/iscsi/acls/chap` — Set/clear CHAP `{iqn, initiator_iqn, userid, password}` or `{…, clear:true}`
- `POST /api/iscsi/portals` — Create portal `{iqn, ip, port}`
- `POST /api/iscsi/portals/delete` — Delete portal `{iqn, ip, port}`
- `GET /api/iscsi/sessions` — Connected initiators per target (from configfs)
- `POST /api/iscsi/saveconfig` — Save config to disk (also done automatically)

### NFS
- `GET /api/nfs/exports` — List exports
- `POST /api/nfs/exports` — Create/replace export `{path, clients[{host, options}]}`
  (multiple clients supported; options e.g. `rw,sync,no_subtree_check,no_root_squash`)
- `DELETE /api/nfs/exports/<path>` — Remove export (also removes the directory if empty)
- `GET /api/nfs/exportfs` — Active exports (`exportfs -v`)
- `GET /api/nfs/clients` — Active client mounts (`showmount -a`)

### SMB
- `GET /api/smb/shares` — List shares
- `POST /api/smb/shares` — Create share `{name, path, ...}`
- `DELETE /api/smb/shares/<name>` — Remove share
- `POST /api/smb/users` — Create SMB user `{username, password}` (no password rules)
- `GET /api/smb/users` — List SMB users (with enabled/disabled state)
- `POST /api/smb/users/<u>/password` — Set password `{password}`
- `POST /api/smb/users/<u>/enable` | `/disable` — Toggle account
- `GET|POST /api/smb/groups`, `DELETE /api/smb/groups/<name>`, `POST /api/smb/groups/<name>/members {username, action}` — Groups for `@group` ACLs
- `GET|POST /api/smb/homes {enabled}` — One-click home-directory shares (`[homes]`)
- `GET /api/smb/shares` — List shares (with access-control + VFS flags)
- `POST /api/smb/shares` — Create/update a share (path, access control, VFS features)
- `POST /api/smb/shares/<name>/toggle` — Enable/disable a share
- `DELETE /api/smb/shares/<name>` — Remove a share
- `GET /api/smb/status` — Parsed sessions / share connections / open files
- `GET|POST /api/smb/global` — Global settings (workgroup, guest mapping,
  min protocol incl. SMB1, encryption, signing)

## File Structure

```
/opt/storage-dashboard/
├── app.py                    # Flask backend application
├── install.sh                # Automated installation script
├── install-prerequisites.sh  # Installs required apt packages
├── requirements.txt          # Python dependencies
├── auth.json                 # Credentials + session secret (0600, gitignored)
├── schedules.json            # Snapshot schedules (gitignored; absent until used)
├── certs/                    # TLS cert + key (gitignored; self-signed by default)
├── .gitignore
├── README.md
├── static/
│   └── css/
│       └── style.css         # Dark theme UI styles
├── templates/
│   └── index.html            # Single-page web application
└── venv/                     # Python virtual environment
```

Plus, installed outside the app directory:

```
/usr/local/sbin/storage-dashboard-locate-read     # root-owned read-only disk-locate helper
/usr/local/sbin/storage-dashboard-iscsi-sessions  # root-owned read-only iSCSI sessions helper
/usr/local/sbin/storage-dashboard-snap-fs         # root-owned snapshot browse/restore helper (path-confined)
/usr/local/sbin/storage-dashboard-netplan         # root-owned netplan apply helper (validates, restores on failure)
/usr/local/sbin/storage-dashboard-mount           # root-owned mount/umount + /etc/fstab helper (confines to /mnt|/media, nofail)
/etc/sudoers.d/storage-dashboard                  # passwordless sudo rules
/etc/systemd/system/storage-dashboard.service     # systemd unit
/etc/systemd/system/storage-dashboard-autosnap.{service,timer}   # auto-snapshots (disabled until used)
/etc/systemd/system/storage-dashboard-replicate.{service,timer}  # ZFS replication (disabled until used)
```

## Service Management

```bash
# View status
sudo systemctl status storage-dashboard

# View logs
sudo journalctl -u storage-dashboard -f

# Restart
sudo systemctl restart storage-dashboard

# Stop
sudo systemctl stop storage-dashboard
```

## Troubleshooting

**Check if the service is running:**
```bash
sudo systemctl status storage-dashboard
```

**Check logs for errors:**
```bash
sudo journalctl -u storage-dashboard --no-pager -n 50
```

**Test API directly** (HTTPS, self-signed → `-k`; most endpoints need auth):
```bash
curl -k https://localhost:8443/
```

**Check sudoers permissions (run as dashboard user):**
```bash
sudo -u dashboard sudo -n /usr/sbin/zpool list
```

**If ZFS module is not loaded:**
```bash
sudo modprobe zfs
```

**If targetcli fails with lockfile error:**
```bash
sudo rm -f /var/run/targetcli.lock
```

## License

MIT
