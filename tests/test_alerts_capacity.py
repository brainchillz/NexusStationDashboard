"""Capacity / degraded-array alert helpers — pure parsing + thresholds for the
new filesystem-full, LVM (full / missing PV), and MD-degraded alerts.
"""
import app


def test_df_use_pct_matches_df_semantics():
    # 100 blocks, 10 free-to-root, 5 available-to-user -> used 90, avail 5 -> 95%
    assert app._df_use_pct(100, 10, 5) == 95
    assert app._df_use_pct(100, 100, 100) == 0      # empty
    assert app._df_use_pct(0, 0, 0) == 0            # no blocks -> no div-by-zero


def test_real_mounts_filters_pseudo_and_dupes():
    text = (
        "sysfs /sys sysfs rw 0 0\n"
        "proc /proc proc rw 0 0\n"
        "tmpfs /run tmpfs rw 0 0\n"
        "/dev/sda1 / ext4 rw,relatime 0 0\n"
        "/dev/sda2 /boot ext4 rw 0 0\n"
        "tank /tank zfs rw 0 0\n"                  # zfs covered separately
        "/dev/loop0 /snap/x squashfs ro 0 0\n"
        "/dev/sda1 / ext4 rw 0 0\n"                # duplicate mountpoint
    )
    mounts = app._real_mounts(text)
    paths = [m[0] for m in mounts]
    assert paths == ['/', '/boot']                  # only real, deduped, no zfs/pseudo


def test_real_mounts_unescapes_spaces():
    text = "/dev/sdb1 /mnt/my\\040disk ext4 rw 0 0\n"
    assert app._real_mounts(text)[0][0] == '/mnt/my disk'


def test_parse_mdstat_detects_degraded():
    healthy = "md0 : active raid1 sdb1[1] sda1[0]\n      1046528 blocks super 1.2 [2/2] [UU]\n"
    degraded = "md1 : active raid1 sdd1[2] sdc1[0]\n      1046528 blocks super 1.2 [2/1] [U_]\n"
    faulty = "md2 : active raid1 sde1[1](F) sdf1[0]\n      1046528 blocks super 1.2 [2/2] [UU]\n"
    assert app._parse_mdstat(healthy)[0]['degraded'] is False
    assert app._parse_mdstat(degraded)[0]['degraded'] is True
    assert app._parse_mdstat(faulty)[0]['degraded'] is True
    assert app._parse_mdstat("Personalities : [raid1]\n") == []


def test_lvm_alerts_only_missing_pv(monkeypatch):
    # A fully-allocated VG (vg_free 0) is NORMAL and must not alert; only a
    # missing PV (failed disk) does.
    monkeypatch.setattr(app, '_lvm_report', lambda tool, fields: [
        {'vg_name': 'ubuntu-vg', 'vg_missing_pv_count': '0'},   # 100% allocated, healthy
        {'vg_name': 'broken', 'vg_missing_pv_count': '1'},      # failed/removed disk
    ])
    keys = {a['key'] for a in app._lvm_alerts()}
    assert keys == {'lvm_pv:broken'}
