"""Plain-disk format & mount — validators, the partition-name helper, the
fstab-state reader, and the mountable-filesystem classifier.

These are the pure pieces of the feature. The privileged work (partitioning,
mkfs, mount/umount, fstab writes) goes through the root-owned
`storage-dashboard-mount` wrapper and is not exercised here.
"""
import json

import app


# ─── allowlists ───────────────────────────────────────────────────────

def test_mount_fstypes_allowlist():
    for fs in ('ext4', 'xfs', 'vfat', 'exfat'):
        assert fs in app.MOUNT_FSTYPES
    # Things we deliberately do NOT offer for formatting.
    for fs in ('ntfs', 'btrfs', 'zfs', 'swap', ''):
        assert fs not in app.MOUNT_FSTYPES


def test_mkfs_cfg_covers_every_fstype():
    assert set(app.MKFS_CFG) == app.MOUNT_FSTYPES
    for fs, cfg in app.MKFS_CFG.items():
        assert cfg['cmd'].startswith('mkfs.')
        assert cfg['label'] in ('-L', '-n')
        assert isinstance(cfg['labelmax'], int) and cfg['labelmax'] > 0
        assert cfg['ptype'] in ('8300', '0700')


def test_mount_bases_are_safe():
    assert app.MOUNT_BASES == ('/mnt', '/media')
    # never the obvious system roots
    for bad in ('/', '/etc', '/boot', '/usr', '/var'):
        assert bad not in app.MOUNT_BASES


def test_non_mountable_fstypes():
    for fs in ('zfs_member', 'LVM2_member', 'linux_raid_member', 'swap'):
        assert fs in app.NON_MOUNTABLE_FSTYPES


# ─── label / mount-name / uuid regexes ────────────────────────────────

def test_re_fslabel():
    for ok in ('backup', 'data_01', 'My.Disk-1', 'a' * 32):
        assert app.RE_FSLABEL.match(ok)
    for bad in ('', 'has space', 'a/b', 'lbl;rm', 'x\ny', 'a' * 33):
        assert not app.RE_FSLABEL.match(bad)


def test_re_mountname_blocks_traversal_and_slashes():
    for ok in ('data', 'usb-1', 'Backup_2026'):
        assert app.RE_MOUNTNAME.match(ok)
    for bad in ('', '../etc', 'a/b', '.hidden', '-flag', 'a b', 'x\n'):
        assert not app.RE_MOUNTNAME.match(bad)


def test_re_uuid():
    for ok in ('AAAA-BBBB', '12345678-1234-1234-1234-1234567890ab', 'A1B2'):
        assert app.RE_UUID.match(ok)
    for bad in ('', 'a/b', 'has space', 'x\ny', 'uuid;rm'):
        assert not app.RE_UUID.match(bad)


# ─── partition-name helper ────────────────────────────────────────────

def test_part1_name():
    assert app._part1_name('sdb') == 'sdb1'
    assert app._part1_name('sda') == 'sda1'
    assert app._part1_name('vda') == 'vda1'
    # devices whose name ends in a digit get the 'p1' form
    assert app._part1_name('nvme0n1') == 'nvme0n1p1'
    assert app._part1_name('mmcblk0') == 'mmcblk0p1'


# ─── managed-fstab reader ─────────────────────────────────────────────

def test_managed_fstab_uuids(tmp_path):
    fstab = tmp_path / 'fstab'
    fstab.write_text(
        "UUID=root-uuid / ext4 defaults 0 1\n"
        "# a comment\n"
        f"{app.FSTAB_MARK_BEGIN}\n"
        "UUID=managed-1 /mnt/data ext4 defaults,nofail 0 2\n"
        "UUID=managed-2 /media/usb vfat defaults,nofail 0 2\n"
        f"{app.FSTAB_MARK_END}\n"
    )
    got = app._managed_fstab_uuids(str(fstab))
    assert got == {'managed-1', 'managed-2'}
    # the unmanaged root entry is never reported
    assert 'root-uuid' not in got


def test_managed_fstab_uuids_missing_file(tmp_path):
    assert app._managed_fstab_uuids(str(tmp_path / 'nope')) == set()


# ─── mountable-filesystem classifier ──────────────────────────────────

def test_list_filesystems_classification(monkeypatch):
    tree = {"blockdevices": [
        {"name": "sda", "type": "disk", "fstype": None, "children": [
            {"name": "sda1", "type": "part", "fstype": "ext4", "mountpoint": "/",
             "label": None, "uuid": "root-uuid", "size": "50G"}]},
        {"name": "sdb", "type": "disk", "fstype": None, "children": [
            {"name": "sdb1", "type": "part", "fstype": "vfat", "mountpoint": None,
             "label": "USB", "uuid": "AAAA-BBBB", "size": "32G", "tran": "usb"}]},
        # a ZFS member must never be offered as a plain filesystem
        {"name": "sdc", "type": "disk", "fstype": "zfs_member", "mountpoint": None, "size": "1T"},
        # a dashboard-managed mount under /mnt is unmountable from the UI
        {"name": "sdd", "type": "disk", "fstype": "ext4", "mountpoint": "/mnt/data",
         "label": "data", "uuid": "data-uuid", "size": "2T"},
    ]}
    monkeypatch.setattr(app, 'run', lambda *a, **k: (json.dumps(tree), '', 0))
    monkeypatch.setattr(app, '_managed_fstab_uuids', lambda *a, **k: {'data-uuid'})

    fs = {f['name']: f for f in app._list_filesystems()}
    assert set(fs) == {'sda1', 'sdb1', 'sdd'}      # sdc (zfs_member) excluded

    # root filesystem: mounted, system, not unmountable
    assert fs['sda1']['mounted'] and fs['sda1']['system']
    assert not fs['sda1']['unmountable']

    # USB stick: a free, unmounted target ready to mount
    assert not fs['sdb1']['mounted']
    assert fs['sdb1']['tran'] == 'usb'
    assert not fs['sdb1']['system']

    # managed data disk: mounted under /mnt, unmountable, and flagged in fstab
    assert fs['sdd']['mounted'] and fs['sdd']['unmountable']
    assert not fs['sdd']['system']
    assert fs['sdd']['fstab'] is True
