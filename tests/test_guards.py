"""Protection-guard tests — these decide whether a destructive action is allowed.
A regression here is the difference between "safe" and "wiped the wrong disk" or
"demoted the last admin and locked everyone out." `disk_wipe_status` and the RBAC
helpers are pure functions, so we can assert their decisions directly.
"""
import app


# ── disk_wipe_status: only a free/stale disk may be wiped ──────────────────────

def _disk(name, fstype=None, mountpoint=None, dtype='disk', children=None):
    return {'name': name, 'fstype': fstype, 'mountpoint': mountpoint,
            'type': dtype, 'children': children or []}


def test_wipe_refuses_boot_disk():
    node = _disk('sda', children=[_disk('sda1', fstype='ext4', mountpoint='/', dtype='part')])
    r = app.disk_wipe_status(node, set(), {})
    assert r['wipeable'] is False
    assert 'boot' in r['reason']


def test_wipe_refuses_live_zfs_member():
    # zfs_member AND part of a currently-imported pool (in the pool map) -> protected.
    node = _disk('sdb', children=[_disk('sdb1', fstype='zfs_member', dtype='part')])
    r = app.disk_wipe_status(node, set(), {'sdb1': 'tank'})
    assert r['wipeable'] is False
    assert 'ZFS' in r['reason']


def test_wipe_allows_stale_zfs_label():
    # zfs_member signature left behind by `zpool destroy`/export (NOT in any live
    # pool) -> wipeable, like a stale md.
    node = _disk('nvme1n1', children=[_disk('nvme1n1p1', fstype='zfs_member', dtype='part'),
                                       _disk('nvme1n1p9', dtype='part')])
    r = app.disk_wipe_status(node, set(), {})   # empty pool map = no live pools
    assert r['wipeable'] is True
    assert app.disk_usage(node, {}, set()) == 'ZFS member (stale)'


def test_wipe_refuses_lvm_member():
    node = _disk('sdc', fstype='LVM2_member')
    r = app.disk_wipe_status(node, set(), {})
    assert r['wipeable'] is False
    assert 'LVM' in r['reason']


def test_wipe_refuses_mounted_nonboot():
    node = _disk('sdd', children=[_disk('sdd1', fstype='ext4', mountpoint='/mnt/data', dtype='part')])
    r = app.disk_wipe_status(node, set(), {})
    assert r['wipeable'] is False
    assert r['reason'] == 'mounted'


def test_wipe_refuses_active_raid_member():
    # Disk holds an md array that IS declared in mdadm.conf -> active, protected.
    node = _disk('sde', children=[_disk('md0', dtype='md')])
    r = app.disk_wipe_status(node, {'md0'}, {})
    assert r['wipeable'] is False
    assert 'RAID' in r['reason']


def test_wipe_allows_stale_raid_member():
    # Auto-assembled md, not in mdadm.conf, not in use -> wipeable, but record
    # which md to stop first.
    node = _disk('sdf', children=[_disk('md9', dtype='md')])
    r = app.disk_wipe_status(node, set(), {})
    assert r['wipeable'] is True
    assert r['md_stop'] == ['md9']


def test_wipe_allows_free_disk():
    node = _disk('sdg')
    r = app.disk_wipe_status(node, set(), {})
    assert r['wipeable'] is True
    assert r['md_stop'] == []


# ── _zfs_disk_usable: server-side guard for `zpool create/add -f` ──────────────

def test_zfs_disk_usable_rejects_inuse_allows_free_and_files(monkeypatch):
    import json
    trees = {
        '/dev/free':  {'blockdevices': [{'name': 'free', 'fstype': None, 'mountpoint': None, 'children': []}]},
        '/dev/inuse': {'blockdevices': [{'name': 'inuse', 'fstype': 'zfs_member', 'mountpoint': None, 'children': []}]},
        '/dev/bootd': {'blockdevices': [{'name': 'bootd', 'fstype': None, 'mountpoint': None,
                                         'children': [{'name': 'bootd1', 'fstype': 'ext4', 'mountpoint': '/boot', 'children': []}]}]},
        '/tmp/x.img': {'blockdevices': []},   # lsblk doesn't recognise it -> file vdev
    }
    monkeypatch.setattr(app, 'run', lambda args, **kw: (json.dumps(trees.get(args[-1], {'blockdevices': []})), '', 0))
    assert app._zfs_disk_usable('/dev/free') is True
    assert app._zfs_disk_usable('/dev/inuse') is False   # stale/active ZFS member
    assert app._zfs_disk_usable('/dev/bootd') is False   # mounted /boot
    assert app._zfs_disk_usable('/tmp/x.img') is True    # file vdev allowed
    assert app._zfs_disk_usable('bad;rm') is False       # fails RE_DISK


# ── RBAC helpers: role resolution + last-admin guard foundation ───────────────

def test_user_role_and_hash_legacy_and_record():
    # Legacy bare-hash string is treated as an admin.
    assert app._user_role('pbkdf2:sha256:...') == 'admin'
    assert app._user_hash('pbkdf2:sha256:abc') == 'pbkdf2:sha256:abc'
    # Modern record.
    assert app._user_role({'role': 'readonly'}) == 'readonly'
    assert app._user_role({'password': 'h'}) == 'admin'   # default when unset
    assert app._user_hash({'password': 'h'}) == 'h'
    # Missing record.
    assert app._user_role(None) == 'admin'


def test_count_admins_mixes_legacy_and_records():
    users = {
        'admin': {'role': 'admin', 'password': 'h'},
        'viewer': {'role': 'readonly', 'password': 'h'},
        'legacy': 'bare-hash-string',   # legacy == admin
    }
    assert app._count_admins(users) == 2


def test_count_admins_single():
    assert app._count_admins({'admin': {'role': 'admin'}}) == 1
    assert app._count_admins({'a': {'role': 'readonly'}}) == 0
