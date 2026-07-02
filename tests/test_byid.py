"""Stable device-identifier tests.

ZFS stores literal vdev paths, so a pool created from kernel names (nvme0n1, sda)
goes DEGRADED when those names get reordered across a reboot. These pure helpers
translate members to /dev/disk/by-id links (and detect pools that still use
kernel names), so a regression here re-introduces the reorder-fragility.
"""
import os
import app


# ── _disk_by_id_map: build kernel-name -> by-id link from a symlink dir ────────

def _make_by_id(tmp_path, links):
    """Create a fake /dev/disk/by-id dir: {link_name: target_basename}."""
    d = tmp_path / 'by-id'
    d.mkdir()
    for name, target in links.items():
        os.symlink('../../' + target, str(d / name))
    return str(d)


def test_by_id_map_basic(tmp_path):
    d = _make_by_id(tmp_path, {
        'nvme-Samsung_SSD_990_S1A2B3': 'nvme0n1',
        'wwn-0x5002538e40abc123': 'nvme0n1',
        'ata-WDC_WD40_WX12345': 'sda',
    })
    m = app._disk_by_id_map(d)
    # Descriptive serial-bearing id wins over bare wwn- for the same disk.
    assert m['nvme0n1'] == os.path.join(d, 'nvme-Samsung_SSD_990_S1A2B3')
    assert m['sda'] == os.path.join(d, 'ata-WDC_WD40_WX12345')


def test_by_id_map_skips_partition_links(tmp_path):
    d = _make_by_id(tmp_path, {
        'nvme-Samsung_SSD_990_S1A2B3': 'nvme0n1',
        'nvme-Samsung_SSD_990_S1A2B3-part1': 'nvme0n1p1',
    })
    m = app._disk_by_id_map(d)
    assert m == {'nvme0n1': os.path.join(d, 'nvme-Samsung_SSD_990_S1A2B3')}


def test_by_id_map_prefers_descriptive_over_wwn(tmp_path):
    d = _make_by_id(tmp_path, {
        'wwn-0x5002538e40abc123': 'sdb',
        'scsi-SATA_Seagate_Z1234': 'sdb',
    })
    assert app._disk_by_id_map(d)['sdb'].endswith('scsi-SATA_Seagate_Z1234')


def test_by_id_map_only_wwn_available(tmp_path):
    d = _make_by_id(tmp_path, {'wwn-0x5002538e40abc123': 'sdc'})
    assert app._disk_by_id_map(d)['sdc'].endswith('wwn-0x5002538e40abc123')


def test_by_id_map_missing_dir():
    assert app._disk_by_id_map('/nonexistent/by-id') == {}


# ── _resolve_stable_dev: member id -> stable path, with fallback ───────────────

def test_resolve_bare_name():
    m = {'nvme0n1': '/dev/disk/by-id/nvme-X'}
    assert app._resolve_stable_dev('nvme0n1', m) == ('/dev/disk/by-id/nvme-X', True)


def test_resolve_dev_path():
    m = {'sda': '/dev/disk/by-id/ata-X'}
    assert app._resolve_stable_dev('/dev/sda', m) == ('/dev/disk/by-id/ata-X', True)


def test_resolve_already_by_id_kept():
    assert app._resolve_stable_dev('/dev/disk/by-id/ata-X', {}) == ('/dev/disk/by-id/ata-X', True)


def test_resolve_fallback_when_no_link():
    # Loopback-file scratch pools / virtio disks without a serial: keep original.
    assert app._resolve_stable_dev('/tmp/scratch.img', {}) == ('/tmp/scratch.img', False)
    assert app._resolve_stable_dev('vdb', {}) == ('vdb', False)


# ── member path classification ─────────────────────────────────────────────────

def test_classify_stable():
    assert app._classify_member_path('/dev/disk/by-id/nvme-Samsung_S1') == 'stable'


def test_classify_kernel():
    for p in ('/dev/nvme0n1', '/dev/sda', '/dev/sdb1', '/dev/vdb', '/dev/dm-0'):
        assert app._classify_member_path(p) == 'kernel', p


def test_classify_other():
    # File vdevs and by-path/by-uuid are not flagged as reorder-unstable here.
    assert app._classify_member_path('/tmp/scratch.img') == 'other'
    assert app._classify_member_path('/dev/disk/by-path/pci-0000:00') == 'other'
