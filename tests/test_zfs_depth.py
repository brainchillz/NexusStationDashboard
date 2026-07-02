"""ZFS depth tests (plan 05) — pure logic only, no ZFS/root needed:
arcstats parsing (05b), the pool-create vdev spec builder (05e), and the
encryption allowlists (05a). Mirrors the existing pure-function test style.
"""
import pytest
import app


# ─── 05b — ARC stats ────────────────────────────────────────────────────

def test_parse_arcstats_skips_headers_and_type_column():
    sample = "\n".join([
        "13 1 0x01 98 26656 4319164516 137183176842",  # kstat header (many cols)
        "name                            type data",     # column header
        "hits                            4    1000",
        "misses                          4    250",
        "size                            4    1073741824",
        "c_max                           4    2147483648",
        "l2_size                         4    0",
        "garbage line",                                  # 2 cols -> skipped
    ])
    stats = app._parse_arcstats(sample)
    assert stats['hits'] == 1000            # value taken from col 3, not the type col
    assert stats['size'] == 1073741824
    assert 'garbage' not in stats and 'name' not in stats


def test_arc_summary_hit_ratio_and_l2():
    s = app._arc_summary({'hits': 750, 'misses': 250, 'size': 100, 'c_max': 200, 'l2_size': 0})
    assert s['hit_ratio'] == 75.0
    assert s['l2_present'] is False
    # No I/O yet -> ratio is None (no divide-by-zero); an L2ARC present flips the flag
    s2 = app._arc_summary({'hits': 0, 'misses': 0, 'l2_size': 500})
    assert s2['hit_ratio'] is None
    assert s2['l2_present'] is True


# ─── 05e — pool creation vdev spec ──────────────────────────────────────

def test_normalize_vdev_spec_legacy_and_structured():
    groups, e = app._normalize_vdev_spec({'vdev_type': 'mirror', 'disks': ['/dev/sda', '/dev/sdb']})
    assert e is None
    assert groups == [{'role': '', 'type': 'mirror', 'disks': ['/dev/sda', '/dev/sdb']}]
    groups2, e2 = app._normalize_vdev_spec({'vdevs': [
        {'role': '', 'type': 'mirror', 'disks': ['/dev/sda']},
        {'role': 'cache', 'disks': ['/dev/sdc']},
    ]})
    assert e2 is None
    assert groups2[1] == {'role': 'cache', 'type': '', 'disks': ['/dev/sdc']}


def test_pool_vdev_args_builds_full_command():
    groups = [
        {'role': '', 'type': 'mirror', 'disks': ['/dev/sda', '/dev/sdb']},
        {'role': '', 'type': 'mirror', 'disks': ['/dev/sdc', '/dev/sdd']},
        {'role': 'cache', 'type': '', 'disks': ['/dev/sde']},
        {'role': 'log', 'type': 'mirror', 'disks': ['/dev/sdf', '/dev/sdg']},
        {'role': 'spare', 'type': '', 'disks': ['/dev/sdh']},
    ]
    assert app._pool_vdev_args(groups) == [
        'mirror', '/dev/sda', '/dev/sdb', 'mirror', '/dev/sdc', '/dev/sdd',
        'cache', '/dev/sde', 'log', 'mirror', '/dev/sdf', '/dev/sdg',
        'spare', '/dev/sdh',
    ]


def test_pool_vdev_args_legacy_stripe_backcompat():
    # The old {vdev_type:'', disks:[...]} path must produce the same bare args.
    assert app._pool_vdev_args([{'role': '', 'type': '', 'disks': ['/dev/sda', '/dev/sdb']}]) == \
        ['/dev/sda', '/dev/sdb']


def test_pool_vdev_args_rejects_bad_spec():
    with pytest.raises(ValueError):
        app._pool_vdev_args([{'role': 'bogus', 'type': '', 'disks': ['/dev/sda']}])
    with pytest.raises(ValueError):
        app._pool_vdev_args([{'role': '', 'type': 'raidzX', 'disks': ['/dev/sda']}])
    with pytest.raises(ValueError):
        app._pool_vdev_args([{'role': 'cache', 'type': 'mirror', 'disks': ['/dev/sda']}])  # cache can't be mirror
    with pytest.raises(ValueError):
        app._pool_vdev_args([{'role': '', 'type': 'mirror', 'disks': []}])  # no disks


# ─── 05a — encryption allowlists ────────────────────────────────────────

def test_encryption_allowlists():
    assert 'aes-256-gcm' in app.ZFS_ENC_ALGOS
    assert 'passphrase' in app.ZFS_KEYFORMATS
    assert 'rot13' not in app.ZFS_ENC_ALGOS
    assert 'plaintext' not in app.ZFS_KEYFORMATS
