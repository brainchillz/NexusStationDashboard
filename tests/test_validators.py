"""Input-validation tests — the command-injection / config-injection defense.

These regexes and helper validators gate every user-supplied value before it
reaches a system command or a config file. A change that loosens one of these
opens a hole; these tests fail loudly if that happens.
"""
import app


def test_re_pool_accepts_normal_names():
    assert app.RE_POOL.match('tank')
    assert app.RE_POOL.match('Flash')
    assert app.RE_POOL.match('pool_1.bak-2')


def test_re_pool_rejects_injection_and_flags():
    assert not app.RE_POOL.match('')            # empty
    assert not app.RE_POOL.match('-R')          # looks like a flag (arg injection)
    assert not app.RE_POOL.match('tank/ds')     # '/' is not a pool char
    assert not app.RE_POOL.match('a b')         # space
    assert not app.RE_POOL.match('tank;rm -rf') # shell metachar
    assert not app.RE_POOL.match('tank\nx')     # newline


def test_re_dataset_vs_snap():
    assert app.RE_DATASET.match('tank/data/sub')
    assert not app.RE_DATASET.match('tank/data@snap')   # '@' belongs to a snapshot
    assert app.RE_SNAP.match('tank/data@snap1')
    assert app.RE_SNAP.match('tank/data@autosnap_daily_2026-06-22')
    assert not app.RE_SNAP.match('tank/data')           # no '@'
    assert not app.RE_SNAP.match('tank/data@a@b')       # second '@'


def test_re_path_blocks_newline_injection():
    # The big one: a newline in an NFS export path would inject lines into
    # /etc/exports.
    assert app.RE_PATH.match('/srv/nfs/share')
    assert app.RE_PATH.match('/etc/exports')
    assert not app.RE_PATH.match('relative/path')                 # must be absolute
    assert not app.RE_PATH.match('/srv/x\n/evil *(rw)')           # newline injection
    assert not app.RE_PATH.match('/srv/x\r/evil')                 # carriage return
    assert not app.RE_PATH.match('/srv/\x00')                     # NUL


def test_re_nfsopts_allowlist():
    assert app.RE_NFSOPTS.match('rw,sync,no_root_squash')
    assert app.RE_NFSOPTS.match('ro,sync,no_subtree_check')
    assert not app.RE_NFSOPTS.match('rw,sync\nfoo')   # newline -> exports injection
    assert not app.RE_NFSOPTS.match('rw 2')           # space
    assert not app.RE_NFSOPTS.match('rw;reboot')      # metachar


def test_re_host_allows_wildcards_and_subnets():
    assert app.RE_HOST.match('*')
    assert app.RE_HOST.match('192.168.1.0/24')
    assert app.RE_HOST.match('10.0.0.5')
    assert app.RE_HOST.match('host.example.com')
    assert not app.RE_HOST.match('host;rm')
    assert not app.RE_HOST.match('a b')


def test_re_iqn_and_size_and_mddev():
    assert app.RE_IQN.match('iqn.2025-01.com.example:target1')
    assert not app.RE_IQN.match('iqn target')
    assert app.RE_SIZE.match('64M')
    assert app.RE_SIZE.match('10GB')
    assert not app.RE_SIZE.match('10GiB')   # 'i' not allowed by RE_SIZE
    assert not app.RE_SIZE.match('big')
    assert app.RE_MDDEV.match('md0')
    assert app.RE_MDDEV.match('md127')
    assert not app.RE_MDDEV.match('md')     # needs a number
    assert not app.RE_MDDEV.match('sda')


def test_valid_endpoint():
    assert app._valid_endpoint('192.168.34.88', 'otnops', 22) is None
    assert app._valid_endpoint('host.local', 'backup', '2222') is None
    assert app._valid_endpoint('a b', 'otnops', 22) == 'Invalid host'
    assert app._valid_endpoint('192.168.34.88', '', 22) == 'Invalid remote user'
    assert app._valid_endpoint('192.168.34.88', 'otnops', 0) == 'Invalid port'
    assert app._valid_endpoint('192.168.34.88', 'otnops', 70000) == 'Invalid port'
    assert app._valid_endpoint('192.168.34.88', 'otnops', 'xx') == 'Invalid port'


def test_valid_relpath_blocks_traversal():
    assert app._valid_relpath('') is True
    assert app._valid_relpath('.') is True
    assert app._valid_relpath('docs/report.txt') is True
    assert app._valid_relpath('/etc/passwd') is False          # absolute escape
    assert app._valid_relpath('../../etc/passwd') is False     # traversal
    assert app._valid_relpath('a/../../b') is False            # embedded traversal
    assert app._valid_relpath('a\nb') is False                 # newline


def test_split_snap():
    assert app._split_snap('tank/data@s1') == ('tank/data', 's1')
    assert app._split_snap('tank/data') == (None, None)        # no '@'
    assert app._split_snap('bad name@s1') == (None, None)      # invalid chars
