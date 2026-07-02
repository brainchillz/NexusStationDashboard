"""Parser tests — these turn raw command/file output into the structures the UI
and the destructive endpoints rely on. A parsing bug shows wrong (or dangerous)
information, so pin the behavior against known-good sample output.
"""
import app


def test_size_to_bytes_and_human():
    assert app._size_to_bytes('64.0MiB') == 64 * 1024 * 1024
    assert app._size_to_bytes('1K') == 1024
    assert app._size_to_bytes('2G') == 2 * 1024 ** 3
    assert app._size_to_bytes('0') == 0
    assert app._size_to_bytes('garbage') == 0
    assert app._size_to_bytes('') == 0
    assert app._human_bytes(0) == '0B'
    assert app._human_bytes(1024) == '1.0K'
    assert app._human_bytes(1536) == '1.5K'
    assert app._human_bytes(1024 ** 3) == '1.0G'


def test_parse_exports(tmp_path):
    f = tmp_path / 'exports'
    f.write_text(
        '# a comment\n'
        '\n'
        '/srv/nfs/a 192.168.1.0/24(rw,sync) 10.0.0.5(ro,sync)\n'
        '/srv/nfs/b *(rw,no_root_squash)\n'
    )
    exports = app.parse_exports(str(f))
    assert len(exports) == 2
    a = exports[0]
    assert a['path'] == '/srv/nfs/a'
    assert len(a['clients']) == 2
    assert a['clients'][0] == {'host': '192.168.1.0/24', 'options': 'rw,sync'}
    assert a['clients'][1] == {'host': '10.0.0.5', 'options': 'ro,sync'}
    assert exports[1]['clients'][0] == {'host': '*', 'options': 'rw,no_root_squash'}


def test_parse_exports_missing_file():
    assert app.parse_exports('/nonexistent/exports/file') == []


def test_parse_targets():
    out = (
        'o- iscsi ............ [Targets: 1]\n'
        '  o- iqn.2025-01.com.example:t1 ... [TPGs: 1]\n'
        '    o- tpg1 ......... [gen-acls]\n'
    )
    assert app.parse_targets(out) == ['iqn.2025-01.com.example:t1']


def test_parse_tpg():
    out = (
        'o- tpg1 ................ [no-gen-acls]\n'
        '  o- acls ............. [ACLs: 1]\n'
        '  | o- iqn.1993-08.org.debian:01:e2e [Mapped LUNs: 1]\n'
        '  o- luns ............. [LUNs: 1]\n'
        '  | o- lun0 .......... [block/disk1 (/dev/sdb) (default_tg_pt_gp)]\n'
        '  o- portals .......... [Portals: 1]\n'
        '    o- 0.0.0.0:3260 ... [OK]\n'
    )
    res = app.parse_tpg(out)
    assert res['acls'] == [{'initiator': 'iqn.1993-08.org.debian:01:e2e'}]
    assert res['luns'][0]['lun'] == 'lun0'
    assert 'block/disk1' in res['luns'][0]['backstore']
    assert res['portals'] == [{'ip': '0.0.0.0', 'port': '3260', 'portal': '0.0.0.0:3260'}]


def test_parse_backstores_in_use_flag():
    out = (
        'o- backstores .......... [...]\n'
        '  o- block ............. [Storage Objects: 1]\n'
        '  | o- disk1 .......... [/dev/sdb (1.0GiB) write-thru activated]\n'
        '  o- fileio ............ [Storage Objects: 1]\n'
        '  | o- file1 .......... [/tmp/f.img (64.0MiB) write-back deactivated]\n'
    )
    bs = {b['name']: b for b in app.parse_backstores(out)}
    assert bs['disk1']['type'] == 'block'
    assert bs['disk1']['size'] == '1.0GiB'
    assert bs['disk1']['in_use'] is True
    # 'deactivated' contains the substring 'activated' — must NOT be read as in-use.
    assert bs['file1']['size'] == '64.0MiB'
    assert bs['file1']['in_use'] is False


def test_parse_mdadm_detail():
    out = (
        '/dev/md0:\n'
        '        Raid Level : raid1\n'
        '        Array Size : 1046528 (1022.00 MiB 1071.64 MB)\n'
        '             State : clean\n'
        '      Raid Devices : 2\n'
        '     Active Devices : 2\n'
        '     Failed Devices : 0\n'
        '      Spare Devices : 1\n'
        '    Number   Major   Minor   RaidDevice State\n'
        '       0       7        0        0      active sync   /dev/loop0\n'
        '       1       7        1        1      active sync   /dev/loop1\n'
        '       2       7        2        -      spare         /dev/loop2\n'
    )
    info = app.parse_mdadm_detail(out)
    assert info['level'] == 'raid1'
    assert info['size'] == '1046528'          # the '(...)' suffix is stripped
    assert info['state'] == 'clean'
    assert info['raid_devices'] == '2'
    assert info['spare'] == '1'
    assert len(info['devices']) == 3
    assert info['devices'][0] == {'number': '0', 'state': 'active sync', 'device': '/dev/loop0'}
    assert info['devices'][2]['state'] == 'spare'


def test_parse_importable():
    out = (
        '   pool: tank\n'
        '     id: 1234567890123456789\n'
        '  state: ONLINE\n'
        ' status: Some supported features are not enabled.\n'
        ' action: The pool can be imported using its name or numeric identifier.\n'
        ' config:\n'
        '        tank        ONLINE\n'
        '\n'
        '   pool: backup\n'
        '     id: 9876543210987654321\n'
        '  state: DEGRADED\n'
    )
    pools = app._parse_importable(out)
    assert len(pools) == 2
    assert pools[0]['name'] == 'tank'
    assert pools[0]['id'] == '1234567890123456789'
    assert pools[0]['state'] == 'ONLINE'
    assert pools[1]['name'] == 'backup'
    assert pools[1]['state'] == 'DEGRADED'


def test_smbconf_render_is_parseable(monkeypatch, tmp_path):
    sections = {
        'global': {'workgroup': 'WORKGROUP', 'server min protocol': 'SMB2'},
        'data': {'path': '/srv/data', 'read only': 'no'},
    }
    rendered = app.smbconf_render(sections)
    assert '[global]' in rendered
    assert 'workgroup = WORKGROUP' in rendered
    assert '[data]' in rendered

    # Round-trip: render -> file -> parse should recover the sections/keys.
    conf = tmp_path / 'smb.conf'
    conf.write_text(rendered)
    monkeypatch.setattr(app, 'SMBCONF_FILE', str(conf))
    parsed = app.smbconf_parse()
    assert parsed['global']['workgroup'] == 'WORKGROUP'
    assert parsed['data']['path'] == '/srv/data'
    assert parsed['data']['read only'] == 'no'
