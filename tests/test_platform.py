"""Platform detection (Debian/Ubuntu vs RHEL/Rocky).

Pure-function tests over sample /etc/os-release text — no file access, no root.
"""
import app


UBUNTU_2404 = '''\
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
'''

ROCKY_9 = '''\
NAME="Rocky Linux"
VERSION="9.8 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.8"
PLATFORM_ID="platform:el9"
'''

ROCKY_10 = '''\
NAME="Rocky Linux"
VERSION="10.1 (Red Quartz)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="10.1"
PLATFORM_ID="platform:el10"
'''

DEBIAN_12 = '''\
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
ID=debian
'''

RHEL_9 = '''\
NAME="Red Hat Enterprise Linux"
VERSION="9.4 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.4"
'''

ALMA_9 = '''\
NAME="AlmaLinux"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
'''


def test_ubuntu_is_debian_family():
    p = app._platform_from_osrelease(UBUNTU_2404)
    assert p['family'] == 'debian'
    assert p['id'] == 'ubuntu'
    assert p['version'] == '24.04'


def test_debian_is_debian_family():
    assert app._platform_from_osrelease(DEBIAN_12)['family'] == 'debian'


def test_rocky9_is_rhel_family():
    p = app._platform_from_osrelease(ROCKY_9)
    assert p['family'] == 'rhel'
    assert p['id'] == 'rocky'
    assert p['version'] == '9.8'


def test_rocky10_is_rhel_family():
    p = app._platform_from_osrelease(ROCKY_10)
    assert p['family'] == 'rhel'
    assert p['version'] == '10.1'


def test_rhel_is_rhel_family():
    assert app._platform_from_osrelease(RHEL_9)['family'] == 'rhel'


def test_almalinux_is_rhel_family_via_id():
    assert app._platform_from_osrelease(ALMA_9)['family'] == 'rhel'


def test_unknown_defaults_to_debian():
    assert app._platform_from_osrelease('ID=plan9\n')['family'] == 'debian'
    assert app._platform_from_osrelease('')['family'] == 'debian'


def test_service_overrides_applied_for_rhel(monkeypatch):
    # The override table must rename Samba's unit and remap package names so a
    # RHEL build manages `smb`/`nfs-utils`/`targetcli`, not the Debian names.
    ov = app.SERVICE_OVERRIDES['rhel']
    assert ov['smb']['service'] == 'smb'
    assert ov['nfs']['pkg'] == 'nfs-utils'
    assert ov['iscsi']['pkg'] == 'targetcli'
    assert ov['zfs']['pkg'] == 'zfs'
