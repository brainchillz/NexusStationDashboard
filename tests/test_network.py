"""Network module pure-function tests: IPv4/CIDR validation and netplan YAML
rendering. The apply/auto-revert path shells out to netplan and is tested live
against the disposable VM, not here.
"""
import time

import app


def test_valid_ipv4():
    assert app._valid_ipv4('192.168.1.1')
    assert app._valid_ipv4('10.0.0.255')
    assert app._valid_ipv4('0.0.0.0')
    assert not app._valid_ipv4('256.0.0.1')      # octet > 255
    assert not app._valid_ipv4('192.168.1')      # too few octets
    assert not app._valid_ipv4('192.168.1.1.1')  # too many
    assert not app._valid_ipv4('1.1.1.-1')
    assert not app._valid_ipv4('a.b.c.d')
    assert not app._valid_ipv4('')


def test_valid_cidr():
    assert app._valid_cidr('192.168.1.50/24')
    assert app._valid_cidr('10.0.0.1/8')
    assert app._valid_cidr('1.2.3.4/32')
    assert not app._valid_cidr('192.168.1.50')     # no prefix
    assert not app._valid_cidr('192.168.1.50/33')  # prefix > 32
    assert not app._valid_cidr('999.1.1.1/24')     # bad ip
    assert not app._valid_cidr('192.168.1.0/')     # empty prefix


def test_hostname_and_domain_regexes():
    assert app.RE_HOST_LABEL.match('silo')
    assert app.RE_HOST_LABEL.match('node-01')
    assert not app.RE_HOST_LABEL.match('bad host')   # space
    assert not app.RE_HOST_LABEL.match('-leading')   # leading hyphen
    assert not app.RE_HOST_LABEL.match('has.dot')    # dot not allowed in a label
    assert app.RE_DOMAIN.match('example.net')
    assert app.RE_DOMAIN.match('a.b.c.example.com')
    assert not app.RE_DOMAIN.match('bad_domain!')


def test_render_netplan_dhcp():
    yaml = app.render_netplan({'ethernets': {'ens18': {'dhcp4': True}}, 'bridges': {}})
    assert 'network:' in yaml
    assert 'version: 2' in yaml
    assert 'ens18:' in yaml
    assert 'dhcp4: true' in yaml
    assert 'addresses:' not in yaml


def test_render_netplan_static_with_gateway_and_dns():
    conf = {'ethernets': {'ens18': {'dhcp4': False, 'addresses': ['192.168.34.50/24'],
                                     'gateway': '192.168.34.1', 'nameservers': ['1.1.1.1', '8.8.8.8']}},
            'bridges': {}}
    yaml = app.render_netplan(conf)
    assert 'dhcp4: false' in yaml
    assert '- 192.168.34.50/24' in yaml
    assert 'to: default' in yaml
    assert 'via: 192.168.34.1' in yaml
    assert 'addresses: [1.1.1.1, 8.8.8.8]' in yaml


def test_render_netplan_bridge():
    conf = {'ethernets': {'ens18': {'dhcp4': False}},
            'bridges': {'br0': {'dhcp4': False, 'interfaces': ['ens18'],
                                'addresses': ['10.0.0.5/24'], 'gateway': '10.0.0.1'}}}
    yaml = app.render_netplan(conf)
    assert 'bridges:' in yaml
    assert 'br0:' in yaml
    assert 'interfaces: [ens18]' in yaml
    assert '- 10.0.0.5/24' in yaml


def test_render_netplan_is_idempotent():
    # Rendering must not mutate the input config — render twice, identical output.
    conf = {'ethernets': {'e': {'dhcp4': False, 'addresses': ['1.2.3.4/24']}}, 'bridges': {}}
    first = app.render_netplan(conf)
    second = app.render_netplan(conf)
    assert first == second
    assert '_addr_header' not in conf['ethernets']['e']


# ─── _build_static_spec (multiple addresses per interface) ────────────────

def test_build_static_spec_multiple_addresses():
    spec, e = app._build_static_spec(
        {'addresses': ['192.168.1.10/24', '10.0.0.5/24'], 'gateway': '192.168.1.1'},
        {'dhcp4': False})
    assert e is None
    assert spec['addresses'] == ['192.168.1.10/24', '10.0.0.5/24']
    assert spec['gateway'] == '192.168.1.1'  # one default gateway regardless of IP count


def test_build_static_spec_dedupes_and_skips_blanks():
    spec, e = app._build_static_spec(
        {'addresses': ['192.168.1.10/24', '', '192.168.1.10/24', '10.0.0.5/24']}, {'dhcp4': False})
    assert e is None
    assert spec['addresses'] == ['192.168.1.10/24', '10.0.0.5/24']


def test_build_static_spec_back_compat_single_address():
    spec, e = app._build_static_spec({'address': '172.16.0.9/24'}, {'dhcp4': False})
    assert e is None
    assert spec['addresses'] == ['172.16.0.9/24']


def test_build_static_spec_requires_at_least_one():
    with app.app.test_request_context():
        spec, e = app._build_static_spec({'addresses': ['', '  ']}, {'dhcp4': False})
    assert spec is None and e is not None


def test_build_static_spec_rejects_bad_cidr():
    with app.app.test_request_context():
        spec, e = app._build_static_spec({'addresses': ['not-a-cidr']}, {'dhcp4': False})
    assert spec is None and e is not None


def test_render_netplan_dhcp_plus_static_coexist():
    # The dual phase needs a DHCP lease and an extra static address at once.
    yaml = app.render_netplan(
        {'ethernets': {'e': {'dhcp4': True, 'addresses': ['1.2.3.4/24']}}, 'bridges': {}})
    assert 'dhcp4: true' in yaml
    assert '- 1.2.3.4/24' in yaml


def test_render_netplan_multiple_addresses():
    yaml = app.render_netplan(
        {'ethernets': {'e': {'dhcp4': False, 'addresses': ['1.2.3.4/24', '5.6.7.8/24']}},
         'bridges': {}})
    assert '- 1.2.3.4/24' in yaml
    assert '- 5.6.7.8/24' in yaml


# ─── _net_union_spec (transitional dual config) ───────────────────────────

def test_union_static_to_static_keeps_both_and_old_gateway():
    prev = {'dhcp4': False, 'addresses': ['192.168.1.10/24'], 'gateway': '192.168.1.1'}
    target = {'dhcp4': False, 'addresses': ['192.168.1.50/24'], 'gateway': '192.168.1.254'}
    dual = app._net_union_spec(prev, target)
    assert dual['dhcp4'] is False
    assert dual['addresses'] == ['192.168.1.10/24', '192.168.1.50/24']
    assert dual['gateway'] == '192.168.1.1'  # OLD gateway kept until finalize


def test_union_dhcp_to_static_adds_static_over_dhcp():
    dual = app._net_union_spec({'dhcp4': True}, {'dhcp4': False, 'addresses': ['10.0.0.9/24']})
    assert dual['dhcp4'] is True             # keep the old DHCP lease alive
    assert dual['addresses'] == ['10.0.0.9/24']
    assert 'gateway' not in dual


def test_union_does_not_relist_dhcp_lease_as_static():
    # The old side is DHCP with a leased address — that address must NOT be
    # carried into the dual spec as a static (dhcp4 re-acquires it).
    old = {'dhcp4': True, 'addresses': ['192.168.34.88/23']}
    dual = app._net_union_spec(old, {'dhcp4': False, 'addresses': ['192.168.34.200/23']})
    assert dual['dhcp4'] is True
    assert dual['addresses'] == ['192.168.34.200/23']  # only the new static


def test_union_static_to_dhcp_keeps_old_static_but_drops_manual_gateway():
    # When DHCP is on, it supplies the default route — we must NOT also emit the
    # old static gateway (a duplicate default route). The old ADDRESS is kept so
    # the admin still reaches the box on its current subnet.
    prev = {'dhcp4': False, 'addresses': ['10.0.0.5/24'], 'gateway': '10.0.0.1'}
    dual = app._net_union_spec(prev, {'dhcp4': True})
    assert dual['dhcp4'] is True
    assert dual['addresses'] == ['10.0.0.5/24']
    assert 'gateway' not in dual


def test_union_dhcp_to_dhcp_has_no_static():
    dual = app._net_union_spec({'dhcp4': True}, {'dhcp4': True})
    assert dual['dhcp4'] is True
    assert 'addresses' not in dual


def test_union_falls_back_to_live_spec_when_unmanaged():
    # No dashboard-managed prev → use the live state so the real current IP is
    # preserved alongside the new one.
    live = {'dhcp4': False, 'addresses': ['172.16.0.2/24'], 'gateway': '172.16.0.1'}
    dual = app._net_union_spec(None, {'dhcp4': False, 'addresses': ['172.16.0.9/24']}, live)
    assert dual['addresses'] == ['172.16.0.2/24', '172.16.0.9/24']
    assert dual['gateway'] == '172.16.0.1'


# ─── handoff token store ──────────────────────────────────────────────────

def _reset_handoff(phase='dual'):
    app._net_handoffs.clear()
    app._net_pending['phase'] = phase


def test_handoff_consume_valid_single_use():
    _reset_handoff('dual')
    secret = 'sd-handoff-test'
    app._net_handoffs[app._hash_token(secret)] = {
        'user': 'admin', 'role': 'admin', 'exp': time.time() + 120, 'used': False}
    rec = app._consume_handoff(secret)
    assert rec and rec['user'] == 'admin'
    assert app._consume_handoff(secret) is None  # single-use
    _reset_handoff(None)


def test_handoff_consume_expired():
    _reset_handoff('dual')
    secret = 'expired'
    app._net_handoffs[app._hash_token(secret)] = {
        'user': 'admin', 'role': 'admin', 'exp': time.time() - 1, 'used': False}
    assert app._consume_handoff(secret) is None
    _reset_handoff(None)


def test_handoff_invalid_without_pending_change():
    _reset_handoff(None)
    secret = 'orphan'
    app._net_handoffs[app._hash_token(secret)] = {
        'user': 'admin', 'role': 'admin', 'exp': time.time() + 120, 'used': False}
    assert app._consume_handoff(secret) is None


def test_handoff_rejects_unknown_secret():
    _reset_handoff('dual')
    assert app._consume_handoff('nope') is None
    assert app._consume_handoff('') is None
    _reset_handoff(None)
