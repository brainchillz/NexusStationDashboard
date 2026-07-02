"""Feature-module toggle tests — load_disabled_modules filtering and the
module/id catalog. Disabling a module only hides it from the nav (no data risk),
but the persisted state must round-trip cleanly and ignore stale/unknown ids.
"""
import json
import app


def test_modules_catalog_ids_are_unique_and_known():
    ids = [m['id'] for m in app.MODULES]
    assert len(ids) == len(set(ids))            # no duplicates
    assert app.MODULE_IDS == set(ids)
    # Every module carries the fields the UI renders.
    for m in app.MODULES:
        assert m['id'] and m['label'] and m['category']


def test_load_disabled_missing_file_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(app, 'MODULES_FILE', str(tmp_path / 'nope.json'))
    assert app.load_disabled_modules() == set()


def test_load_disabled_reads_known_ids(tmp_path, monkeypatch):
    p = tmp_path / 'modules.json'
    p.write_text(json.dumps({'disabled': ['lvm', 'nfs']}))
    monkeypatch.setattr(app, 'MODULES_FILE', str(p))
    assert app.load_disabled_modules() == {'lvm', 'nfs'}


def test_load_disabled_ignores_unknown_and_bad_json(tmp_path, monkeypatch):
    p = tmp_path / 'modules.json'
    # 'bogus' is not a real module → must be dropped; real ids kept.
    p.write_text(json.dumps({'disabled': ['zfs', 'bogus']}))
    monkeypatch.setattr(app, 'MODULES_FILE', str(p))
    assert app.load_disabled_modules() == {'zfs'}

    p.write_text('{ this is not json')
    assert app.load_disabled_modules() == set()


def _fake_run_factory(active_map, enabled_state):
    """Build a fake run() that answers systemctl is-active/is-enabled from maps
    and reports no zpools, so _compute_alerts exercises only service logic."""
    def fake_run(args, **kw):
        if args[:1] == ['systemctl'] and 'is-active' in args:
            unit = args[-1]
            return (active_map.get(unit, 'inactive'), '', 0)
        if args[:1] == ['systemctl'] and 'is-enabled' in args:
            return (enabled_state, '', 0)
        if args[:1] == ['zpool']:
            return ('', '', 1)   # no pools
        return ('', '', 0)
    return fake_run


def test_alerts_suppressed_for_disabled_module(monkeypatch):
    # smbd inactive but the SMB *module* is disabled → no Samba alert.
    monkeypatch.setattr(app, 'run', _fake_run_factory({'zfs.target': 'active'}, 'enabled'))
    monkeypatch.setattr(app, 'load_disabled_modules', lambda: {'smb', 'iscsi', 'nfs'})
    monkeypatch.setattr(app, '_smart_health_ok', lambda: True)
    keys = {a['key'] for a in app._compute_alerts()}
    assert 'service:smb' not in keys
    assert 'service:nfs' not in keys


def test_alerts_suppressed_for_boot_disabled_unit(monkeypatch):
    # All services inactive AND disabled at boot → intentional, no alerts.
    monkeypatch.setattr(app, 'run', _fake_run_factory({}, 'disabled'))
    monkeypatch.setattr(app, 'load_disabled_modules', lambda: set())
    monkeypatch.setattr(app, '_smart_health_ok', lambda: True)
    assert app._compute_alerts() == []


def test_alerts_fire_for_enabled_inactive_service(monkeypatch):
    # Enabled but inactive (and module not disabled) → that IS an issue.
    monkeypatch.setattr(app, 'run', _fake_run_factory({'zfs.target': 'active'}, 'enabled'))
    monkeypatch.setattr(app, 'load_disabled_modules', lambda: set())
    monkeypatch.setattr(app, '_smart_health_ok', lambda: True)
    keys = {a['key'] for a in app._compute_alerts()}
    assert 'service:smb' in keys      # smbd inactive + enabled + module on
    assert 'service:zfs' not in keys  # zfs.target active


def test_service_keys_are_module_ids():
    # The dashboard hides a service line when its module is disabled; that filter
    # keys the SYSTEM_SERVICES dict by module id, so every service key must be a
    # real module id or it could never be filtered.
    assert set(app.SYSTEM_SERVICES) <= app.MODULE_IDS


def test_summary_drops_disabled_module_service(monkeypatch):
    # A disabled module must not appear in /api/summary's services block, even
    # though its unit may still be active (the Services page lists it separately).
    monkeypatch.setattr(app, 'run', _fake_run_factory(
        {s['service']: 'active' for s in app.SYSTEM_SERVICES.values()}, 'enabled'))
    monkeypatch.setattr(app, 'load_disabled_modules', lambda: {'smb'})
    with app.app.test_request_context():
        services = app.api_summary().get_json()['services']
    assert 'smb' not in services
    assert 'zfs' in services          # an enabled module is still listed
