"""Feature 08 — log viewer helpers.

Pure tests for the curated log-source resolution and the grep/priority allowlists
that keep client input from becoming a journalctl flag or an arbitrary unit.
"""
import app


def test_log_grep_allowlist():
    ok = ['error', 'zfs pool', 'a.b:c/d=e,f+g-h', 'UPPER lower 123', '']
    bad = ['has\nnewline', 'semi;colon', 'x' * 121, 'back`tick', 'pipe|x']
    for s in ok:
        assert app.RE_LOG_GREP.match(s), s
    for s in bad:
        assert not app.RE_LOG_GREP.match(s), s


def test_log_priorities():
    assert app.LOG_PRIORITIES == {'0', '1', '2', '3', '4', '5', '6', '7'}


def test_log_sources_include_dashboard_services_tasks():
    ids = {s['id'] for s in app._log_sources()}
    assert 'dashboard' in ids
    assert 'svc:zfs' in ids            # a system service
    assert 'task:history' in ids       # a managed task
    # every source has a non-empty unit
    assert all(s['unit'] for s in app._log_sources())


def test_log_unit_for_known_and_unknown():
    assert app._log_unit_for('svc:smb') == app.SYSTEM_SERVICES['smb']['service']
    assert app._log_unit_for('task:alerts') == 'storage-dashboard-alerts.service'
    assert app._log_unit_for('bogus') is None
    assert app._log_unit_for('') is None


def test_own_unit_fallback(monkeypatch):
    # No cgroup readable -> sane default
    def boom(*a, **k):
        raise OSError('nope')
    monkeypatch.setattr('builtins.open', boom)
    assert app._own_unit() == 'storage-dashboard.service'


def test_web_manifest_is_public():
    assert 'web_manifest' in app.PUBLIC_ENDPOINTS
