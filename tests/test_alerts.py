"""Tests for alerting + maintenance pure helpers: notification config validation
and the maintenance due-date logic. _compute_alerts itself shells out, so it is
left for integration testing; here we cover the decision/validation logic.
"""
from datetime import datetime, timedelta
import app


def test_validate_notifications_ok():
    cfg, errmsg = app._validate_notifications({
        'email': {'enabled': True, 'host': 'smtp.example.com', 'port': 587,
                  'security': 'starttls', 'to': 'me@example.com', 'from': 'a@b.co'},
        'webhook': {'enabled': True, 'url': 'https://hooks.example.com/x'},
    })
    assert errmsg is None
    assert cfg['email']['host'] == 'smtp.example.com'


def test_validate_notifications_rejects_bad_inputs():
    assert app._validate_notifications({'email': {'enabled': True, 'host': 'bad host',
                                                   'port': 587, 'to': 'me@x.co'}})[1] == 'Invalid SMTP host'
    assert app._validate_notifications({'email': {'enabled': True, 'host': 'smtp.x.co',
                                                   'port': 0, 'to': 'me@x.co'}})[1] == 'Invalid SMTP port'
    assert app._validate_notifications({'email': {'enabled': True, 'host': 'smtp.x.co',
                                                   'port': 587, 'to': 'notanemail'}})[1] == 'Invalid recipient address'
    assert 'http' in app._validate_notifications({'webhook': {'enabled': True, 'url': 'ftp://x'}})[1]


def test_validate_notifications_ignores_disabled_channels():
    # Garbage in a disabled channel is fine — it's not used.
    cfg, errmsg = app._validate_notifications({
        'email': {'enabled': False, 'host': 'whatever'},
        'webhook': {'enabled': False, 'url': 'not-a-url'},
    })
    assert errmsg is None


def test_notifications_enabled():
    assert app._notifications_enabled({'email': {'enabled': True}, 'webhook': {}}) is True
    assert app._notifications_enabled({'email': {}, 'webhook': {'enabled': True}}) is True
    assert app._notifications_enabled({'email': {}, 'webhook': {}}) is False


def test_alerts_tick_dedups_and_resolves(tmp_path, monkeypatch):
    """The notifier must fire once per new condition, stay quiet while it
    persists, and send a RESOLVED when it clears."""
    nf = tmp_path / 'notifications.json'
    nf.write_text('{"email":{},"webhook":{"enabled":true,"url":"http://x"},"state":{}}')
    monkeypatch.setattr(app, 'NOTIFICATIONS_FILE', str(nf))

    sent = []
    monkeypatch.setattr(app, '_notify', lambda cfg, kind, msg: sent.append((kind, msg)) or [])

    alerts = [{'key': 'zfs_full:tank', 'message': 'ZFS pool tank is 95% full'}]
    monkeypatch.setattr(app, '_compute_alerts', lambda: alerts)

    app.cli_alerts_tick()                       # new condition -> ALERT
    assert sent == [('ALERT', 'ZFS pool tank is 95% full')]

    app.cli_alerts_tick()                       # same condition -> nothing (de-dup)
    assert len(sent) == 1

    monkeypatch.setattr(app, '_compute_alerts', lambda: [])
    app.cli_alerts_tick()                       # condition cleared -> RESOLVED
    assert sent[-1] == ('RESOLVED', 'ZFS pool tank is 95% full')
    assert len(sent) == 2


def test_alerts_tick_silent_when_disabled(tmp_path, monkeypatch):
    nf = tmp_path / 'notifications.json'
    nf.write_text('{"email":{},"webhook":{},"state":{}}')   # no channel enabled
    monkeypatch.setattr(app, 'NOTIFICATIONS_FILE', str(nf))
    sent = []
    monkeypatch.setattr(app, '_notify', lambda cfg, kind, msg: sent.append((kind, msg)) or [])
    monkeypatch.setattr(app, '_compute_alerts', lambda: [{'key': 'smart', 'message': 'SMART failure'}])
    app.cli_alerts_tick()
    assert sent == []                            # disabled -> never sends
    # ...but state is still tracked so enabling later doesn't double-fire history.
    import json
    assert json.load(open(nf))['state'] == {'smart': 'SMART failure'}


def test_maint_due():
    now = datetime.now()
    # Never run -> due.
    assert app._maint_due('', 'weekly') is True
    # Ran 8 days ago, weekly -> due.
    assert app._maint_due((now - timedelta(days=8)).isoformat(), 'weekly') is True
    # Ran 2 days ago, weekly -> not due.
    assert app._maint_due((now - timedelta(days=2)).isoformat(), 'weekly') is False
    # Ran 40 days ago, monthly -> due.
    assert app._maint_due((now - timedelta(days=40)).isoformat(), 'monthly') is True
    # Unknown frequency -> never due (defensive).
    assert app._maint_due('', 'hourly') is False
    # Corrupt timestamp -> treat as due.
    assert app._maint_due('not-a-date', 'daily') is True
