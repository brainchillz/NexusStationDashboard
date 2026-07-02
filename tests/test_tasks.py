"""Feature 04 — scheduled tasks console.

Pure tests for the systemctl-property parsing (_usec_to_epoch), the task-status
shaping (_task_status via a monkeypatched _systemctl_show), and the failure-alert
derivation (_task_alerts). No systemd needed.
"""
import app


def test_usec_to_epoch():
    assert app._usec_to_epoch('1751433600000000') == 1751433600
    assert app._usec_to_epoch('0') is None
    assert app._usec_to_epoch('') is None
    assert app._usec_to_epoch(None) is None
    assert app._usec_to_epoch('garbage') is None


def _stub_show(mapping):
    """Return a _systemctl_show that yields mapping[unit] (or {})."""
    return lambda unit, props: mapping.get(unit, {})


def test_task_status_never_run(monkeypatch):
    t = app.MANAGED_TASKS[0]
    monkeypatch.setattr(app, '_systemctl_show', _stub_show({
        t['timer']: {'ActiveState': 'active', 'LastTriggerUSec': '', 'NextElapseUSecRealtime': '1751433600000000'},
        t['service']: {'Result': 'success', 'ExecMainStatus': '0', 'ActiveState': 'inactive'},
    }))
    s = app._task_status(t)
    assert s['timer_active'] is True
    assert s['last_run'] is None
    assert s['ok'] is None           # never run -> unknown, not "ok"
    assert s['next_run'] == 1751433600


def test_task_status_ran_ok(monkeypatch):
    t = app.MANAGED_TASKS[0]
    monkeypatch.setattr(app, '_systemctl_show', _stub_show({
        t['timer']: {'ActiveState': 'active', 'LastTriggerUSec': '1751433600000000'},
        t['service']: {'Result': 'success', 'ExecMainStatus': '0', 'ActiveState': 'inactive'},
    }))
    s = app._task_status(t)
    assert s['last_run'] == 1751433600
    assert s['ok'] is True
    assert s['exit_code'] == 0


def test_task_status_failed(monkeypatch):
    t = app.MANAGED_TASKS[0]
    monkeypatch.setattr(app, '_systemctl_show', _stub_show({
        t['timer']: {'ActiveState': 'active', 'LastTriggerUSec': '1751433600000000'},
        t['service']: {'Result': 'exit-code', 'ExecMainStatus': '1', 'ActiveState': 'inactive'},
    }))
    s = app._task_status(t)
    assert s['ok'] is False
    assert s['last_result'] == 'exit-code'
    assert s['exit_code'] == 1


def test_task_status_running(monkeypatch):
    t = app.MANAGED_TASKS[0]
    monkeypatch.setattr(app, '_systemctl_show', _stub_show({
        t['timer']: {'ActiveState': 'active', 'LastTriggerUSec': '1751433600000000'},
        t['service']: {'Result': 'success', 'ExecMainStatus': '0', 'ActiveState': 'active'},
    }))
    assert app._task_status(t)['running'] is True


def test_task_alerts_only_on_armed_failure(monkeypatch):
    def show(unit, props):
        if unit.endswith('.timer'):
            # first task armed, the rest disarmed
            armed = unit == app.MANAGED_TASKS[0]['timer']
            return {'ActiveState': 'active' if armed else 'inactive',
                    'LastTriggerUSec': '1751433600000000' if armed else ''}
        return {'Result': 'exit-code', 'ExecMainStatus': '1', 'ActiveState': 'inactive'}
    monkeypatch.setattr(app, '_systemctl_show', show)
    alerts = app._task_alerts()
    assert len(alerts) == 1
    assert alerts[0]['key'] == 'task:' + app.MANAGED_TASKS[0]['id']


def test_task_alerts_none_when_healthy(monkeypatch):
    monkeypatch.setattr(app, '_systemctl_show', lambda unit, props: (
        {'ActiveState': 'active', 'LastTriggerUSec': '1751433600000000'} if unit.endswith('.timer')
        else {'Result': 'success', 'ExecMainStatus': '0', 'ActiveState': 'inactive'}))
    assert app._task_alerts() == []


def test_systemctl_show_parses_kv(monkeypatch):
    monkeypatch.setattr(app, 'run', lambda args, **k: ('A=1\nB=x=y\nnoeq\n', '', 0))
    d = app._systemctl_show('u', ['A', 'B'])
    assert d == {'A': '1', 'B': 'x=y'}


def test_history_is_a_managed_task():
    assert 'history' in app.TASK_IDS
