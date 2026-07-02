"""Feature 01 — bounded time-series history store.

Pure/DB-backed unit tests for the SQLite ring buffer: record/query round-trips,
the allowlist + None filtering, the daily rollup fold, the size backstop, the
least-squares forecast slope, and the label validator. Each test drives a
throwaway db via the DASHBOARD_HISTORY_DB indirection (app reads the module
global HISTORY_DB, so we monkeypatch that).
"""
import os
import time

import app


def _fresh_db(tmp_path, monkeypatch):
    db = os.path.join(str(tmp_path), 'history.db')
    monkeypatch.setattr(app, 'HISTORY_DB', db)
    return db


def test_record_and_query_roundtrip(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    app._history_record([('cpu_pct', '', 12.5), ('cpu_pct', '', 40.0)])
    pts = app._history_query('cpu_pct', '', 0)
    assert [p[1] for p in pts] == [12.5, 40.0]
    # every point is [ts, value]
    assert all(len(p) == 2 and isinstance(p[0], int) for p in pts)


def test_record_filters_unknown_metric_and_none(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    app._history_record([
        ('cpu_pct', '', 5.0),
        ('not_a_metric', '', 99.0),   # dropped: not allowlisted
        ('mem_pct', '', None),        # dropped: None value
    ])
    assert len(app._history_query('cpu_pct', '', 0)) == 1
    assert app._history_query('not_a_metric', '', 0) == []
    assert app._history_query('mem_pct', '', 0) == []


def test_query_respects_label_and_since(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    app._history_record([('pool_alloc', 'tank', 100.0), ('pool_alloc', 'Flash', 200.0)])
    assert [p[1] for p in app._history_query('pool_alloc', 'tank', 0)] == [100.0]
    assert [p[1] for p in app._history_query('pool_alloc', 'Flash', 0)] == [200.0]
    # since in the future returns nothing
    assert app._history_query('pool_alloc', 'tank', int(time.time()) + 3600) == []


def test_record_never_raises_on_bad_input(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    # non-float value is swallowed (best-effort), not raised
    app._history_record([('cpu_pct', '', object())])
    # a totally malformed rows arg is swallowed too
    app._history_record(None)


def test_rollup_folds_prior_days_and_prunes_raw(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    monkeypatch.setattr(app, 'HISTORY_RAW_DAYS', 3)
    conn = app._history_conn()
    old = int(time.time()) - 5 * 86400   # 5 days ago -> a "prior day", also < raw window
    conn.executemany('INSERT INTO samples(ts,metric,label,value) VALUES(?,?,?,?)',
                     [(old, 'cpu_pct', '', 10.0), (old + 60, 'cpu_pct', '', 30.0)])
    conn.close()
    app._history_maybe_rollup()
    daily = app._history_query_daily('cpu_pct', '', 400)
    assert len(daily) == 1
    row = daily[0]
    assert row['min'] == 10.0 and row['max'] == 30.0 and row['avg'] == 20.0
    assert row['last'] == 30.0   # latest sample of the day
    # raw older than the raw window is gone
    assert app._history_query('cpu_pct', '', 0) == []


def test_rollup_is_idempotent_same_day(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    conn = app._history_conn()
    old = int(time.time()) - 5 * 86400
    conn.execute('INSERT INTO samples(ts,metric,label,value) VALUES(?,?,?,?)',
                 (old, 'cpu_pct', '', 42.0))
    conn.close()
    app._history_maybe_rollup()
    app._history_maybe_rollup()   # second call short-circuits on the meta marker
    assert len(app._history_query_daily('cpu_pct', '', 400)) == 1


def test_daily_query_returns_chronological(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    conn = app._history_conn()
    conn.executemany('INSERT INTO daily(day,metric,label,avg,min,max,last) VALUES(?,?,?,?,?,?,?)',
                     [('2026-01-01', 'cpu_pct', '', 1, 1, 1, 1),
                      ('2026-01-03', 'cpu_pct', '', 3, 3, 3, 3),
                      ('2026-01-02', 'cpu_pct', '', 2, 2, 2, 2)])
    conn.close()
    days = [r['day'] for r in app._history_query_daily('cpu_pct', '', 400)]
    assert days == ['2026-01-01', '2026-01-02', '2026-01-03']


def test_size_backstop_no_error_when_under_cap(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    app._history_record([('cpu_pct', '', 1.0)])
    mb = app._history_size_backstop()
    assert mb >= 0 and mb < app.HISTORY_MAX_MB


def test_size_backstop_missing_db_returns_zero(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)   # db not created yet
    assert app._history_size_backstop() == 0


def test_forecast_slope_linear():
    # value climbs 10 units/sec
    pts = [[0, 0.0], [1, 10.0], [2, 20.0], [3, 30.0]]
    assert abs(app._history_forecast_slope(pts) - 10.0) < 1e-9


def test_forecast_slope_needs_three_points():
    assert app._history_forecast_slope([[0, 1.0], [1, 2.0]]) is None


def test_forecast_slope_flat_is_zero():
    assert app._history_forecast_slope([[0, 5.0], [1, 5.0], [2, 5.0]]) == 0.0


def test_forecast_slope_degenerate_x_returns_none():
    assert app._history_forecast_slope([[5, 1.0], [5, 2.0], [5, 3.0]]) is None


def test_forecast_slope_skips_none_values():
    pts = [[0, 0.0], [1, None], [2, 20.0], [3, 30.0]]
    slope = app._history_forecast_slope(pts)
    assert slope is not None and slope > 0


def test_history_label_regex():
    ok = ['tank', 'Flash', 'pool_1', 'a b.c-d:e/f', '']
    bad = ['bad;rm', 'has\nnewline', 'x' * 65, 'quote"']
    for s in ok:
        assert app.RE_HISTORY_LABEL.match(s)
    for s in bad:
        assert not app.RE_HISTORY_LABEL.match(s)


def test_num_helper():
    assert app._num('42') == 42
    assert app._num(None) is None
    assert app._num('nope') is None


def test_llama_history_sample_when_up(monkeypatch):
    monkeypatch.setattr(app, '_llama_tokens_total', lambda: 12345.0)
    assert app._llama_history_samples() == [('llama_tokens_total', '', 12345.0)]


def test_llama_history_sample_empty_when_down(monkeypatch):
    monkeypatch.setattr(app, '_llama_tokens_total', lambda: None)
    assert app._llama_history_samples() == []


def test_llama_tokens_total_disabled_module(monkeypatch):
    monkeypatch.setattr(app, 'load_disabled_modules', lambda: {'llamacpp'})
    # short-circuits before any network call
    assert app._llama_tokens_total() is None


def test_llama_tokens_total_metric_is_allowlisted():
    assert 'llama_tokens_total' in app.HISTORY_METRICS
