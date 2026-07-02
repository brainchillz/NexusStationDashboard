"""Tests for the /proc resource parsers and the Prometheus metric formatting —
all pure functions (text in, numbers/text out).
"""
import app


def test_parse_meminfo_converts_kb_to_bytes():
    text = (
        'MemTotal:       16384000 kB\n'
        'MemFree:         1000000 kB\n'
        'MemAvailable:    8192000 kB\n'
        'SwapTotal:       2048000 kB\n'
        'SwapFree:        2048000 kB\n'
    )
    m = app._parse_meminfo(text)
    assert m['MemTotal'] == 16384000 * 1024
    assert m['MemAvailable'] == 8192000 * 1024
    assert m['SwapTotal'] == 2048000 * 1024


def test_parse_loadavg():
    assert app._parse_loadavg('0.52 0.58 0.59 1/523 12345') == (0.52, 0.58, 0.59)
    assert app._parse_loadavg('') == (0.0, 0.0, 0.0)
    assert app._parse_loadavg('garbage') == (0.0, 0.0, 0.0)


def test_parse_cpu_stat_idle_is_idle_plus_iowait():
    # cpu  user nice system idle iowait irq softirq steal ...
    text = 'cpu  100 0 50 800 40 0 10 0 0 0\ncpu0 ...\n'
    idle, total = app._parse_cpu_stat(text)
    assert idle == 800 + 40
    assert total == 100 + 0 + 50 + 800 + 40 + 0 + 10 + 0 + 0 + 0


def test_cpu_percent_from_two_samples():
    # total advanced 100, idle advanced 75 -> 25% busy
    assert app._cpu_percent((1000, 5000), (1075, 5100)) == 25.0
    # no time elapsed -> 0, never divide-by-zero
    assert app._cpu_percent((1000, 5000), (1000, 5000)) == 0.0


def test_prom_escape():
    assert app._prom_escape('tank') == 'tank'
    assert app._prom_escape('po"ol') == 'po\\"ol'
    assert app._prom_escape('a\\b') == 'a\\\\b'
    assert app._prom_escape('a\nb') == 'a\\nb'


def test_prom_num_formats_ints_and_floats():
    assert app._prom_num(5) == '5'
    assert app._prom_num(1024) == '1024'
    assert app._prom_num(0.52) == '0.52'
    assert app._prom_num(25.0) == '25'


def test_render_metrics_text_format():
    fams = [
        ('storagedash_up', 'Dashboard is up', 'gauge', [('', 1)]),
        ('storagedash_zfs_pool_size_bytes', 'Pool size', 'gauge',
         [('{pool="tank"}', 1000), ('{pool="Flash"}', 2000)]),
        ('storagedash_empty', 'nothing', 'gauge', []),   # empty family is skipped
    ]
    text = app._render_metrics(fams)
    lines = text.split('\n')
    assert '# HELP storagedash_up Dashboard is up' in lines
    assert '# TYPE storagedash_up gauge' in lines
    assert 'storagedash_up 1' in lines
    assert 'storagedash_zfs_pool_size_bytes{pool="tank"} 1000' in lines
    assert 'storagedash_zfs_pool_size_bytes{pool="Flash"} 2000' in lines
    # an empty family emits no HELP/TYPE line
    assert not any('storagedash_empty' in l for l in lines)
    assert text.endswith('\n')
