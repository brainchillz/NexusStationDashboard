"""Feature 02 — GPU monitoring parsers.

Pure tests for the nvidia-smi CSV and rocm-smi JSON parsers, normalized to a
common shape. Real rocm-smi output from an AMD/ROCm host (.73) drives the AMD
cases. No GPU or tooling needed to run these.
"""
import app


ROCM_JSON = (
    '{"card0": {"Temperature (Sensor edge) (C)": "35.0", '
    '"Temperature (Sensor junction) (C)": "36.0", '
    '"Average Graphics Package Power (W)": "19.0", "GPU use (%)": "3", '
    '"GPU Memory Allocated (VRAM%)": "85", "Card Series": "N/A", '
    '"Card Model": "0x7551", "Card SKU": "APM107573", "GFX Version": "gfx1201", '
    '"VRAM Total Memory (B)": "34208743424", '
    '"VRAM Total Used Memory (B)": "29225381888"}, '
    '"card1": {"Temperature (Sensor edge) (C)": "39.0", '
    '"Current Socket Graphics Package Power (W)": "12.134", "GPU use (%)": "0", '
    '"GPU Memory Allocated (VRAM%)": "1", "Card SKU": "PHXGENERIC", '
    '"GFX Version": "gfx1103", "VRAM Total Memory (B)": "4294967296", '
    '"VRAM Total Used Memory (B)": "72495104"}}'
)


def test_rocm_parse_two_cards():
    gpus = app._parse_rocm_smi(ROCM_JSON)
    assert len(gpus) == 2
    a, b = gpus
    assert a['index'] == 0 and b['index'] == 1
    assert a['vendor'] == 'amd'


def test_rocm_normalized_values():
    a = app._parse_rocm_smi(ROCM_JSON)[0]
    assert a['util'] == 3.0
    assert a['mem_pct'] == 85.0
    assert a['mem_used'] == 29225381888
    assert a['mem_total'] == 34208743424
    assert a['temp'] == 36.0          # junction preferred over edge
    assert a['power'] == 19.0
    assert 'gfx1201' in a['name'] and 'APM107573' in a['name']


def test_rocm_name_falls_back_to_gfx_when_series_na():
    # card0 Series is "N/A" -> SKU used, gfx appended
    a = app._parse_rocm_smi(ROCM_JSON)[0]
    assert a['name'] == 'APM107573 (gfx1201)'


def test_rocm_power_alt_key():
    # card1 reports "Current Socket Graphics Package Power (W)"
    b = app._parse_rocm_smi(ROCM_JSON)[1]
    assert b['power'] == 12.134


def test_rocm_mem_pct_computed_when_absent():
    j = ('{"card0": {"GPU use (%)": "10", "VRAM Total Memory (B)": "1000", '
         '"VRAM Total Used Memory (B)": "250"}}')
    g = app._parse_rocm_smi(j)[0]
    assert g['mem_pct'] == 25.0


def test_rocm_bad_json_returns_empty():
    assert app._parse_rocm_smi('not json') == []
    assert app._parse_rocm_smi('') == []
    assert app._parse_rocm_smi('[1,2,3]') == []


def test_nvidia_parse():
    csv = '0, NVIDIA GeForce RTX 4090, 45, 8192, 24576, 61, 210.5'
    g = app._parse_nvidia_smi(csv)[0]
    assert g['index'] == 0
    assert g['vendor'] == 'nvidia'
    assert g['name'] == 'NVIDIA GeForce RTX 4090'
    assert g['util'] == 45.0
    assert g['mem_used'] == 8192 * 1024 * 1024
    assert g['mem_total'] == 24576 * 1024 * 1024
    assert g['mem_pct'] == 33.3
    assert g['temp'] == 61.0
    assert g['power'] == 210.5


def test_nvidia_multi_and_short_lines():
    csv = ('0, A, 10, 100, 200, 50, 30\n'
           'garbage line\n'
           '1, B, 20, 50, 200, 55, 40')
    gpus = app._parse_nvidia_smi(csv)
    assert [g['index'] for g in gpus] == [0, 1]


def test_nvidia_handles_na_values():
    csv = '0, GPU, [N/A], [N/A], [N/A], [N/A], [N/A]'
    g = app._parse_nvidia_smi(csv)[0]
    assert g['util'] is None and g['mem_pct'] is None and g['power'] is None


def test_gpu_vendor_none_when_no_tools(monkeypatch):
    monkeypatch.setattr(app.shutil, 'which', lambda _n: None)
    assert app._gpu_vendor() is None


def test_gpu_history_samples_emit_per_gpu(monkeypatch):
    monkeypatch.setattr(app, '_gpu_snapshot', lambda *a, **k: {
        'available': True, 'vendor': 'amd',
        'gpus': [{'index': 0, 'util': 3.0, 'mem_pct': 85.0, 'temp': 36.0},
                 {'index': 1, 'util': 0.0, 'mem_pct': 1.0, 'temp': 39.0}]})
    rows = app._gpu_history_samples()
    assert ('gpu_util', 'gpu0', 3.0) in rows
    assert ('gpu_mem_pct', 'gpu1', 1.0) in rows
    assert ('gpu_temp', 'gpu0', 36.0) in rows
    # labels used are valid history labels
    for _m, lbl, _v in rows:
        assert app.RE_HISTORY_LABEL.match(lbl)


def test_gpu_history_samples_empty_when_no_gpu(monkeypatch):
    monkeypatch.setattr(app, '_gpu_snapshot', lambda *a, **k: {'available': False, 'gpus': []})
    assert app._gpu_history_samples() == []


def test_gpu_module_registered():
    assert 'gpu' in app.MODULE_IDS
