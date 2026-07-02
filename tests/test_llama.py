"""llama.cpp module tests — the pure logic behind model/arg editing. These guard
config-file injection (newlines/quotes into /etc/llama.conf) and argument
injection (flags/values that reach the llama-server command line), plus the
opts round-trip used by the editor.
"""
import os
import json
import app


def test_llamacpp_registered_as_service_no_alerts():
    svc = app.SYSTEM_SERVICES.get('llamacpp')
    assert svc and svc['service'] == 'llama-server'
    assert svc.get('alert') is False        # never spams health alerts
    assert svc.get('pkg') is None           # not apt-managed


def test_llamacpp_is_a_toggleable_module():
    m = [x for x in app.MODULES if x['id'] == 'llamacpp']
    assert m and m[0]['category'] == 'AI Tools'


def test_parse_opts_handles_bool_value_and_equals():
    parsed = app._llama_parse_opts('--threads 8 --mlock --n-gpu-layers=99 -fa')
    assert {'flag': '--threads', 'value': '8'} in parsed
    assert {'flag': '--mlock', 'value': ''} in parsed         # known boolean
    assert {'flag': '--n-gpu-layers', 'value': '99'} in parsed  # --flag=value form
    assert {'flag': '-fa', 'value': ''} in parsed              # short boolean


def test_opts_round_trip():
    s = '--threads 16 --n-gpu-layers 99 --mlock'
    assert app._llama_format_opts(app._llama_parse_opts(s)) == s


def test_format_opts_skips_empty_flags():
    assert app._llama_format_opts([{'flag': '', 'value': 'x'},
                                   {'flag': '--ctx-size', 'value': '4096'}]) == '--ctx-size 4096'


def test_flag_and_value_regexes_block_injection():
    assert app.RE_LLAMA_FLAG.match('--n-gpu-layers')
    assert app.RE_LLAMA_FLAG.match('-fa')
    assert not app.RE_LLAMA_FLAG.match('--bad;rm')       # shell metachar
    assert not app.RE_LLAMA_FLAG.match('--a b')          # space
    assert app.RE_LLAMA_VALUE.match('3,1')               # tensor-split style
    assert app.RE_LLAMA_VALUE.match('/usr/share/models/x.gguf')
    assert not app.RE_LLAMA_VALUE.match('x y')           # space (extra arg injection)
    assert not app.RE_LLAMA_VALUE.match('a\nLLAMA_OPTS=evil')  # newline (conf injection)
    assert not app.RE_LLAMA_VALUE.match('"quoted"')      # quote breaks LLAMA_OPTS="..."


def test_clean_args_validates_and_drops_model_flag():
    clean, e = app._llama_clean_args([
        {'flag': '--threads', 'value': '8'},
        {'flag': '', 'value': 'x'},          # empty flag -> dropped
        {'flag': '-m', 'value': '/x.gguf'},  # model flag -> dropped (managed separately)
        {'flag': '--mlock', 'value': ''},
    ])
    assert e is None
    assert clean == [{'flag': '--threads', 'value': '8'}, {'flag': '--mlock', 'value': ''}]
    # injection attempts are rejected
    assert app._llama_clean_args([{'flag': '--bad;rm', 'value': 'x'}])[1] is not None
    assert app._llama_clean_args([{'flag': '--threads', 'value': 'a\nevil'}])[1] is not None
    assert app._llama_clean_args('nope')[1] is not None


def test_preset_name_regex():
    assert app.RE_LLAMA_PRESET.match('GPU heavy 128k')
    assert app.RE_LLAMA_PRESET.match('cpu-only_v2')
    assert not app.RE_LLAMA_PRESET.match('')
    assert not app.RE_LLAMA_PRESET.match(' leading-space')
    assert not app.RE_LLAMA_PRESET.match('bad/slash')
    assert not app.RE_LLAMA_PRESET.match('x' * 65)


def test_presets_load_missing_and_bad(tmp_path, monkeypatch):
    monkeypatch.setattr(app, 'LLAMA_PRESETS_FILE', str(tmp_path / 'nope.json'))
    assert app._load_llama_presets() == {}
    p = tmp_path / 'p.json'
    p.write_text('{ not json')
    monkeypatch.setattr(app, 'LLAMA_PRESETS_FILE', str(p))
    assert app._load_llama_presets() == {}


def test_valid_model_confined_to_models_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(app, 'LLAMA_MODELS_DIR', str(tmp_path))
    good = tmp_path / 'qwen.gguf'
    good.write_text('x')
    assert app._llama_valid_model(str(good)) is True
    assert app._llama_valid_model(str(tmp_path / 'missing.gguf')) is False   # not present
    assert app._llama_valid_model(str(tmp_path / 'notes.txt')) is False      # not .gguf
    # Path traversal escaping the models dir is rejected.
    assert app._llama_valid_model(str(tmp_path / '..' / 'etc' / 'x.gguf')) is False
    assert app._llama_valid_model('/etc/passwd') is False


# ─── 06b — model + args profiles (back-compat normalization) ────────────

def test_norm_preset_backcompat():
    # Legacy shape: a bare args list -> {model:'', args:[...]}
    legacy = [{'flag': '--threads', 'value': '8'}]
    assert app._norm_preset(legacy) == {'model': '', 'args': legacy}
    # Current shape: {model, args} preserved
    assert app._norm_preset({'model': '/m/x.gguf', 'args': []}) == {'model': '/m/x.gguf', 'args': []}
    # Dict missing args -> empty list
    assert app._norm_preset({'model': '/m/x.gguf'}) == {'model': '/m/x.gguf', 'args': []}
    # Junk shapes normalize to empty
    assert app._norm_preset('nope') == {'model': '', 'args': []}
    assert app._norm_preset({'args': 'notalist'}) == {'model': '', 'args': []}


def test_presets_load_normalizes_legacy(tmp_path, monkeypatch):
    p = tmp_path / 'p.json'
    p.write_text(json.dumps({
        'old': [{'flag': '--mlock', 'value': ''}],
        'new': {'model': '/m/x.gguf', 'args': [{'flag': '--threads', 'value': '8'}]},
    }))
    monkeypatch.setattr(app, 'LLAMA_PRESETS_FILE', str(p))
    loaded = app._load_llama_presets()
    assert loaded['old'] == {'model': '', 'args': [{'flag': '--mlock', 'value': ''}]}
    assert loaded['new']['model'] == '/m/x.gguf'


# ─── 06a — Hugging Face model pull validators ───────────────────────────

def test_hf_repo_and_file_regexes():
    assert app.RE_HF_REPO.match('bartowski/Llama-3.2-3B-Instruct-GGUF')
    assert app.RE_HF_REPO.match('TheBloke/Mixtral-8x7B-GGUF')
    assert not app.RE_HF_REPO.match('noslash')
    assert not app.RE_HF_REPO.match('a/b/c')            # extra path segment
    assert not app.RE_HF_REPO.match('../etc/passwd')    # traversal (leading dot)
    assert not app.RE_HF_REPO.match('org/mo del')       # space
    assert app.RE_HF_FILE.match('model-Q4_K_M.gguf')
    assert not app.RE_HF_FILE.match('model.bin')        # not .gguf
    assert not app.RE_HF_FILE.match('sub/dir/x.gguf')   # path separator
    assert not app.RE_HF_FILE.match('../x.gguf')        # traversal


# ─── 06c — in-memory tokens/sec derivation ──────────────────────────────

def test_llama_derive_rate(monkeypatch):
    app._llama_rate.update(ts=0.0, tokens=None)
    clock = [1000.0]
    monkeypatch.setattr(app.time, 'time', lambda: clock[0])
    # First sample: no prior -> no rate emitted, state primed
    r = {'metrics': {'tokens_predicted_total': 100}}
    app._llama_derive_rate(r)
    assert 'tokens_per_sec' not in r
    # +10s, +200 tokens -> 20 tok/s
    clock[0] = 1010.0
    r = {'metrics': {'tokens_predicted_total': 300}}
    app._llama_derive_rate(r)
    assert r['tokens_per_sec'] == 20.0
    # Counter went backwards (server restarted) -> interval skipped
    clock[0] = 1020.0
    r = {'metrics': {'tokens_predicted_total': 50}}
    app._llama_derive_rate(r)
    assert 'tokens_per_sec' not in r
    # Missing counter -> no crash, no rate
    r = {'metrics': {}}
    app._llama_derive_rate(r)
    assert 'tokens_per_sec' not in r
