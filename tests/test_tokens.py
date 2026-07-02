"""API-token helper tests — token hashing and constant-time lookup. These gate
non-session (automation) access, so a regression could grant or deny the wrong
caller. Pure functions; _resolve_token reads config via a monkeypatched _tokens.
"""
import hashlib
import app


def test_hash_token_is_sha256_hex():
    secret = 'sd_example'
    assert app._hash_token(secret) == hashlib.sha256(secret.encode()).hexdigest()
    assert len(app._hash_token(secret)) == 64


def test_resolve_token_matches_only_correct_secret(monkeypatch):
    good = 'sd_' + 'A' * 40
    other = 'sd_' + 'B' * 40
    tokens = [
        {'id': 'tok-1', 'name': 'backup', 'role': 'readonly', 'hash': app._hash_token(good)},
    ]
    monkeypatch.setattr(app, '_tokens', lambda: tokens)

    rec = app._resolve_token(good)
    assert rec is not None
    assert rec['name'] == 'backup'
    assert rec['role'] == 'readonly'

    assert app._resolve_token(other) is None        # wrong secret
    assert app._resolve_token('') is None            # empty
    assert app._resolve_token('A' * 40) is None      # missing sd_ prefix
    assert app._resolve_token(None) is None


def test_resolve_token_no_tokens(monkeypatch):
    monkeypatch.setattr(app, '_tokens', lambda: [])
    assert app._resolve_token('sd_anything') is None
