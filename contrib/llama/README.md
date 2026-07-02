# llama.cpp integration (AI Tools → LLama.cpp)

The dashboard manages a local `llama.cpp` **`llama-server`** systemd unit:
service control on the **Services** page and a dedicated **AI Tools → LLama.cpp**
page for model switching + CLI-argument editing. A health/metrics card appears
on the Dashboard while the module is enabled.

It drives the same clean config model as the standalone llama-switcher: a static
unit runs a wrapper that sources `/etc/llama.conf` (`LLAMA_BIN` / `LLAMA_MODEL` /
`LLAMA_OPTS`), so changing the model or args is just a validated rewrite of that
file plus a restart — no `daemon-reload`.

## One-time host setup

```bash
# 1. wrapper + unit
sudo install -m 0755 llama-server.sh /usr/local/bin/llama-server.sh
sudo install -m 0644 llama-server.service /etc/systemd/system/llama-server.service

# 2. config — set LLAMA_BIN to your llama-server binary
sudo cp llama.conf.example /etc/llama.conf
sudoedit /etc/llama.conf

# 3. models: drop *.gguf files under /usr/share/models
sudo mkdir -p /usr/share/models

sudo systemctl daemon-reload
```

The dashboard already grants `tee /etc/llama.conf` in its sudoers (added by
`install.sh`) and controls the unit via the existing `systemctl` grant — no extra
permissions needed. Enable/start the server from the dashboard (Services page or
the LLama.cpp page).

## Tunable paths (dashboard env vars)

| Var | Default | Purpose |
|-----|---------|---------|
| `DASHBOARD_LLAMA_CONF` | `/etc/llama.conf` | Config file the wrapper sources |
| `DASHBOARD_LLAMA_MODELS_DIR` | `/usr/share/models` | Where `.gguf` models are discovered |
| `DASHBOARD_LLAMA_BIN` | `/usr/local/llama.cpp/llama-server` | Default binary (overridable in the conf) |
| `DASHBOARD_LLAMA_URL` | `http://localhost:8080` | llama-server base URL for `/health` + `/metrics` |

If none of this is set up, the LLama.cpp page shows a "not configured" notice and
the module simply stays idle (no alerts, no errors).
