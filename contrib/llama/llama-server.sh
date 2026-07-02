#!/bin/bash
# Static wrapper for the llama-server systemd unit. It sources /etc/llama.conf
# (LLAMA_BIN / LLAMA_MODEL / LLAMA_OPTS) so the dashboard can change the model
# and CLI args by rewriting that one file + restarting — no daemon-reload, no
# unit edits. The dashboard validates every value before it is written here.
. /etc/llama.conf
exec "$LLAMA_BIN" -m "$LLAMA_MODEL" $LLAMA_OPTS
