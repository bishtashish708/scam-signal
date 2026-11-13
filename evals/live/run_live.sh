#!/usr/bin/env bash
# Live LLM-in-the-loop check: runs each prompt in evals/live/cases.jsonl through `claude -p`
# with this repo loaded via --plugin-dir. Does NOT touch your global config.
# MCP servers are disabled (--strict-mcp-config) so no real inbox/connector can be read,
# and WebFetch/WebSearch are blocked. Each case is one Claude call (~15 total).
#
#   evals/live/run_live.sh [out_dir]      # then: python3 evals/live/summarize.py out_dir
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-$(mktemp -d)}"; WORK="$(mktemp -d)"
mkdir -p "$OUT"; cp "$REPO/tests/fixtures/phish_paypal.eml" "$WORK/suspicious.eml"
python3 -c "import json,sys;[print(json.loads(l)['id']) for l in open(sys.argv[1])]" "$REPO/evals/live/cases.jsonl" |
while read -r id; do
  prompt=$(python3 -c "import json,sys;[print(json.loads(l)['prompt']) for l in open(sys.argv[1]) if json.loads(l)['id']==sys.argv[2]]" "$REPO/evals/live/cases.jsonl" "$id")
  (cd "$WORK" && claude -p "$prompt" --plugin-dir "$REPO" \
     --strict-mcp-config --mcp-config '{"mcpServers":{}}' \
     --allowedTools "Skill" "Read" "Bash(python3:*)" --disallowedTools "WebFetch" "WebSearch" \
     --max-turns 15 --output-format stream-json --verbose > "$OUT/$id.jsonl")
  echo "$id done"
done
echo "outputs in $OUT"
