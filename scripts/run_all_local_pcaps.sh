#!/usr/bin/env bash
# run_all_local_pcaps.sh - Run discover, inspect, and analyze on every local trace under .local/
#
# Usage:
#   bash scripts/run_all_local_pcaps.sh
#   bash scripts/run_all_local_pcaps.sh --quick
#   bash scripts/run_all_local_pcaps.sh --force
#
# Behavior:
#   - scans .local/ recursively for .pcap and .pcapng files
#   - skips .local/runs/ so generated outputs are never re-processed
#   - auto-selects the top profile from discovery for inspect + analyze
#
# Output:  .local/runs/
#            discover_<capture>_start_<n>_V_01.{json,md}
#            inspect_<capture>_start_<n>_V_01.{json,md}
#            analyze_<capture>_start_<n>_V_01_*.{json,md}
#          .local/runs/RESULTS.md  - consolidated overview

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCAL_DIR="$PROJECT_ROOT/.local"
RUNS_DIR="$LOCAL_DIR/runs"
HOSTS_FILE="$LOCAL_DIR/hosts"
RESULTS_FILE="$RUNS_DIR/RESULTS.md"

QUICK=0
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    --force) FORCE=1 ;;
    --help|-h)
      sed -n '2,8p' "$0" | sed 's/^# //'
      exit 0
      ;;
  esac
done

if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

log()  { echo -e "${CYAN}[pcap-run]${RESET} $*"; }
ok()   { echo -e "${GREEN}  ✓${RESET} $*"; }
warn() { echo -e "${YELLOW}  ⚠${RESET} $*"; }
fail() { echo -e "${RED}  ✗${RESET} $*"; }
sep()  { echo -e "${BOLD}────────────────────────────────────────────────────${RESET}"; }

top_profile_from_discovery() {
  local json_file="$1"
  local profile
  if [[ -f "$json_file" ]]; then
    profile=$(jq -r '(.candidate_profiles[0].profile) // "lte-core"' "$json_file" 2>/dev/null || echo "lte-core")
    echo "${profile:-lte-core}"
  else
    echo "lte-core"
  fi
}

slugify_trace_path() {
  local trace_path="$1"
  local relative_path="${trace_path#$LOCAL_DIR/}"
  local without_ext="${relative_path%.*}"
  echo "${without_ext//\//__}"
}

json_field() {
  local file="$1"
  local query="$2"
  jq -r "$query // empty" "$file" 2>/dev/null || true
}

capture_segment() {
  local trace_path="$1"
  local base stem
  base="$(basename "$trace_path")"
  stem="${base%.*}"
  stem="$(printf '%s' "$stem" | sed -E 's/[[:space:]]+/_/g; s/[^A-Za-z0-9._-]+/_/g; s/_+/_/g; s/^[._-]+//; s/[._-]+$//')"
  echo "${stem:-capture}"
}

trace_has_outputs() {
  local capture_key="$1"
  find "$RUNS_DIR" -maxdepth 1 -type f \
    \( -name "discover_${capture_key}_start_*_V_*.json" \
    -o -name "inspect_${capture_key}_start_*_V_*.json" \
    -o -name "analyze_${capture_key}_start_*_V_*_summary.json" \) \
    | grep -q .
}

cleanup_trace_outputs() {
  local capture_key="$1"
  local run_slug="$2"

  find "$RUNS_DIR" -maxdepth 1 -type f \
    \( -name "discover_${capture_key}_start_*_V_*.json" \
    -o -name "discover_${capture_key}_start_*_V_*.md" \
    -o -name "inspect_${capture_key}_start_*_V_*.json" \
    -o -name "inspect_${capture_key}_start_*_V_*.md" \
    -o -name "analyze_${capture_key}_start_*_V_*_summary.json" \
    -o -name "analyze_${capture_key}_start_*_V_*_detail.json" \
    -o -name "analyze_${capture_key}_start_*_V_*_summary.md" \
    -o -name "${run_slug}__*" \) \
    -delete
}

resolve_pcap2llm() {
  if [[ -x "$PROJECT_ROOT/.venv/bin/pcap2llm" && -x "$PROJECT_ROOT/.venv/bin/python" ]] \
    && "$PROJECT_ROOT/.venv/bin/python" -c "import pcap2llm" >/dev/null 2>&1; then
    echo "$PROJECT_ROOT/.venv/bin/pcap2llm"
    return 0
  fi
  if command -v pcap2llm >/dev/null 2>&1; then
    command -v pcap2llm
    return 0
  fi
  return 1
}

if [[ ! -d "$LOCAL_DIR" ]]; then
  fail "No .local directory found under $PROJECT_ROOT"
  exit 1
fi

if ! PCAP2LLM_BIN="$(resolve_pcap2llm)"; then
  fail "pcap2llm not found - add it to PATH or use $PROJECT_ROOT/.venv"
  exit 1
fi
if ! command -v jq &>/dev/null; then
  fail "jq not found - install it with: brew install jq"
  exit 1
fi

pcap_files=()
while IFS= read -r capture; do
  pcap_files+=("$capture")
done < <(
  find "$LOCAL_DIR" \
    -path "$RUNS_DIR" -prune -o \
    -type f \( -iname '*.pcap' -o -iname '*.pcapng' \) -print \
    | LC_ALL=C sort
)

if [[ ${#pcap_files[@]} -eq 0 ]]; then
  fail "No .pcap or .pcapng files found under $LOCAL_DIR"
  exit 1
fi

mkdir -p "$RUNS_DIR"

PRIVACY="internal"

HOSTS_ARGS=()
if [[ -f "$HOSTS_FILE" ]]; then
  HOSTS_ARGS=(--hosts-file "$HOSTS_FILE")
fi

MAX_PACKETS=500

declare -a RESULT_ROWS=()

total=${#pcap_files[@]}
idx=0

for pcap in "${pcap_files[@]}"; do
  idx=$((idx + 1))
  rel_path="${pcap#$LOCAL_DIR/}"
  display_name="${rel_path%.*}"
  run_slug="$(slugify_trace_path "$pcap")"
  capture_key="$(capture_segment "$pcap")"

  sep
  log "${BOLD}[$idx/$total]${RESET} $display_name"

  if trace_has_outputs "$capture_key" && [[ "$FORCE" -eq 0 ]]; then
    warn "Trace outputs already exist - skipping (use --force to re-run and replace them)"
    RESULT_ROWS+=("| \`$display_name\` | skipped | - | - | - |")
    continue
  fi

  if [[ "$FORCE" -eq 1 ]]; then
    cleanup_trace_outputs "$capture_key" "$run_slug"
  fi

  discover_status="ok"
  inspect_status="ok"
  analyze_status="ok"
  top_profile="lte-core"
  classification=""

  log "  [1/3] discover …"
  discover_stdout="$(mktemp)"
  discover_stderr="$(mktemp)"
  if "$PCAP2LLM_BIN" discover "$pcap" \
       --out "$RUNS_DIR" \
       "${HOSTS_ARGS[@]}" \
       >"$discover_stdout" \
       2>"$discover_stderr"; then
    discovery_json="$(json_field "$discover_stdout" '.discovery_json')"
    if [[ -n "$discovery_json" ]]; then
      top_profile=$(top_profile_from_discovery "$discovery_json")
      classification=$(jq -r '.capture_context.classification_state // "unknown"' "$discovery_json" 2>/dev/null || echo "unknown")
      ok "discover done → profile=${BOLD}$top_profile${RESET}  state=$classification"
    else
      warn "discover produced no JSON"
      discover_status="no-output"
    fi
  else
    fail "discover failed"
    sed -n '1,80p' "$discover_stderr" >&2
    discover_status="failed"
  fi
  rm -f "$discover_stdout" "$discover_stderr"

  log "  [2/3] inspect …"
  inspect_stderr="$(mktemp)"
  if inspect_json_output="$("$PCAP2LLM_BIN" inspect "$pcap" \
    --profile "$top_profile" \
    --out "$RUNS_DIR" \
    2>"$inspect_stderr")"; then
    if inspect_md_output="$("$PCAP2LLM_BIN" inspect "$pcap" \
      --profile "$top_profile" \
      --format markdown \
      --out "$RUNS_DIR" \
      2>>"$inspect_stderr")"; then
      inspect_json="$(printf '%s\n' "$inspect_json_output" | sed -n 's/^Wrote inspect output to //p' | tail -1)"
      inspect_md="$(printf '%s\n' "$inspect_md_output" | sed -n 's/^Wrote inspect output to //p' | tail -1)"
      ok "inspect done → $(basename "${inspect_json:-inspect}") + $(basename "${inspect_md:-inspect}")"
    else
      fail "inspect failed"
      sed -n '1,120p' "$inspect_stderr" >&2
      inspect_status="failed"
    fi
  else
    fail "inspect failed"
    sed -n '1,120p' "$inspect_stderr" >&2
    inspect_status="failed"
  fi
  rm -f "$inspect_stderr"

  if [[ "$QUICK" -eq 1 ]]; then
    analyze_status="skipped"
    ok "analyze skipped (--quick mode)"
  else
    log "  [3/3] analyze --profile $top_profile …"
    analyze_json="$(mktemp)"
    analyze_stderr="$(mktemp)"
    if "$PCAP2LLM_BIN" analyze "$pcap" \
         --profile "$top_profile" \
         --privacy-profile "$PRIVACY" \
         --max-packets "$MAX_PACKETS" \
         --out "$RUNS_DIR" \
         --llm-mode \
         "${HOSTS_ARGS[@]}" \
         2>"$analyze_stderr" \
       | tee "$analyze_json" >/dev/null; then
      a_status=$(jq -r '.status // "unknown"' "$analyze_json" 2>/dev/null || echo "unknown")
      a_included=$(jq -r '.coverage.detail_packets_included // "?"' "$analyze_json" 2>/dev/null || echo "?")
      a_truncated=$(jq -r '.coverage.detail_truncated // false' "$analyze_json" 2>/dev/null || echo "?")
      ok "analyze done → status=$a_status  packets=$a_included  truncated=$a_truncated"
      if [[ "$a_truncated" == "true" ]]; then
        warn "detail was truncated — consider passing --max-packets higher or a -Y filter"
      fi
      a_warnings=$(jq -r '(.warnings // []) | join(", ")' "$analyze_json" 2>/dev/null || echo "")
      [[ -n "$a_warnings" ]] && warn "warnings: $a_warnings"
    else
      fail "analyze failed"
      sed -n '1,160p' "$analyze_stderr" >&2
      sed -n '1,160p' "$analyze_json" >&2
      analyze_status="failed"
    fi
    rm -f "$analyze_json" "$analyze_stderr"
  fi

  RESULT_ROWS+=("| \`$display_name\` | $discover_status | $top_profile | $inspect_status | $analyze_status |")
done

sep
log "Writing $RESULTS_FILE …"

{
  echo "# Local Trace Run Results"
  echo ""
  echo "Generated: $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo ""
  echo "| Trace | Discover | Top Profile | Inspect | Analyze |"
  echo "|---|---|---|---|---|"
  for row in "${RESULT_ROWS[@]}"; do
    echo "$row"
  done
  echo ""
  echo "Runner command: \`bash scripts/run_all_local_pcaps.sh\`"
  echo ""
  echo "## Output structure"
  echo ""
  echo "\`\`\`"
  echo ".local/runs/"
  echo "  discover_<capture>_start_<n>_V_01.json"
  echo "  discover_<capture>_start_<n>_V_01.md"
  echo "  inspect_<capture>_start_<n>_V_01.json"
  echo "  inspect_<capture>_start_<n>_V_01.md"
  echo "  analyze_<capture>_start_<n>_V_01_summary.json"
  echo "  analyze_<capture>_start_<n>_V_01_detail.json"
  echo "  analyze_<capture>_start_<n>_V_01_summary.md"
  echo "\`\`\`"
} > "$RESULTS_FILE"

sep
ok "All done. Results summary → $RESULTS_FILE"
echo ""
echo -e "  Traces processed : ${BOLD}$idx${RESET}"
echo -e "  Output root      : ${BOLD}$RUNS_DIR${RESET}"
echo ""
