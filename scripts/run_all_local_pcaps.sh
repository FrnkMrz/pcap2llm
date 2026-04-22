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
#            analyze_<capture>_start_<n>_V_01_flow.{json,svg}
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

abs_artifact_path() {
  local path="$1"
  if [[ -z "$path" || "$path" == "null" ]]; then
    return 0
  fi
  if [[ "$path" == /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s/%s\n' "$PROJECT_ROOT" "$path"
  fi
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
    -o -name "analyze_${capture_key}_start_*_V_*_flow.json" \
    -o -name "analyze_${capture_key}_start_*_V_*_flow.svg" \
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
declare -a FLOW_JSON_FILES=()

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
    RESULT_ROWS+=("| \`$display_name\` | skipped | - | - | - | - | - | - | - | - | - | - |")
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
  packets="-"
  flow_events="-"
  flow_nodes="-"
  flow_phases="-"
  flow_errors="-"
  flow_paired="-"
  flow_links="-"

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
      --render-flow-svg \
      --llm-mode \
      "${HOSTS_ARGS[@]}" \
         2>"$analyze_stderr" \
       | tee "$analyze_json" >/dev/null; then
      a_status=$(jq -r '.status // "unknown"' "$analyze_json" 2>/dev/null || echo "unknown")
      a_included=$(jq -r '.coverage.detail_packets_included // "?"' "$analyze_json" 2>/dev/null || echo "?")
      a_truncated=$(jq -r '.coverage.detail_truncated // false' "$analyze_json" 2>/dev/null || echo "?")
      packets="$a_included"
      a_flow_json="$(abs_artifact_path "$(json_field "$analyze_json" '.files.flow_json')")"
      a_flow_svg="$(abs_artifact_path "$(json_field "$analyze_json" '.files.flow_svg')")"
      if [[ -f "$a_flow_json" ]]; then
        FLOW_JSON_FILES+=("$a_flow_json")
        flow_rendered=$(jq -r '.event_count_rendered // ((.events // []) | length) // 0' "$a_flow_json" 2>/dev/null || echo "0")
        flow_uncollapsed=$(jq -r '.event_count_uncollapsed // .event_count_rendered // ((.events // []) | length) // 0' "$a_flow_json" 2>/dev/null || echo "0")
        flow_events="${flow_rendered}/${flow_uncollapsed}"
        flow_nodes=$(jq -r '(.nodes // []) | length' "$a_flow_json" 2>/dev/null || echo "0")
        flow_phases=$(jq -r '(.phases // []) | length' "$a_flow_json" 2>/dev/null || echo "0")
        flow_errors=$(jq -r '[.events[]? | select((.status // "") == "error" or (.is_error // false) == true)] | length' "$a_flow_json" 2>/dev/null || echo "0")
        flow_paired=$(jq -r '[.events[]? | select(.paired_event_id != null and .paired_event_id != "")] | length' "$a_flow_json" 2>/dev/null || echo "0")
        if [[ -f "$a_flow_svg" ]]; then
          flow_links="[SVG]($a_flow_svg) / [JSON]($a_flow_json)"
        else
          flow_links="[JSON]($a_flow_json)"
        fi
      fi
      ok "analyze done → status=$a_status  packets=$a_included  flow_events=$flow_events  truncated=$a_truncated"
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

  RESULT_ROWS+=("| \`$display_name\` | $discover_status | $top_profile | $inspect_status | $analyze_status | $packets | $flow_events | $flow_nodes | $flow_phases | $flow_errors | $flow_paired | $flow_links |")
done

sep
log "Writing $RESULTS_FILE …"

{
  echo "# Local Trace Run Results"
  echo ""
  echo "Generated: $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "Privacy: \`$PRIVACY\`"
  echo "Flow rendering: \`--render-flow-svg\`"
  echo ""
  echo "## Flow Overview"
  echo ""
  echo "| Trace | Discover | Top Profile | Inspect | Analyze | Packets | Flow Events | Nodes | Phases | Errors | Paired | Flow |"
  echo "|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---|"
  for row in "${RESULT_ROWS[@]}"; do
    echo "$row"
  done
  echo ""
  if [[ ${#FLOW_JSON_FILES[@]} -gt 0 ]]; then
    echo "## Flow Event Samples"
    echo ""
    echo "Each sample shows up to the first 8 rendered flow events from the corresponding \`flow.json\`."
    echo ""
    for flow_json in "${FLOW_JSON_FILES[@]}"; do
      capture_name=$(jq -r '(.capture_file // input_filename) | split("/")[-1]' "$flow_json" 2>/dev/null || basename "$flow_json")
      profile_name=$(jq -r '.profile // "unknown"' "$flow_json" 2>/dev/null || echo "unknown")
      rendered=$(jq -r '.event_count_rendered // ((.events // []) | length) // 0' "$flow_json" 2>/dev/null || echo "0")
      uncollapsed=$(jq -r '.event_count_uncollapsed // .event_count_rendered // ((.events // []) | length) // 0' "$flow_json" 2>/dev/null || echo "0")
      nodes=$(jq -r '(.nodes // []) | length' "$flow_json" 2>/dev/null || echo "0")
      phases=$(jq -r '(.phases // []) | length' "$flow_json" 2>/dev/null || echo "0")
      errors=$(jq -r '[.events[]? | select((.status // "") == "error" or (.is_error // false) == true)] | length' "$flow_json" 2>/dev/null || echo "0")
      phase_preview=$(jq -r '[.phases[0:8][]? | (.label // .kind // "Phase")] | join(", ")' "$flow_json" 2>/dev/null || echo "")
      [[ -z "$phase_preview" ]] && phase_preview="-"
      echo "### $capture_name"
      echo "Profile \`$profile_name\`; events $rendered/$uncollapsed; nodes $nodes; phases $phases ($phase_preview); errors $errors."
      echo ""
      jq -r '
        .events[0:8][]? |
        "- pkt \(.packet_no // "?") - `\(.status // "")` - \(.message_name // .short_label // "event")" +
        (if .correlation_id then " - corr `\(.correlation_id)`" else "" end) +
        (if .paired_event_id then " - paired `\(.paired_event_id)`" else "" end)
      ' "$flow_json" 2>/dev/null || true
      remaining=$(jq -r '((.events // []) | length) - ([.events[0:8][]?] | length)' "$flow_json" 2>/dev/null || echo "0")
      if [[ "$remaining" =~ ^[0-9]+$ && "$remaining" -gt 0 ]]; then
        echo "- ... +$remaining more events in [flow.json]($flow_json)"
      fi
      flow_warnings=$(jq -r '(.warnings // []) | join("; ")' "$flow_json" 2>/dev/null || echo "")
      if [[ -n "$flow_warnings" ]]; then
        echo "- Flow warnings: $flow_warnings"
      fi
      echo ""
    done
  fi
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
  echo "  analyze_<capture>_start_<n>_V_01_flow.json"
  echo "  analyze_<capture>_start_<n>_V_01_flow.svg"
  echo "\`\`\`"
} > "$RESULTS_FILE"

sep
ok "All done. Results summary → $RESULTS_FILE"
echo ""
echo -e "  Traces processed : ${BOLD}$idx${RESET}"
echo -e "  Output root      : ${BOLD}$RUNS_DIR${RESET}"
echo ""
