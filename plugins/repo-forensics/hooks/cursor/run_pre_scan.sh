#!/usr/bin/env bash
# Cursor beforeShellExecution wrapper (PRD v3 R2/R7/R8, M2).
#
# This is the ONLY thing standing between the agent and a shell command, and
# the hook is declared failClosed:true. It differs from hooks/run_pre_scan.sh
# (the Claude/Codex/OpenClaw wrapper) in three ways that all matter:
#
#   1. STDOUT IS THE VERDICT CHANNEL. Cursor parses stdout as JSON, so every
#      diagnostic goes to stderr. The Claude wrapper echoes warnings to stdout
#      because the Claude contract tolerates it; here that would corrupt the
#      verdict and land in the undefined-behaviour bucket.
#
#   2. TAMPER-AWARE DEGRADE (R8). The Claude wrapper exits 0 when pre_scan.py
#      is missing, on the reasoning that a blocked-everything hook is worse
#      than an absent one. That reasoning inverts here: "scanner absent" and
#      "scanner deleted five seconds ago" are the same observation at runtime,
#      so anything able to delete pre_scan.py could downgrade a failClosed
#      blocker into approve-and-warn. The install manifest is what tells the
#      two apart, and it is consulted BEFORE the allow branch.
#
#   3. SESSION BOOTSTRAP (K1). Cursor does not reliably fire sessionStart in
#      cloud/agent contexts, so the refresh daemon is bootstrapped from here,
#      behind a time-window latch so it costs one stat() per command rather
#      than a fork.
#
# Exit contract: 0 = allow/ask, 2 = deny. Valid JSON on stdout on every path.

set -u

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-}"
if [ -z "$PLUGIN_ROOT" ]; then
    # Fallback only. cursor_install.py bakes an absolute CLAUDE_PLUGIN_ROOT
    # into the installed command (the openclaw_install.py pattern), so this
    # runs solely for a hand-wired hooks.json.
    _self_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd)" || _self_dir=""
    if [ -n "$_self_dir" ]; then
        PLUGIN_ROOT="$(cd "$_self_dir/../.." 2>/dev/null && pwd)" || PLUGIN_ROOT=""
    fi
fi

SCRIPT="$PLUGIN_ROOT/skills/repo-forensics/scripts/pre_scan.py"
LAUNCHER="$PLUGIN_ROOT/hooks/python-launcher.sh"
ENSURE_REFRESH="$PLUGIN_ROOT/hooks/ensure_refresh_daemon.sh"
MANIFEST="$PLUGIN_ROOT/install-manifest.json"

warn() { printf '%s\n' "$*" >&2; }

# JSON string escaping for a message we control (no user/attacker content is
# interpolated here, but a path could contain a quote or a backslash).
json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' \
        | tr -d '\r' | awk 'BEGIN{ORS=""} {if(NR>1) print "\\n"; print}'
}

verdict() {
    # verdict <permission> <message>
    local perm="$1" msg
    msg="$(json_escape "${2:-}")"
    printf '{"permission": "%s", "user_message": "%s", "agent_message": "%s"}\n' \
        "$perm" "$msg" "$msg"
    case "$perm" in
        deny) exit 2 ;;
        *) exit 0 ;;
    esac
}

# --- (K1) once-per-session refresh bootstrap --------------------------------
# Latched on a time window rather than a session id: the wrapper must not read
# stdin (the scanner needs it), so no conversation_id is available here. The
# latch file is touched BEFORE forking so a burst of parallel commands forks
# once, not N times.
_bootstrap_refresh() {
    [ -f "$ENSURE_REFRESH" ] || return 0
    local latch_dir latch now mtime
    latch_dir="${XDG_CACHE_HOME:-$HOME/.cache}/repo-forensics"
    latch="$latch_dir/cursor-session.latch"
    now="$(date +%s 2>/dev/null || echo 0)"
    mtime=0
    if [ -f "$latch" ]; then
        mtime="$(stat -c %Y "$latch" 2>/dev/null || stat -f %m "$latch" 2>/dev/null || echo 0)"
    fi
    case "$now$mtime" in *[!0-9]*) return 0 ;; esac
    if [ "$mtime" -gt 0 ] && [ "$((now - mtime))" -lt 14400 ]; then
        return 0  # already bootstrapped this session window
    fi
    mkdir -p "$latch_dir" 2>/dev/null || return 0
    : > "$latch" 2>/dev/null || return 0
    "${BASH:-/bin/bash}" "$ENSURE_REFRESH" >/dev/null 2>&1 &
    return 0
}
_bootstrap_refresh

# --- evidence recorder (opt-in) ---------------------------------------------
# Off unless REPO_FORENSICS_HOOK_LOG names a file. When on, it records WHO
# invoked this hook and WHAT they sent, which is the only thing that can
# actually prove Cursor called us rather than a test harness imitating it:
# the parent-process name is Cursor's, and we did not write it.
#
# Deliberately not on by default -- the payload is a verbatim shell command,
# which belongs in a log only when someone has asked for one.
_evidence(){
    [ -n "${REPO_FORENSICS_HOOK_LOG:-}" ] || return 0

    # Walk up a few processes and record only each one's NAME. The ancestry is
    # the proof -- if "cursor" is in this chain, Cursor invoked us and no test
    # harness can claim otherwise. Full command lines are deliberately NOT
    # logged: they are long, they carry absolute paths, and the name alone
    # already settles the question.
    local chain="" pid=$PPID depth=0 comm
    while [ "$depth" -lt 6 ] && [ "$pid" -gt 1 ] 2>/dev/null; do
        comm="$(cat "/proc/$pid/comm" 2>/dev/null || ps -o comm= -p "$pid" 2>/dev/null)"
        [ -n "$comm" ] || break
        chain="${chain:+$chain <- }$comm"
        pid="$(awk '{print $4}' "/proc/$pid/stat" 2>/dev/null)" || break
        depth=$((depth + 1))
    done

    # Redact PII before anything reaches disk. A real Cursor beforeShellExecution
    # envelope carries `user_email` (the signed-in account) and `transcript_path`
    # (a path to the conversation log) alongside the command. Neither is needed
    # to prove the hook fired, and a debug log is exactly the artifact people
    # paste into issues -- so it must not contain them in the first place.
    local safe
    safe="$(printf '%s' "$1" | sed \
        -e 's/"user_email"[[:space:]]*:[[:space:]]*"[^"]*"/"user_email":"<redacted>"/g' \
        -e 's/"transcript_path"[[:space:]]*:[[:space:]]*"[^"]*"/"transcript_path":"<redacted>"/g' \
        -e 's/[A-Za-z0-9._%+-]\{1,\}@[A-Za-z0-9.-]\{1,\}\.[A-Za-z]\{2,\}/<redacted-email>/g')"

    if [ ! -s "$REPO_FORENSICS_HOOK_LOG" ]; then
        {
            printf '# repo-forensics hook evidence log\n'
            printf '# user_email and transcript_path are redacted automatically.\n'
            printf '# PRIVACY: "stdin" below still contains the VERBATIM shell command\n'
            printf '# the agent was about to run. Review before sharing. Delete when\n'
            printf '# done, and unset REPO_FORENSICS_HOOK_LOG to stop recording.\n\n'
        } >> "$REPO_FORENSICS_HOOK_LOG" 2>/dev/null
    fi
    {
        printf '=== %s ===\n' "$(date -Is 2>/dev/null || date)"
        printf 'process chain  : %s\n' "${chain:-<unknown>}"
        printf 'stdin          : %s\n' "$safe"
        printf 'verdict        : %s (exit %s)\n\n' "$2" "$3"
    } >> "$REPO_FORENSICS_HOOK_LOG" 2>/dev/null
    return 0
}

# --- (R8) tamper-aware degrade ----------------------------------------------
# Consulted BEFORE the allow branch. Pure shell on purpose: if the install is
# being tampered with, "just run python to check" is question-begging.
_manifest_claims_missing_file() {
    [ -f "$MANIFEST" ] || return 1
    local block entry
    # Isolate the "files" array, then take each quoted string inside it.
    block="$(tr -d '\n' < "$MANIFEST" 2>/dev/null \
        | sed -n 's/.*"files"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p')" || return 1
    [ -n "$block" ] || return 1
    printf '%s' "$block" | grep -o '"[^"]*"' 2>/dev/null | tr -d '"' | while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        if [ ! -e "$PLUGIN_ROOT/$entry" ]; then
            printf '%s' "$entry"
            exit 0
        fi
    done
    return 1
}

if [ ! -f "$SCRIPT" ]; then
    _missing="$(_manifest_claims_missing_file || true)"
    if [ -f "$MANIFEST" ]; then
        # A manifest exists. Either it names something that is gone (tamper),
        # or it is present but does not claim the scanner at all.
        if [ -n "${_missing:-}" ] || grep -q 'pre_scan\.py' "$MANIFEST" 2>/dev/null; then
            warn "[repo-forensics] TAMPER: install manifest $MANIFEST expects files that are absent at runtime (e.g. ${_missing:-skills/repo-forensics/scripts/pre_scan.py})."
            warn "[repo-forensics] Refusing to approve while the install is inconsistent. Reinstall repo-forensics."
            verdict deny "[repo-forensics] TAMPER: the install manifest expects ${_missing:-pre_scan.py}, which is absent at runtime. The pre-execution gate cannot vouch for this command; reinstall repo-forensics or remove the stale hook."
        fi
    fi
    warn "[repo-forensics] WARNING: pre_scan.py not found at: $SCRIPT"
    warn "[repo-forensics] No install manifest claims it, so this is treated as 'not installed here' rather than tampering."
    warn "[repo-forensics] The pre-execution gate is NOT protecting this command."
    verdict allow ""
fi

# --- run the gate -----------------------------------------------------------
# NOT exec'd: on a failClosed wire the wrapper has to stay alive to answer for
# the scanner. python-launcher.sh exits 127 with no stdout when it cannot find
# an interpreter, and a bare non-zero exit with an empty verdict is exactly the
# ambiguous state R7 says must resolve to deny.
# stdin is buffered ONLY when the evidence recorder is on. With it off the
# scanner reads the pipe directly, exactly as before -- no behaviour change and
# no extra copy of an attacker-controlled payload sitting in a shell variable.
if [ -n "${REPO_FORENSICS_HOOK_LOG:-}" ]; then
    _stdin="$(cat)"
    if [ -f "$LAUNCHER" ]; then
        _out="$(printf '%s' "$_stdin" | "${BASH:-/bin/bash}" "$LAUNCHER" "$SCRIPT" --adapter cursor)"
        _rc=$?
    else
        _out="$(printf '%s' "$_stdin" | python3 "$SCRIPT" --adapter cursor)"
        _rc=$?
    fi
    _perm="$(printf '%s' "$_out" | sed -n 's/.*"permission"[: ]*"\([a-z]*\)".*/\1/p')"
    _evidence "$_stdin" "${_perm:-<unparsed>}" "$_rc"
elif [ -f "$LAUNCHER" ]; then
    _out="$("${BASH:-/bin/bash}" "$LAUNCHER" "$SCRIPT" --adapter cursor)"
    _rc=$?
else
    _out="$(python3 "$SCRIPT" --adapter cursor)"
    _rc=$?
fi

case "$_rc" in
    0|2)
        if [ -n "$_out" ]; then
            printf '%s\n' "$_out"
            exit "$_rc"
        fi
        ;;
esac

warn "[repo-forensics] FAIL-CLOSED: the pre-execution gate exited $_rc without a verdict."
warn "[repo-forensics] A gate that cannot answer must not approve. Check the Python interpreter and the install."
verdict deny "[repo-forensics] FAIL-CLOSED: the repo-forensics pre-execution gate could not run (exit $_rc, no verdict). The command was not checked, so it is denied rather than waved through."
