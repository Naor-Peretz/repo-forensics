#!/usr/bin/env python3
"""
hook_adapter.py - canonical hook-envelope adapter layer for repo-forensics.

One detection path, many agents. Claude Code, Codex CLI and OpenClaw all speak
the Claude Code hook envelope (`{"tool_name": "Bash", "tool_input": {...}}`);
Cursor speaks its own (`{"command": ..., "hook_event_name": ...}`) and expects
its own verdict shape. This module normalises BOTH into one canonical request
and renders a canonical verdict back into whichever shape the caller's agent
expects, so `pre_scan.py` / `auto_scan.py` / `session_scan.py` keep exactly one
copy of the detection logic (PRD v3 G3/N1).

Design constraints inherited from pre_scan.py (all load-bearing):
  - Pure stdlib, no subprocess, no network, no filesystem walk. This module is
    imported on the PreToolUse blocking path where the latency budget is <10ms.
  - LEAF module: it imports nothing from the repo. `pre_scan.py` stays
    standalone in the sense that matters (no auto_scan import, no scan fan-out);
    this is shared *envelope* plumbing, not shared detection.
  - Every code path must be able to emit a valid verdict. A hook that crashes
    without printing is indistinguishable from a hook that approved.

Fail-open vs fail-closed (the asymmetry is deliberate — PRD v3 R7 + errata 1):

  Claude/Codex/OpenClaw (`claude` adapter): unparseable or unrecognised stdin
  APPROVES. This is the shipped behaviour at v2.14.2 and is pinned by
  test_pre_scan.py::TestMain::test_malformed_json_approves. Their PreToolUse
  gate is one layer among several (PostToolUse deep scan follows), so a
  degraded parse must not brick every Bash command.

  Cursor (`cursor` adapter): unparseable or unrecognised stdin DENIES. Cursor
  hooks are declared `failClosed: true` and beforeShellExecution is the only
  gate in front of the command. A renamed/spoofed field must not silently
  approve a live payload — that is precisely the "shape-mismatch passes a live
  payload" bug class the adapter exists to prevent.

Created by Alex Greenshpun.
"""

import json
import os
import sys

# --- Adapters ---------------------------------------------------------------

ADAPTER_CLAUDE = "claude"
ADAPTER_CURSOR = "cursor"
ADAPTERS = (ADAPTER_CLAUDE, ADAPTER_CURSOR)

# Adapters whose blocking path fails CLOSED on an envelope it cannot understand.
FAIL_CLOSED_ADAPTERS = frozenset({ADAPTER_CURSOR})

# --- Canonical verdicts -----------------------------------------------------

ALLOW = "allow"
DENY = "deny"
ASK = "ask"

# Exit-code contract. Mirrors the shipped Claude convention (0 approve /
# 2 block) and Cursor's (0 allow-or-ask / 2 deny). `ask` is advisory: it
# surfaces to the human without hard-blocking, so it exits 0.
EXIT_FOR = {ALLOW: 0, ASK: 0, DENY: 2}

# --- Cursor envelope --------------------------------------------------------

# Events Cursor is documented to dispatch. An event outside this set arriving
# on a wire we installed for beforeShellExecution is schema drift, not a new
# feature we can safely ignore — see classify_drift().
CURSOR_EVENTS = frozenset({
    "beforeShellExecution",
    "afterShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
    "afterFileEdit",
    "beforeSubmitPrompt",
    "sessionStart",
    "stop",
})

# The events that carry a shell command we are expected to gate.
CURSOR_COMMAND_EVENTS = frozenset({"beforeShellExecution", "afterShellExecution"})

DEFAULT_CURSOR_EVENT = "beforeShellExecution"

MAX_STDIN_BYTES = 1_048_576  # 1MB, same cap as the shipped pre_scan reader

# --- Kill switches (PRD v3 R11) ---------------------------------------------

# Detection off, integrity still enforced. This is the everyday escape hatch
# for a false positive: it must never be able to mask a tampered install or an
# envelope the adapter cannot parse, because both of those are exactly what an
# attacker would arrange before planting `REPO_FORENSICS_PRE_SCAN=0` in the
# session environment from an earlier command.
KILL_SWITCH_ENV = "REPO_FORENSICS_PRE_SCAN"
KILL_SWITCH_OFF = "0"

# Everything off, including the fail-closed integrity/drift denials. Spelled
# deliberately ugly and undocumented in the happy path so it cannot be reached
# by a plausible-looking session plant, but still available to an operator whose
# Cursor build genuinely drifted and who needs to keep working.
KILL_SWITCH_UNSAFE = "unsafe-off"

# Precedence, strongest first (R11):
#   1. REPO_FORENSICS_PRE_SCAN=unsafe-off  -> allow everything, loudly
#   2. install-manifest tamper             -> deny (not user-suppressible)
#   3. envelope drift (fail-closed adapter)-> deny (not user-suppressible)
#   4. REPO_FORENSICS_PRE_SCAN=0           -> allow, loudly
#   5. detection verdict
PRECEDENCE_DOC = (
    "unsafe-off > tamper > drift > REPO_FORENSICS_PRE_SCAN=0 > detection"
)

# --- Install manifest (PRD v3 R8 / A3) --------------------------------------

INSTALL_MANIFEST_NAME = "install-manifest.json"
PLUGIN_ROOT_ENV = "CLAUDE_PLUGIN_ROOT"

INTEGRITY_OK = "ok"
INTEGRITY_TAMPER = "tamper"
INTEGRITY_UNCLAIMED = "unclaimed"

# Path of this scanner family relative to a plugin root, used to tell
# "deleted at runtime" apart from "never installed here".
PRE_SCAN_REL = os.path.join("skills", "repo-forensics", "scripts", "pre_scan.py")


def adapter_from_argv(argv):
    """Extract `--adapter NAME` / `--adapter=NAME` from *argv*.

    Hand-rolled rather than argparse: this runs on the <10ms blocking path and
    argparse costs more to import than the whole rest of the gate. Unknown
    names fall back to the default adapter, which keeps a typo from silently
    disabling the Cursor fail-closed policy... except that it would, so an
    unknown name is reported to the caller for a loud failure instead.
    """
    for index, arg in enumerate(argv):
        if arg == "--adapter" and index + 1 < len(argv):
            return argv[index + 1].strip().lower()
        if arg.startswith("--adapter="):
            return arg.split("=", 1)[1].strip().lower()
    return ADAPTER_CLAUDE


def normalize_adapter(name):
    """Return (adapter, error). An unrecognised adapter is an error, never a
    silent downgrade to the fail-open default."""
    candidate = (name or ADAPTER_CLAUDE).strip().lower()
    if candidate in ADAPTERS:
        return candidate, None
    return ADAPTER_CLAUDE, "unknown adapter {!r} (known: {})".format(
        name, ", ".join(ADAPTERS))


def read_stdin(limit=MAX_STDIN_BYTES):
    """Read the hook payload. Never raises; unreadable stdin returns ''."""
    try:
        return sys.stdin.read(limit)
    except (OSError, UnicodeDecodeError):
        return ""


class HookRequest:
    """One normalised hook invocation.

    `drift` is non-empty when the envelope could not be understood. Callers on
    a fail-closed adapter must treat that as a denial, not as "no command".
    """

    __slots__ = ("adapter", "event", "command", "cwd", "sandbox", "raw", "drift")

    def __init__(self, adapter, event=None, command=None, cwd=None,
                 sandbox=False, raw=None, drift=None):
        self.adapter = adapter
        self.event = event
        self.command = command
        self.cwd = cwd
        self.sandbox = bool(sandbox)
        self.raw = raw if isinstance(raw, dict) else {}
        self.drift = drift

    @property
    def ok(self):
        return not self.drift

    def __repr__(self):  # pragma: no cover - debugging aid only
        return "HookRequest(adapter={!r}, event={!r}, drift={!r})".format(
            self.adapter, self.event, self.drift)


def _load_json(raw):
    """Strict JSON load. Returns (value, error). Trailing garbage is an error:
    `json.loads` rejects it, and that rejection is a signal we want."""
    if raw is None:
        return None, "no stdin"
    if not raw.strip():
        return None, "empty stdin"
    try:
        return json.loads(raw), None
    except ValueError as exc:  # JSONDecodeError is a ValueError
        return None, "stdin is not valid JSON: {}".format(exc)


def parse_request(adapter, raw):
    """Normalise a raw stdin payload into a HookRequest for *adapter*."""
    data, error = _load_json(raw)
    if error:
        return HookRequest(adapter, drift=error)
    if not isinstance(data, dict):
        return HookRequest(adapter, drift="hook payload must be a JSON object, got {}".format(
            type(data).__name__))
    if adapter == ADAPTER_CURSOR:
        return _parse_cursor(data)
    return _parse_claude(data)


def _parse_claude(data):
    """Claude Code / Codex / OpenClaw PreToolUse+PostToolUse envelope.

    Kept deliberately permissive: a non-Bash tool is "nothing to gate", not
    drift, because this hook is registered for every tool on some installs.
    """
    tool_name = data.get("tool_name", "")
    if tool_name != "Bash":
        return HookRequest(ADAPTER_CLAUDE, event=tool_name or None,
                           command=None, raw=data)
    tool_input = data.get("tool_input", {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except ValueError:
            # Legacy behaviour: an unparseable tool_input yields no command,
            # which the fail-open adapter treats as approve.
            return HookRequest(ADAPTER_CLAUDE, event="Bash", command=None, raw=data)
    if not isinstance(tool_input, dict):
        return HookRequest(ADAPTER_CLAUDE, event="Bash", command=None, raw=data)
    return HookRequest(
        ADAPTER_CLAUDE,
        event="Bash",
        command=tool_input.get("command", ""),
        cwd=data.get("cwd"),
        raw=data,
    )


def _parse_cursor(data):
    """Cursor hook envelope.

    Strict on purpose. Every branch that cannot produce a command it is
    confident about reports drift, and the caller denies. See the module
    docstring for why the two adapters differ here.
    """
    event = data.get("hook_event_name")

    if event is None:
        # Tolerated: some Cursor builds omit the event name on the shell wire.
        # We can still do our job if a command is unambiguously present, but we
        # say so on stderr rather than pretending the envelope was complete.
        if isinstance(data.get("command"), str):
            return HookRequest(
                ADAPTER_CURSOR, event=DEFAULT_CURSOR_EVENT,
                command=data["command"], cwd=data.get("cwd"),
                sandbox=data.get("sandbox", False), raw=data,
            )
        return HookRequest(ADAPTER_CURSOR, raw=data, drift=(
            "cursor payload has neither 'hook_event_name' nor a string "
            "'command' field (schema drift or a spoofed envelope)"))

    if not isinstance(event, str) or event not in CURSOR_EVENTS:
        return HookRequest(ADAPTER_CURSOR, raw=data, drift=(
            "unknown cursor hook_event_name {!r}; this wire was installed for "
            "{}".format(event, DEFAULT_CURSOR_EVENT)))

    if event not in CURSOR_COMMAND_EVENTS:
        # A real Cursor event that carries no shell command. Nothing to gate.
        return HookRequest(ADAPTER_CURSOR, event=event, command=None,
                           cwd=data.get("cwd"), raw=data)

    command = data.get("command")
    if not isinstance(command, str):
        return HookRequest(ADAPTER_CURSOR, event=event, raw=data, drift=(
            "cursor {} payload is missing a string 'command' field (got {}); "
            "field rename or spoofed envelope".format(
                event, type(command).__name__)))

    return HookRequest(
        ADAPTER_CURSOR, event=event, command=command, cwd=data.get("cwd"),
        sandbox=data.get("sandbox", False), raw=data,
    )


# --- Verdict rendering ------------------------------------------------------

def render_verdict(adapter, permission, user_message="", agent_message=""):
    """Return (stdout_payload, exit_code) in *adapter*'s native shape."""
    exit_code = EXIT_FOR.get(permission, 0)

    if adapter == ADAPTER_CURSOR:
        return {
            "permission": permission,
            "user_message": user_message or "",
            "agent_message": agent_message or (user_message or ""),
        }, exit_code

    # Claude Code / Codex / OpenClaw shipped shape. `ask` has no representation
    # in the v2.14.2 contract, so it approves silently on stdout; the reason
    # still reaches the operator on stderr (see emit_verdict). Keeping stdout
    # byte-identical to the shipped behaviour is what makes the Cursor work
    # non-breaking for the other three agents.
    if permission == DENY:
        return {"decision": "block", "reason": user_message or agent_message or ""}, 2
    return {}, 0


def render_session_context(adapter, text):
    """Return (stdout_payload, exit_code) for a session-start report.

    sessionStart cannot gate anything, so it does not carry a permission at
    all. Cursor's contract for it is `additional_context` -- the text is
    injected into the agent's context rather than shown as an allow/deny
    (PRD v3 R4). Emitting the permission triple here would be a category error:
    it would read as a verdict on a session, which is not a thing that can be
    denied.

    An empty report emits `{}` rather than an empty `additional_context`, so a
    quiet session adds nothing to the agent's context instead of a blank line.
    """
    if adapter == ADAPTER_CURSOR:
        return ({"additional_context": text} if text else {}), 0
    return None, 0  # Claude/Codex/OpenClaw surface plain text, not JSON


def emit_session_context(adapter, text, stream=None):
    """Print a session-start report in *adapter*'s shape. Returns the exit code."""
    out = stream if stream is not None else sys.stdout
    payload, exit_code = render_session_context(adapter, text)
    if payload is None:
        if text:
            try:
                print(text, file=out)
            except (OSError, ValueError):
                pass
        return exit_code
    try:
        print(json.dumps(payload), file=out)
    except (OSError, ValueError, TypeError):
        try:
            print("{}", file=out)
        except (OSError, ValueError):
            pass
    return exit_code


def emit_verdict(adapter, permission, user_message="", agent_message="",
                 stderr_note=None, stream=None, err_stream=None):
    """Print the verdict and return the exit code. Never raises."""
    payload, exit_code = render_verdict(adapter, permission, user_message, agent_message)
    out = stream if stream is not None else sys.stdout
    err = err_stream if err_stream is not None else sys.stderr

    if stderr_note:
        try:
            print(stderr_note, file=err)
        except (OSError, ValueError):
            pass

    # An `ask` that the Claude shape cannot express must not vanish silently.
    if adapter != ADAPTER_CURSOR and permission == ASK and (user_message or agent_message):
        try:
            print("[repo-forensics] NOTE: {}".format(user_message or agent_message),
                  file=err)
        except (OSError, ValueError):
            pass

    try:
        print(json.dumps(payload), file=out)
    except (OSError, ValueError, TypeError):
        # Last resort: the contract says "valid JSON on stdout, always".
        try:
            print("{}", file=out)
        except (OSError, ValueError):
            pass
    return exit_code


# --- Kill switch ------------------------------------------------------------

def kill_switch_state(env=None):
    """Return one of None / 'detection' / 'unsafe'.

    'detection' -> skip detection, keep integrity + drift enforcement (R11).
    'unsafe'    -> skip everything, including the fail-closed denials.
    """
    environ = env if env is not None else os.environ
    raw = environ.get(KILL_SWITCH_ENV)
    if raw is None:
        return None
    value = raw.strip().lower()
    if value == KILL_SWITCH_UNSAFE:
        return "unsafe"
    if value == KILL_SWITCH_OFF:
        return "detection"
    # Anything else (`false`, `no`, ``) is NOT a disable. A kill switch that
    # accepts fuzzy values is a kill switch an attacker can trip by accident.
    return None


# --- Install-manifest integrity (R8) ----------------------------------------

def plugin_root(env=None):
    environ = env if env is not None else os.environ
    root = environ.get(PLUGIN_ROOT_ENV)
    return root.strip() if isinstance(root, str) and root.strip() else None


def check_install_integrity(root, required_rel=PRE_SCAN_REL):
    """Classify the runtime state of an installed plugin root (PRD v3 R8).

    Returns (state, detail):
      INTEGRITY_OK        - nothing to worry about (also: no root to check).
      INTEGRITY_TAMPER    - the install manifest claims a file that is gone,
                            or the manifest itself is unreadable/corrupt.
                            The blocking path must DENY.
      INTEGRITY_UNCLAIMED - `required_rel` is absent and no manifest claims it.
                            Genuinely not installed here: allow, but loudly.

    "Scanner absent" and "scanner deleted" are the same observation at runtime;
    the manifest is what tells them apart. Checking it BEFORE the allow branch
    is the whole point — otherwise deleting pre_scan.py silently converts a
    failClosed blocker into approve-and-warn.
    """
    if not root:
        return INTEGRITY_OK, ""

    manifest_path = os.path.join(root, INSTALL_MANIFEST_NAME)
    manifest = None
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r") as handle:
                manifest = json.load(handle)
        except (OSError, ValueError) as exc:
            return INTEGRITY_TAMPER, (
                "install manifest {} is present but unreadable ({}); refusing to "
                "treat a corrupt manifest as 'not installed'".format(manifest_path, exc))
        if not isinstance(manifest, dict):
            return INTEGRITY_TAMPER, (
                "install manifest {} is not a JSON object".format(manifest_path))

    claimed = []
    if manifest is not None:
        files = manifest.get("files", [])
        if not isinstance(files, list):
            return INTEGRITY_TAMPER, (
                "install manifest {} has a non-list 'files' field".format(manifest_path))
        claimed = [f for f in files if isinstance(f, str)]

    missing = []
    for rel in claimed:
        # Normalise separators so a manifest written on one platform still
        # resolves on another; reject anything that escapes the root.
        parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            return INTEGRITY_TAMPER, (
                "install manifest {} lists a path that escapes the plugin root: "
                "{!r}".format(manifest_path, rel))
        if not os.path.exists(os.path.join(root, *parts)):
            missing.append(rel)

    if missing:
        return INTEGRITY_TAMPER, (
            "install manifest {} expects {} file(s) that are absent at runtime: "
            "{}".format(manifest_path, len(missing), ", ".join(sorted(missing)[:5])))

    if required_rel:
        required_abs = os.path.join(root, *required_rel.replace("\\", "/").split("/"))
        if not os.path.exists(required_abs):
            normalized_claims = {c.replace("\\", "/") for c in claimed}
            if required_rel.replace("\\", "/") in normalized_claims:
                # Already covered by the `missing` sweep above; defensive only.
                return INTEGRITY_TAMPER, (
                    "install manifest expects {} but it is absent".format(required_rel))
            return INTEGRITY_UNCLAIMED, (
                "{} is not present under plugin root {} and no install manifest "
                "claims it".format(required_rel, root))

    return INTEGRITY_OK, ""
