#!/usr/bin/env python3
"""scan_yara.py - YARA signature scanner (optional dependency).

Detects malware, webshells, cryptominers, and hacktools via curated YARA
signatures shipped in data/yara/. yara-python (a C extension on libyara) is an
OPTIONAL dependency: the core product stays zero-non-stdlib-deps, offline, and
deterministic, so a hard C-extension dep would break the dominant plugin-cache
install path (file copies with no pip step) and trip auto_scan.py's fail-loud
contract on every hook run.

Degradation when yara-python is absent (deterministic, offline):
  - module import never fails (try/except ImportError).
  - main() prints ONE stderr line containing the enrichment marker
    "not found" (matched by aggregate_json.build_enrichment_status -> a
    missing-tool capability gap -> enrichment_status.overall = DEGRADED;
    honest, additive, never affects exit code).
  - stdout gets [] via the normal core.output_findings path; exit 0.
  - scan_file/scan_text return [] (in-process callers get a vacuous pass;
    the teeth tests keep this honest).

Rules are resolved from realpath(dirname(__file__))/../data/yara (mirrors
rule_loader._INSTALL_RULEPACK_DIR anchoring) - never CWD, never scan-target.
The manifest's per-file sha256 is verified before compiling; mismatch -> one
loud CRITICAL scanner-integrity finding and the scanner disables itself (the
PACK_LOAD_ERROR / B6 once-only pattern from scan_secrets.py).

Created by Alex Greenshpun
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forensics_core as core
import _context_gate

SCANNER_NAME = "yara"

# Optional dependency: yara-python (C extension on libyara). Never a hard dep.
try:
    import yara  # type: ignore
    YARA_AVAILABLE = True
except ImportError:
    yara = None  # type: ignore
    YARA_AVAILABLE = False

_YARA_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "data", "yara"))
_MANIFEST_PATH = os.path.join(_YARA_DIR, "manifest.json")

# Per-file wall-clock cap well under the runner's SCANNER_TIMEOUT=120.
_MATCH_TIMEOUT = 30
# Line resolution only for files that decode as UTF-8 and fit in memory.
_LINE_RESOLVE_MAX_BYTES = 1024 * 1024
# Snippet window around the first matched string.
_SNIPPET_RADIUS = 40

# Module globals populated by _verify_and_compile() on first use.
_RULES = None
_RULE_META = {}
_INTEGRITY_ERROR = False
_integrity_emitted = False


def _load_manifest():
    """Load and validate the YARA manifest. Returns (manifest, error_str)."""
    try:
        with open(_MANIFEST_PATH, "r", encoding="utf-8") as handle:
            manifest = __import__("json").load(handle)
    except (OSError, ValueError) as exc:
        return None, "manifest load failed: {}".format(exc)
    if not isinstance(manifest, dict):
        return None, "manifest is not a JSON object"
    return manifest, None


def _verify_files(manifest):
    """Verify each manifest.files[].sha256 against the on-disk .yar bytes.
    Returns (files_dict, error_str) where files_dict maps path->abspath."""
    files = manifest.get("files", [])
    if not isinstance(files, list) or not files:
        return None, "manifest.files missing or empty"
    out = {}
    for entry in files:
        if not isinstance(entry, dict):
            return None, "manifest.files entry is not an object"
        rel = entry.get("path", "")
        expected = entry.get("sha256", "")
        if not rel or not expected:
            return None, "manifest.files entry missing path or sha256"
        abs_path = os.path.join(_YARA_DIR, rel)
        try:
            with open(abs_path, "rb") as handle:
                actual = hashlib.sha256(handle.read()).hexdigest()
        except OSError as exc:
            return None, "rule file {} unreadable: {}".format(rel, exc)
        if actual.lower() != expected.lower():
            return None, ("rule file {} sha256 mismatch (expected {}, got {}); "
                          "rule pack may be tampered or corrupted".format(
                              rel, expected, actual))
        out[rel] = abs_path
    return out, None


def _verify_and_compile():
    """Load manifest, verify sha256 of every .yar, compile. Sets module globals.
    Returns True on success, False on integrity/compile failure (with
    _INTEGRITY_ERROR set)."""
    global _RULES, _RULE_META, _INTEGRITY_ERROR, _INTEGRITY_REASON
    if _RULES is not None or _INTEGRITY_ERROR:
        return _RULES is not None

    manifest, err = _load_manifest()
    if manifest is None:
        _INTEGRITY_ERROR = True
        _INTEGRITY_REASON = err
        return False
    rule_meta = manifest.get("rule_meta", {})
    if not isinstance(rule_meta, dict):
        _INTEGRITY_ERROR = True
        _INTEGRITY_REASON = "manifest.rule_meta is not an object"
        return False

    files, verr = _verify_files(manifest)
    if files is None:
        _INTEGRITY_ERROR = True
        _INTEGRITY_REASON = verr
        return False

    try:
        # Compile each .yar under its own namespace (filename) so rule names
        # from different families cannot collide.
        filepaths = {rel: path for rel, path in files.items()}
        _RULES = yara.compile(filepaths=filepaths)
        _RULE_META = rule_meta
        return True
    except Exception as exc:  # yara.SyntaxError / yara.CompileError etc.
        _INTEGRITY_ERROR = True
        _INTEGRITY_REASON = "yara compile failed: {}".format(exc)
        return False


# Reason string for the integrity finding (set when _INTEGRITY_ERROR is True).
_INTEGRITY_REASON = ""


def _integrity_finding(rel_path):
    """The single loud diagnostic emitted (once per scanner run) when the YARA
    rule pack failed integrity verification or compilation. Critical so it
    cannot be missed; the operator is told to reinstall."""
    return core.Finding(
        scanner=SCANNER_NAME, severity="critical",
        title="YARA rule pack failed integrity verification",
        description=("data/yara/ manifest sha256 mismatch or compile error ({}); "
                     "signature scanning is disabled. Reinstall repo-forensics "
                     "to restore detection.".format(_INTEGRITY_REASON)),
        file=rel_path, line=0,
        snippet="yara rule pack failed integrity verification",
        category="scanner-integrity",
        evidence_class="direct",
    )


def _first_match_offset(match):
    """Extract the byte offset of the first matched string from a yara Match,
    handling both the 4.2 tuple shape and the 4.3+ StringMatch shape."""
    strings = getattr(match, "strings", None)
    if not strings:
        return None
    first = strings[0]
    # yara-python 4.3+: StringMatch with .instances (list of StringMatchInstance)
    instances = getattr(first, "instances", None)
    if instances:
        inst = instances[0]
        offset = getattr(inst, "offset", None)
        if offset is not None:
            return offset
        tup = getattr(inst, "match", None)  # older internal
        if isinstance(tup, tuple) and tup:
            return tup[0]
    # yara-python 4.2: tuple (offset, identifier, data)
    if isinstance(first, tuple) and len(first) >= 1:
        return first[0]
    # Fallback: object with .offset
    offset = getattr(first, "offset", None)
    return offset


def _first_match_data(match):
    """Extract the raw bytes of the first matched string for snippet building."""
    strings = getattr(match, "strings", None)
    if not strings:
        return b""
    first = strings[0]
    instances = getattr(first, "instances", None)
    if instances:
        inst = instances[0]
        data = getattr(inst, "matched_data", None) or getattr(inst, "data", None)
        if data:
            return data if isinstance(data, (bytes, bytearray)) else bytes(data)
        tup = getattr(inst, "match", None)
        if isinstance(tup, tuple) and len(tup) >= 3 and isinstance(tup[2], (bytes, bytearray)):
            return bytes(tup[2])
    if isinstance(first, tuple) and len(first) >= 3 and isinstance(first[2], (bytes, bytearray)):
        return bytes(first[2])
    return b""


def _resolve_line(file_path, offset):
    """Convert a byte offset to a 1-based line for files <= 1MB that decode as
    UTF-8. Returns 0 when line resolution is not possible."""
    try:
        if os.path.getsize(file_path) > _LINE_RESOLVE_MAX_BYTES:
            return 0
        with open(file_path, "rb") as handle:
            data = handle.read()
        data.decode("utf-8")  # raises on non-utf8
    except (OSError, UnicodeDecodeError, ValueError):
        return 0
    if offset is None or offset < 0 or offset > len(data):
        return 0
    # Count newlines up to offset (bisect-style: linear is fine for <=1MB).
    return data.count(b"\n", 0, offset) + 1


def _make_snippet(file_path, match_bytes):
    """repr()-style snippet of <=80 bytes around the first matched string,
    non-printables stripped so raw binary never lands in JSON."""
    try:
        with open(file_path, "rb") as handle:
            data = handle.read()
    except OSError:
        data = match_bytes or b""
    if match_bytes:
        idx = data.find(match_bytes) if data else -1
        if idx >= 0:
            start = max(0, idx - _SNIPPET_RADIUS)
            end = min(len(data), idx + len(match_bytes) + _SNIPPET_RADIUS)
            window = data[start:end]
        else:
            window = match_bytes
    else:
        window = data[:80]
    # Strip non-printables; keep a compact repr.
    text = window.decode("utf-8", "replace")
    cleaned = "".join(ch if ch.isprintable() or ch in ("\t", " ") else "."
                      for ch in text)
    cleaned = cleaned.replace("\t", " ").strip()
    if len(cleaned) > 80:
        cleaned = cleaned[:77] + "..."
    return "match: {}".format(cleaned) if cleaned else "match: <bytes>"


def _evidence_class_for_match(rel_path, content=None):
    """Classify the carrier file's context and gate the match's
    evidence_class per the YARA policy (design §3.1/§3.4).

    code/binary/config with no demoting flags -> ``direct`` (live payload / live
    miner config stay at manifest severity). prose-doc / agent-instruction /
    test-fixture / blocklist -> ``inferred`` (YARA matches code artifacts, not
    prose directives; a webshell's bytes inside SKILL.md are inert until
    extracted+executed). The report layer caps severity->low + confidence->0.40
    and records original_severity (aggregate_json.apply_evidence_caps) -> the
    finding stays listed and auditable, never silently suppressed.

    ``content`` is the file bytes the caller already read (for the snippet). It
    is threaded into the classifier so the shebang upgrade fires for an
    extensionless script (``tests/setup`` with a ``#!`` line) -> code -> direct,
    instead of demoting to inferred -> LOW -> exit 0. Fail closed: an unknown
    executable carrier must not be graded down by an attacker-chosen folder.
    Integrity/timeout/read-error findings keep ``direct`` and do NOT route
    through this helper.
    """
    file_ctx = _context_gate.classify_file_context(rel_path, content=content)
    return _context_gate.gate_evidence(file_ctx, policy="yara")


def _emit_match_finding(match, file_path, rel_path):
    """Build a Finding for one YARA match using manifest rule_meta."""
    rule_name = match.rule
    meta = _RULE_META.get(rule_name)
    if meta is None:
        # Unknown rule: a tamper signal (rule in .yar but not in manifest).
        return core.Finding(
            scanner=SCANNER_NAME, severity="critical",
            title="YARA rule not registered in manifest",
            description=("Rule '{}' matched but is absent from "
                         "data/yara/manifest.json rule_meta; the rule pack may "
                         "be tampered.".format(rule_name)),
            file=rel_path, line=0,
            snippet="unregistered rule: {}".format(rule_name),
            category="scanner-integrity",
            evidence_class="direct",
        )
    offset = _first_match_offset(match)
    match_bytes = _first_match_data(match)
    line = _resolve_line(file_path, offset)
    snippet = _make_snippet(file_path, match_bytes)
    # Read the carrier bytes so the classifier can run the shebang upgrade for
    # an extensionless script (#! first line -> code -> direct). classify caps
    # at 1MB and degrades to path-only on None, so an over-cap or unreadable
    # file still fails closed via the extension set.
    try:
        with open(file_path, "rb") as handle:
            file_content = handle.read(_context_gate._CONTENT_MAX_BYTES + 1)
    except OSError:
        file_content = None
    return core.Finding(
        scanner=SCANNER_NAME,
        severity=meta.get("severity", "medium"),
        title=meta.get("title", rule_name),
        description=meta.get("explanation", meta.get("title", rule_name)),
        file=rel_path,
        line=line,
        snippet=snippet,
        category=meta.get("category", "malware"),
        rule_id=meta.get("id", ""),
        confidence=meta.get("confidence", 0.70),
        attacker=meta.get("attacker", ""),
        boundary=meta.get("boundary", ""),
        asset=meta.get("asset", ""),
        evidence_class=_evidence_class_for_match(rel_path, content=file_content),
    )


def scan_file(file_path, rel_path):
    """Scan one file with the compiled YARA rules. Returns a list of Findings."""
    global _integrity_emitted
    if not YARA_AVAILABLE:
        return []
    if not _verify_and_compile():
        # B6: emit the integrity diagnostic only on the first call.
        if not _integrity_emitted:
            _integrity_emitted = True
            return [_integrity_finding(rel_path)]
        return []
    findings = []
    try:
        matches = _RULES.match(file_path, timeout=_MATCH_TIMEOUT)
    except yara.TimeoutError:
        return [core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title="YARA scan timed out",
            description="File exceeded the per-file YARA timeout ({}s); "
                        "signature scan incomplete for this file.".format(
                            _MATCH_TIMEOUT),
            file=rel_path, line=0,
            snippet="yara match timeout",
            category="scan-incomplete",
            evidence_class="direct",
        )]
    except Exception as exc:
        # Unreadable / unreadable-as-bytes: honest LOW scan-incomplete.
        return [core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title="YARA scan could not read file",
            description="YARA could not scan this file ({}); signature scan "
                        "incomplete for this file.".format(exc),
            file=rel_path, line=0,
            snippet="yara read error",
            category="scan-incomplete",
            evidence_class="direct",
        )]
    # Determinism: sort matches by rule name.
    for match in sorted(matches, key=lambda m: m.rule):
        findings.append(_emit_match_finding(match, file_path, rel_path))
    return findings


def _sanitize_rel_path(rel_path):
    """Normalize a caller-supplied rel_path before it reaches a Finding or
    SARIF uri (FIX 2 / DEFECT-1). Forward-slash-converts backslashes and
    collapses ``.`` / ``..`` segments so an emitted path can never carry a
    ``..`` that resolves outside SRCROOT. A leading ``..`` that escapes root
    (``../../evil.php``) is dropped, mirroring walk_aux's os.path.relpath
    normalization. Never raises; unknown input passes through unchanged."""
    if not rel_path:
        return ""
    try:
        norm = rel_path.replace("\\", "/")
        parts = []
        for p in norm.split("/"):
            if p == "" or p == ".":
                continue
            if p == "..":
                if parts:
                    parts.pop()
                # leading ``..`` with nothing to pop: drop (neutralize).
                continue
            parts.append(p)
        return "/".join(parts)
    except Exception:
        return rel_path


def scan_text(text, rel_path):
    """YARA scan over an in-memory text blob (archive-recursion seam parity
    with scan_secrets.scan_text). Not wired into scan_archive in v2.13.0."""
    global _integrity_emitted
    # FIX 2 / DEFECT-1: normalize the caller-supplied rel_path before it is
    # used in any Finding.file / SARIF uri / classifier call. Do NOT fix in
    # sarif_export alone — the text/JSON Finding.file would still carry ``..``.
    rel_path = _sanitize_rel_path(rel_path)
    if not YARA_AVAILABLE:
        return []
    if not _verify_and_compile():
        if not _integrity_emitted:
            _integrity_emitted = True
            return [_integrity_finding(rel_path)]
        return []
    findings = []
    try:
        data = text.encode("utf-8", "replace") if isinstance(text, str) else bytes(text)
        matches = _RULES.match(data=data, timeout=_MATCH_TIMEOUT)
    except yara.TimeoutError:
        return [core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title="YARA scan timed out",
            description="In-memory blob exceeded the per-file YARA timeout; "
                        "signature scan incomplete.".format(_MATCH_TIMEOUT),
            file=rel_path, line=0,
            snippet="yara match timeout",
            category="scan-incomplete",
            evidence_class="direct",
        )]
    except Exception as exc:
        return [core.Finding(
            scanner=SCANNER_NAME, severity="low",
            title="YARA scan could not read blob",
            description="YARA could not scan the in-memory blob ({}); "
                        "signature scan incomplete.".format(exc),
            file=rel_path, line=0,
            snippet="yara read error",
            category="scan-incomplete",
            evidence_class="direct",
        )]
    for match in sorted(matches, key=lambda m: m.rule):
        # Line resolution over an in-memory blob: not provided (no file path).
        meta = _RULE_META.get(match.rule)
        if meta is None:
            findings.append(_emit_match_finding(match, "", rel_path))
            continue
        match_bytes = _first_match_data(match)
        snippet = _make_snippet("", match_bytes)
        findings.append(core.Finding(
            scanner=SCANNER_NAME,
            severity=meta.get("severity", "medium"),
            title=meta.get("title", match.rule),
            description=meta.get("explanation", meta.get("title", match.rule)),
            file=rel_path, line=0,
            snippet=snippet,
            category=meta.get("category", "malware"),
            rule_id=meta.get("id", ""),
            confidence=meta.get("confidence", 0.70),
            attacker=meta.get("attacker", ""),
            boundary=meta.get("boundary", ""),
            asset=meta.get("asset", ""),
            evidence_class=_evidence_class_for_match(rel_path),
        ))
    return findings


def main():
    args = core.parse_common_args(sys.argv, "YARA Scanner")
    repo_path = args.repo_path

    if not YARA_AVAILABLE:
        # Degradation: one stderr line with the "not found" enrichment marker.
        # build_enrichment_status greps scanner stderr for "not found" -> a
        # missing-tool capability gap. Stdout gets [] via output_findings; exit 0.
        print("[!] scan_yara: yara-python not found; signature scan skipped "
              "(install yara-python to enable)", file=sys.stderr)
        core.output_findings([], args.format, SCANNER_NAME)
        return

    core.emit_status(args.format, f"[*] Scanning for YARA signatures in {repo_path}...")

    ignore_patterns = core.load_ignore_patterns(repo_path)
    if ignore_patterns:
        core.emit_status(args.format, f"[*] Loaded {len(ignore_patterns)} custom ignore patterns from .forensicsignore")

    all_findings = []
    for file_path, rel_path in core.walk_aux(repo_path, ignore_patterns, apply_size_cap=True):
        findings = scan_file(file_path, rel_path)
        all_findings.extend(findings)

    core.output_findings(all_findings, args.format, SCANNER_NAME)


if __name__ == "__main__":
    main()
