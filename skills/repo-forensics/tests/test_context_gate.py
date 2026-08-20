"""test_context_gate.py - context classifier tests (design §2 / §6 step 1).

Every signal positive + negative; unclosed-fence fail-safe (must fail toward
``prose``, NOT demote); Windows ``\\`` paths; bare-basename inputs (the teeth
shape scan_yara passes). Deterministic + offline + stdlib-only; never raises.
"""

import os
import sys

import pytest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS_DIR = os.path.join(_TESTS_DIR, "..", "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import _context_gate as gate  # noqa: E402


# ---------------------------------------------------------------------------
# primary: positive + negative for each class
# ---------------------------------------------------------------------------

class TestPrimary:
    def test_agent_instruction_wins_over_md_extension(self):
        # SKILL.md is .md but is agent-instruction, not prose-doc.
        ctx = gate.classify_file_context("SKILL.md")
        assert ctx.primary == "agent-instruction"

    def test_claude_md_is_agent_instruction(self):
        assert gate.classify_file_context("CLAUDE.md").primary == "agent-instruction"

    def test_agents_md_nested_is_agent_instruction(self):
        assert gate.classify_file_context("sub/AGENTS.md").primary == "agent-instruction"

    def test_copilot_instructions_is_agent_instruction(self):
        ctx = gate.classify_file_context(".github/copilot-instructions.md")
        assert ctx.primary == "agent-instruction"

    def test_prose_doc_via_extension(self):
        assert gate.classify_file_context("webshell-101.md").primary == "prose-doc"

    def test_prose_doc_via_docs_path_segment(self):
        # A doc-extension file under docs/ is prose context (design §2.2 rule 2).
        assert gate.classify_file_context("docs/intro.md").primary == "prose-doc"

    def test_code_ext_under_docs_not_demoted(self):
        # FIX 1: a code extension under docs/ is code, not prose-doc. docs is a
        # route, not a sandbox; .php/.sh/.bat under docs/ are runnable.
        ctx = gate.classify_file_context("docs/foo.py")
        assert ctx.primary == "code"
        assert gate.gate_evidence(ctx, policy="yara") == "direct"

    def test_prose_doc_via_doc_path_segment(self):
        assert gate.classify_file_context("doc/intro.txt").primary == "prose-doc"

    def test_prose_doc_via_readme_basename(self):
        assert gate.classify_file_context("README.md").primary == "prose-doc"

    def test_prose_doc_via_txt_extension(self):
        assert gate.classify_file_context("cheatsheet.txt").primary == "prose-doc"

    def test_code_via_php_extension(self):
        assert gate.classify_file_context("shell.php").primary == "code"

    def test_code_via_bat_extension(self):
        assert gate.classify_file_context("dropper.bat").primary == "code"

    def test_code_via_jsp_extension(self):
        assert gate.classify_file_context("shell.jsp").primary == "code"

    def test_code_via_ps1_extension(self):
        assert gate.classify_file_context("run.ps1").primary == "code"

    def test_config_via_json_extension(self):
        assert gate.classify_file_context("config.json").primary == "config"

    def test_config_via_yaml_extension(self):
        assert gate.classify_file_context("miner.yaml").primary == "config"

    def test_binary_no_extension(self):
        assert gate.classify_file_context("x.bin").primary == "binary"

    def test_binary_unknown_extension(self):
        assert gate.classify_file_context("payload.xyz").primary == "binary"

    def test_binary_exe(self):
        assert gate.classify_file_context("malware.exe").primary == "binary"


# ---------------------------------------------------------------------------
# Shebang upgrade (optional content signal): no-ext file -> code
# ---------------------------------------------------------------------------

class TestShebangUpgrade:
    def test_shebang_bash_upgrades_binary_to_code(self):
        ctx = gate.classify_file_context("hookscript", content="#!/bin/bash\necho hi\n")
        assert ctx.primary == "code"

    def test_shebang_env_python_upgrades(self):
        ctx = gate.classify_file_context("drop", content="#!/usr/bin/env python3\nimport os\n")
        assert ctx.primary == "code"

    def test_shebang_unknown_interp_stays_binary(self):
        ctx = gate.classify_file_context("weird", content="#!/usr/bin/env xyz\n")
        assert ctx.primary == "binary"

    def test_no_shebang_stays_binary(self):
        ctx = gate.classify_file_context("plain", content="just text\n")
        assert ctx.primary == "binary"

    def test_shebang_oversize_content_ignored(self):
        big = "#!/bin/bash\n" + "x" * (gate._CONTENT_MAX_BYTES + 10)
        ctx = gate.classify_file_context("big", content=big)
        assert ctx.primary == "binary"

    def test_shebang_not_probed_without_content(self):
        # No content supplied -> no shebang probe (never touches filesystem).
        ctx = gate.classify_file_context("hookscript")
        assert ctx.primary == "binary"


# ---------------------------------------------------------------------------
# is_test_fixture: path segment + anchored basename, exact segment equality
# ---------------------------------------------------------------------------

class TestTestFixture:
    def test_tests_segment(self):
        assert gate.classify_file_context("tests/test_x.py").is_test_fixture

    def test_test_segment(self):
        # Non-code carrier under a test/ segment still reads as a fixture.
        assert gate.classify_file_context("test/foo.bin").is_test_fixture

    def test_test_segment_does_not_demote_code(self):
        # The PATH-SEGMENT signal must not fire on an executable
        # carrier. `tests/` is attacker-choosable, and a live webshell parked
        # there was demoted to LOW purely by folder name.
        assert not gate.classify_file_context("test/foo.py").is_test_fixture

    def test_underscore_tests_segment(self):
        assert gate.classify_file_context("src/__tests__/copilot.test.ts").is_test_fixture

    def test_fixtures_segment(self):
        assert gate.classify_file_context("fixtures/webshell.bin").is_test_fixture

    def test_spec_segment(self):
        assert gate.classify_file_context("spec/thing.bin").is_test_fixture
        # ...but not for a code carrier.
        assert not gate.classify_file_context("spec/thing.py").is_test_fixture
        # ...nor for a config carrier: a live miner config under spec/ is
        # operational data, not a fixture.
        assert not gate.classify_file_context("spec/thing.json").is_test_fixture

    def test_golden_segment(self):
        assert gate.classify_file_context("golden/pack.bin").is_test_fixture

    def test_test_underscore_py_basename(self):
        assert gate.classify_file_context("test_webshells.py").is_test_fixture

    def test_x_test_go_basename(self):
        assert gate.classify_file_context("foo_test.go").is_test_fixture

    def test_dot_test_js_basename(self):
        assert gate.classify_file_context("foo.test.js").is_test_fixture

    def test_dot_spec_tsx_basename(self):
        assert gate.classify_file_context("bar.spec.tsx").is_test_fixture

    def test_conftest_py(self):
        assert gate.classify_file_context("conftest.py").is_test_fixture

    def test_negative_substring_not_segment(self):
        # Substring sloppiness must NOT trip: "latest/" and "protest/" contain
        # "test" as a substring but not as an exact segment (design §2.2).
        assert not gate.classify_file_context("latest/x.py").is_test_fixture
        assert not gate.classify_file_context("protest/x.py").is_test_fixture

    def test_negative_plain_code(self):
        assert not gate.classify_file_context("shell.php").is_test_fixture

    def test_negative_bare_basename_no_test_marker(self):
        # The teeth shape: bare basename with no test marker.
        assert not gate.classify_file_context("YR-WEB-001.bin").is_test_fixture


# ---------------------------------------------------------------------------
# is_blocklist: filename token + path segment + content shape
# ---------------------------------------------------------------------------

class TestBlocklist:
    def test_blocklist_txt_filename(self):
        # FIX 1: the basename-token signal fires on non-code extensions
        # (.txt is a doc extension); a real filter list named blocklist.txt.
        ctx = gate.classify_file_context("blocklist.txt")
        assert ctx.is_blocklist

    def test_blacklist_filename(self):
        assert gate.classify_file_context("blacklist.txt").is_blocklist

    def test_easylist_filename(self):
        assert gate.classify_file_context("easylist.txt").is_blocklist

    def test_denylist_path_segment(self):
        assert gate.classify_file_context("denylists/rules.txt").is_blocklist

    def test_filter_lists_segment(self):
        assert gate.classify_file_context("filter-lists/x.txt").is_blocklist

    def test_hyphen_delimited_token(self):
        # FIX 1: hyphen-delimited token fires on a non-code extension.
        assert gate.classify_file_context("my-blocklist-v2.txt").is_blocklist

    def test_underscore_delimited_token(self):
        assert gate.classify_file_context("ublock_filters.txt").is_blocklist

    def test_content_filter_rules_dominant(self):
        content = "||ads.example.com^\n||tracker.io^\n! comment\n||malware.net^"
        ctx = gate.classify_file_context("oddname.txt", content=content)
        assert ctx.is_blocklist

    def test_negative_plain_js(self):
        assert not gate.classify_file_context("app.js").is_blocklist

    def test_negative_config_json(self):
        # A real .json config must NOT trip the blocklist content signal.
        content = '{"url": "stratum+tcp://pool.x:3333", "algo": "rx/0"}'
        ctx = gate.classify_file_context("config.json", content=content)
        assert not ctx.is_blocklist

    def test_negative_substring_not_token(self):
        # "blocked" contains "block" but not the delimited token "blocklist".
        assert not gate.classify_file_context("blocked.js").is_blocklist


# ---------------------------------------------------------------------------
# is_security_doc: basename stem in {security, privacy}
# ---------------------------------------------------------------------------

class TestSecurityDoc:
    def test_security_md(self):
        assert gate.classify_file_context("SECURITY.md").is_security_doc

    def test_privacy_txt(self):
        assert gate.classify_file_context("privacy.txt").is_security_doc

    def test_readme_is_not_security_doc(self):
        # readme is deliberately NOT a security doc (attack real estate).
        assert not gate.classify_file_context("README.md").is_security_doc

    def test_changelog_is_not_security_doc(self):
        assert not gate.classify_file_context("CHANGELOG.md").is_security_doc


# ---------------------------------------------------------------------------
# Windows backslash paths (parity with _is_doc_file normalization)
# ---------------------------------------------------------------------------

class TestWindowsPaths:
    def test_backslash_tests_segment(self):
        ctx = gate.classify_file_context("tests\\test_x.py")
        assert ctx.is_test_fixture

    def test_backslash_docs_segment(self):
        ctx = gate.classify_file_context("docs\\webshell.md")
        assert ctx.primary == "prose-doc"

    def test_backslash_agent_instruction(self):
        ctx = gate.classify_file_context("sub\\SKILL.md")
        assert ctx.primary == "agent-instruction"

    def test_backslash_blocklist(self):
        ctx = gate.classify_file_context("denylists\\rules.txt")
        assert ctx.is_blocklist


# ---------------------------------------------------------------------------
# Bare-basename inputs (the teeth shape scan_yara passes: "YR-WEB-001.bin")
# ---------------------------------------------------------------------------

class TestBareBasename:
    def test_bin_bare_basename_is_binary_direct(self):
        ctx = gate.classify_file_context("YR-WEB-001.bin")
        assert ctx.primary == "binary"
        assert not ctx.is_test_fixture
        assert gate.gate_evidence(ctx, policy="yara") == "direct"

    def test_php_bare_basename_is_code_direct(self):
        ctx = gate.classify_file_context("shell.php")
        assert ctx.primary == "code"
        assert gate.gate_evidence(ctx, policy="yara") == "direct"

    def test_json_bare_basename_is_config_direct(self):
        ctx = gate.classify_file_context("config.json")
        assert ctx.primary == "config"
        assert gate.gate_evidence(ctx, policy="yara") == "direct"


# ---------------------------------------------------------------------------
# classify_line_context: prose fence tracking + comment/string detection
# ---------------------------------------------------------------------------

class TestLineContextProse:
    def test_prose_line_outside_fence(self):
        content = "intro\nsome prose line\n```\ncode\n```\nafter\n"
        assert gate.classify_line_context("x.md", content, 2) == "prose"

    def test_line_inside_closed_fence_is_fenced_code(self):
        content = "intro\n```\nshell -c x\n```\nafter\n"
        # line 3 is inside the closed fence (open=2, close=4).
        assert gate.classify_line_context("x.md", content, 3) == "fenced-code"

    def test_fence_line_itself_is_prose(self):
        content = "intro\n```\ncode\n```\n"
        # The opening fence line (2) is not strictly inside -> prose.
        assert gate.classify_line_context("x.md", content, 2) == "prose"

    def test_unclosed_fence_fails_toward_prose(self):
        # Fail-safe: an unclosed fence must NOT mark the remainder fenced.
        # Lines after the lone ``` must classify as prose (loud), not fenced.
        content = "intro\n```\nshell -c x\nmore shell\n"  # no closing fence
        assert gate.classify_line_context("x.md", content, 3) == "prose"
        assert gate.classify_line_context("x.md", content, 4) == "prose"

    def test_multiple_closed_fences(self):
        content = "a\n```\nb\n```\nc\n```\nd\n```\ne\n"
        # line 3 inside first block, line 7 inside second block.
        assert gate.classify_line_context("x.md", content, 3) == "fenced-code"
        assert gate.classify_line_context("x.md", content, 7) == "fenced-code"
        # line 5 is between blocks -> prose.
        assert gate.classify_line_context("x.md", content, 5) == "prose"

    def test_indented_fence_and_language_tag(self):
        content = "intro\n  ```python\nshell -c x\n  ```\n"
        # line 3 inside the closed indented+tagged fence.
        assert gate.classify_line_context("x.md", content, 3) == "fenced-code"

    def test_agent_instruction_file_uses_fence_tracking(self):
        content = "# Skill\n```\n$(find .)\n```\n"
        assert gate.classify_line_context("SKILL.md", content, 3) == "fenced-code"
        assert gate.classify_line_context("SKILL.md", content, 1) == "prose"


class TestLineContextCode:
    def test_hash_comment(self):
        content = "x = 1\n# exfil $HOME\ny = 2\n"
        assert gate.classify_line_context("a.py", content, 2) == "comment-or-string"

    def test_slash_comment(self):
        content = "a;\n// todo: eval(x)\nb;\n"
        assert gate.classify_line_context("a.js", content, 2) == "comment-or-string"

    def test_quoted_string_line(self):
        content = "x\n'eval(gzinflate(base64_decode))'\ny\n"
        assert gate.classify_line_context("a.py", content, 2) == "comment-or-string"

    def test_log_call_line(self):
        content = "x\nprint('eval(x)')\ny\n"
        assert gate.classify_line_context("a.py", content, 2) == "comment-or-string"

    def test_executable_code_line(self):
        content = "x = 1\nsystem($_POST['c'])\ny = 2\n"
        assert gate.classify_line_context("shell.php", content, 2) == "code-line"

    def test_config_comment(self):
        content = '{"a": 1}\n# a comment\n'
        assert gate.classify_line_context("config.yaml", content, 2) == "comment-or-string"


# ---------------------------------------------------------------------------
# gate_evidence: YARA policy (design §3.1)
# ---------------------------------------------------------------------------

class TestYaraPolicy:
    def test_code_direct(self):
        assert gate.gate_evidence(
            gate.classify_file_context("shell.php"), policy="yara") == "direct"

    def test_binary_direct(self):
        assert gate.gate_evidence(
            gate.classify_file_context("x.bin"), policy="yara") == "direct"

    def test_config_direct(self):
        assert gate.gate_evidence(
            gate.classify_file_context("config.json"), policy="yara") == "direct"

    def test_prose_doc_inferred(self):
        assert gate.gate_evidence(
            gate.classify_file_context("x.md"), policy="yara") == "inferred"

    def test_docs_path_inferred(self):
        assert gate.gate_evidence(
            gate.classify_file_context("docs/x.md"), policy="yara") == "inferred"

    def test_test_fixture_inferred(self):
        assert gate.gate_evidence(
            gate.classify_file_context("tests/test_x.py"), policy="yara") == "inferred"

    def test_blocklist_inferred(self):
        # FIX 1: blocklist demotion via the basename-token signal fires on a
        # non-code extension (config .json — the §9 accepted residual). A code
        # extension carrying the token is NOT demoted (see TestGatingEvasionFix).
        assert gate.gate_evidence(
            gate.classify_file_context("blocklist.json"), policy="yara") == "inferred"

    def test_agent_instruction_inferred(self):
        # YARA maps agent-instruction -> inferred (inert payload until
        # extracted+executed; the asymmetry vs MH, design §3.1).
        assert gate.gate_evidence(
            gate.classify_file_context("SKILL.md"), policy="yara") == "inferred"

    def test_flags_win_over_primary(self):
        # A binary fixture under tests/ -> inferred (flag wins over primary; a
        # bare binary would otherwise map to direct). CODE and CONFIG
        # carriers under tests/ no longer set the flag at all, so the
        # flag-vs-primary precedence is shown with a binary carrier.
        ctx = gate.classify_file_context("tests/payload.bin")
        assert ctx.primary == "binary"
        assert ctx.is_test_fixture
        assert gate.gate_evidence(ctx, policy="yara") == "inferred"

    def test_unknown_policy_defaults_direct(self):
        # Unknown policy name -> loud default, never raises.
        ctx = gate.classify_file_context("x.md")
        assert gate.gate_evidence(ctx, policy="nope") == "direct"


# ---------------------------------------------------------------------------
# FIX 1 regression teeth: extension-blind doc/blocklist demotion (batch-4 FN).
# A live payload on an executable extension MUST win primary="code" / direct
# over the doc-basename stem, the doc path segment, and the blocklist basename
# token. 26 batch-4 variants collapse to these representative cases.
# ---------------------------------------------------------------------------

# Each carrier is a code extension carrying a doc basename stem, a docs/ path
# segment, and/or a blocklist basename token. All MUST classify code/direct.
GATING_EVASION_CASES = [
    "readme.php",          # doc basename stem on .php (root cause 1)
    "changelog.php",       # doc basename stem on .php
    "license.bat",         # doc basename stem on .bat
    "readme.jsp",          # doc basename stem on .jsp
    "docs/shell.php",      # docs path segment on .php (root cause 2)
    "documentation/x.php", # documentation path segment on .php
    "v1/docs/index.php",   # docs segment mid-path on .php
    "blacklist.bat",       # blocklist token on .bat (root cause 3)
    "denylist.php",        # blocklist token on .php
    "nocoin.sh",           # blocklist token on .sh
]


class TestGatingEvasionFix:
    """FIX 1: an executable extension wins code/direct over doc/blocklist
    basename + path-segment signals. The exit-code gate must not be defeated
    by a filename or directory choice."""

    @pytest.mark.parametrize("rel_path", GATING_EVASION_CASES)
    def test_code_ext_wins_over_doc_and_blocklist_signals(self, rel_path):
        ctx = gate.classify_file_context(rel_path)
        assert ctx.primary == "code", (
            f"{rel_path}: primary was {ctx.primary!r}, expected 'code' "
            f"(executable extension must not be demoted by a doc/blocklist "
            f"basename or path-segment signal)")
        assert ctx.is_blocklist is False, (
            f"{rel_path}: is_blocklist was True; a blocklist basename token on "
            f"a code extension is a dropper/webshell, not a filter list")
        assert gate.gate_evidence(ctx, policy="yara") == "direct", (
            f"{rel_path}: gate_evidence was not 'direct'; a live payload on an "
            f"executable extension must stay at manifest severity / exit-2")

    # --- must-still-pass (gauntlet-confirmed; do not regress) ---

    def test_webshell_in_md_still_demotes(self):
        # .md is a doc extension -> prose-doc -> inferred (inert until executed).
        ctx = gate.classify_file_context("webshell-101.md")
        assert ctx.primary == "prose-doc"
        assert gate.gate_evidence(ctx, policy="yara") == "inferred"

    def test_webshell_in_skill_md_still_demotes(self):
        ctx = gate.classify_file_context("SKILL.md")
        assert ctx.primary == "agent-instruction"
        assert gate.gate_evidence(ctx, policy="yara") == "inferred"

    def test_webshell_under_tests_stays_direct(self):
        # Was an accepted residual, now a closed bypass: YARA is the
        # only byte-signature detector, so demoting a live tests/shell.php to
        # LOW by folder name blinded it entirely. The folder is chosen by the
        # scanned repo — it cannot be allowed to grade its own payload.
        ctx = gate.classify_file_context("tests/shell.php")
        assert ctx.primary == "code"
        assert ctx.is_test_fixture is False
        assert gate.gate_evidence(ctx, policy="yara") == "direct"

    def test_named_test_file_still_demotes(self):
        # The anchored BASENAME signals are unchanged: they carry the real FP
        # mass (dozens of test_*.py loading modules under test) and the name is
        # descriptive of actual test code, not just a folder.
        ctx = gate.classify_file_context("tests/test_loader.py")
        assert ctx.is_test_fixture is True

    def test_blocklist_json_config_still_demotes(self):
        # §9 accepted residual: a miner config named blocklist.json (config ext,
        # blocklist basename token) -> inferred.
        ctx = gate.classify_file_context("blocklist.json")
        assert ctx.primary == "config"
        assert ctx.is_blocklist is True
        assert gate.gate_evidence(ctx, policy="yara") == "inferred"

    def test_readme_dir_with_index_php_is_direct(self):
        # readme is a DIR here, not a basename stem; index.php is code -> direct.
        ctx = gate.classify_file_context("readme/index.php")
        assert ctx.primary == "code"
        assert gate.gate_evidence(ctx, policy="yara") == "direct"

    def test_agent_instruction_wins_over_code_extension(self):
        # SKILL.md is agent-instruction even though .md would be prose-doc; no
        # code extension is ever named SKILL.md, so this precedence is safe.
        ctx = gate.classify_file_context("SKILL.md")
        assert ctx.primary == "agent-instruction"


# ---------------------------------------------------------------------------
# C1 regression teeth: executable extensions that were MISSING from _CODE_EXTS
# (the shell carriers .ksh/.command/.bashrc/.profile plus .gradle/.scpt/
# .applescript/.osascript/.wsf/.awk/.ahk/.nse) must fold into the code carve-out
# on the content-less YARA path. Before the fix these got primary='binary',
# code_carrier=False, and a tests/ fixtures/ golden/ filters/ denylists/ path
# segment demoted their YARA match to inferred -> LOW -> exit 0, while
# _is_comment_or_string treated .command/.ksh as never-inert (an internal
# contradiction). Fail closed: a runnable carrier is never graded down by an
# attacker-chosen folder.
# ---------------------------------------------------------------------------
_EXEC_CARRIER_EXTS = [
    ".ksh", ".command", ".bashrc", ".profile",
    ".gradle", ".scpt", ".applescript", ".osascript", ".wsf", ".awk",
    ".ahk", ".nse",
]
_DEMOTING_SEGMENTS = ["tests", "fixtures", "golden", "filters", "denylists"]


class TestExecutableExtensionCarrierNotDemoted:
    """C1: a content-less executable-extension carrier under a demoting folder
    must NOT be demoted by the YARA policy; a genuine prose .md under the same
    folder must still demote."""

    @pytest.mark.parametrize("ext", _EXEC_CARRIER_EXTS)
    @pytest.mark.parametrize("segment", _DEMOTING_SEGMENTS)
    def test_exec_carrier_under_demoting_folder_stays_direct(self, ext, segment):
        rel_path = "{}/evil{}".format(segment, ext)
        ctx = gate.classify_file_context(rel_path)  # NO content
        assert ctx.is_test_fixture is False, (
            f"{rel_path}: is_test_fixture was True; an executable extension "
            f"must not be treated as a folder-demoted fixture")
        assert ctx.is_blocklist is False, (
            f"{rel_path}: is_blocklist was True; an executable extension under "
            f"a denylist/filter folder is a dropper, not a filter list")
        assert gate.gate_evidence(ctx, policy="yara") == "direct", (
            f"{rel_path}: gate_evidence was not 'direct'; a content-less "
            f"executable carrier must stay at manifest severity / exit-2 "
            f"regardless of the folder it is parked in")

    @pytest.mark.parametrize("segment", _DEMOTING_SEGMENTS)
    def test_prose_md_under_demoting_folder_still_demotes(self, segment):
        rel_path = "{}/notes.md".format(segment)
        ctx = gate.classify_file_context(rel_path)
        assert ctx.primary == "prose-doc"
        assert gate.gate_evidence(ctx, policy="yara") == "inferred", (
            f"{rel_path}: genuine prose .md must still demote to inferred; "
            f"the fix is additive to code extensions only")


# ---------------------------------------------------------------------------
# FIX 3 regression teeth: .. collapse before segment-membership checks.
# A demoting segment the path escaped must not fire.
# ---------------------------------------------------------------------------

class TestTraversalCollapse:
    """FIX 3 / DEFECT-2: .. segments are collapsed before is_test_fixture /
    is_blocklist / prose-doc segment membership is evaluated."""

    @pytest.mark.parametrize("rel_path", [
        "tests/../shell.php", "tests\\..\\shell.php",
        "docs/../shell.php", "docs\\..\\shell.php",
        "denylists/../evil.php", "denylists\\..\\evil.php",
        "v1/docs/../index.php",
    ])
    def test_escaped_demoting_segment_does_not_demote(self, rel_path):
        ctx = gate.classify_file_context(rel_path)
        assert ctx.primary == "code", (
            f"{rel_path}: primary was {ctx.primary!r}; the escaped demoting "
            f"segment must not classify prose-doc/test/blocklist")
        assert ctx.is_test_fixture is False
        assert ctx.is_blocklist is False
        assert gate.gate_evidence(ctx, policy="yara") == "direct"

    def test_real_tests_segment_still_demotes(self):
        # A non-escaped tests/ segment still demotes a NON-code carrier
        # (regression guard for the '..' collapse, not for code demotion).
        ctx = gate.classify_file_context("tests/payload.bin")
        assert ctx.is_test_fixture is True
        assert gate.gate_evidence(ctx, policy="yara") == "inferred"


# ---------------------------------------------------------------------------
# Never raises + determinism
# ---------------------------------------------------------------------------

class TestRobustness:
    def test_empty_rel_path_loud(self):
        ctx = gate.classify_file_context("")
        # Empty -> no doc/code/config signal -> binary (loud for YARA).
        assert ctx.primary == "binary"
        assert gate.gate_evidence(ctx, policy="yara") == "direct"

    def test_none_rel_path_loud(self):
        ctx = gate.classify_file_context(None)
        assert ctx.primary == "binary"

    def test_garbage_rel_path_does_not_raise(self):
        # Should not raise on weird input.
        ctx = gate.classify_file_context("\x00\x01\x02")
        assert ctx.primary in ("binary", "code", "config", "prose-doc",
                               "agent-instruction")

    def test_classify_line_context_none_content_does_not_raise(self):
        out = gate.classify_line_context("x.md", None, 5)
        assert out == "prose"

    def test_classify_line_context_bad_line_no_does_not_raise(self):
        out = gate.classify_line_context("x.md", "a\nb\n", -1)
        assert out in ("prose", "code-line")

    def test_determinism_same_input_same_output(self):
        a = gate.classify_file_context("tests/test_x.py")
        b = gate.classify_file_context("tests/test_x.py")
        assert a == b

    def test_file_context_equality_and_hash(self):
        a = gate.classify_file_context("shell.php")
        b = gate.classify_file_context("shell.php")
        assert a == b
        assert hash(a) == hash(b)
        assert a != gate.classify_file_context("x.md")


# ---------------------------------------------------------------------------
# Regression teeth: CONFIG carriers join the code-carrier carve-out.
# A live miner/exfil config is operational data, not a fixture. Attacker-chosen
# FOLDER placement (tests/ fixtures/ golden/ spec/ mocks/ ... or filters/
# denylists/ blocklists/) must NOT set is_test_fixture / is_blocklist on a
# config carrier, which _yara_policy would otherwise map inferred -> LOW ->
# exit 0, blinding the only byte-signature detector on a live critical payload.
# ---------------------------------------------------------------------------

# (rel_path, expected_primary) — each a config carrier under a demoting folder.
R4_CONFIG_CARRIER_CASES = [
    ("tests/config.json", "config"),      # test-fixture path segment
    ("fixtures/config.json", "config"),
    ("golden/config.json", "config"),
    ("spec/config.yaml", "config"),
    ("mocks/config.toml", "config"),
    ("filters/config.yaml", "config"),    # blocklist path segment
    ("denylists/config.env", "config"),
    ("blocklists/data.xml", "config"),
]


class TestConfigCarrierNotDemoted:
    """A config carrier under a test-fixture or blocklist folder keeps its
    loud context. Mirrors the code-carrier carve-out and
    scan_skill_threats._mh_gate_demotes, which already lists 'config'."""

    @pytest.mark.parametrize("rel_path,expected_primary", R4_CONFIG_CARRIER_CASES)
    def test_config_carrier_folder_does_not_demote(self, rel_path, expected_primary):
        ctx = gate.classify_file_context(rel_path)
        assert ctx.primary == expected_primary, (
            f"{rel_path}: primary was {ctx.primary!r}, expected "
            f"{expected_primary!r}")
        assert not ctx.is_test_fixture, (
            f"{rel_path}: is_test_fixture set on a config carrier — folder "
            f"placement must not demote operational data")
        assert not ctx.is_blocklist, (
            f"{rel_path}: is_blocklist set on a config carrier")

    @pytest.mark.parametrize("rel_path,_", R4_CONFIG_CARRIER_CASES)
    def test_config_carrier_yara_stays_direct(self, rel_path, _):
        # The whole point: YARA evidence class stays 'direct' (loud), so a live
        # critical payload is not graded down to inferred -> LOW -> exit 0.
        ctx = gate.classify_file_context(rel_path)
        assert gate.gate_evidence(ctx, policy="yara") == "direct"

    def test_content_blocklist_shape_not_applied_to_config(self):
        # Even blocklist-shaped CONTENT must not flag a config carrier under a
        # blocklist folder (the content-shape branch is also code_carrier-gated).
        content = "||ads.example.com^\n||tracker.io^\n||malware.net^"
        ctx = gate.classify_file_context("filters/rules.json", content=content)
        assert not ctx.is_blocklist
        assert gate.gate_evidence(ctx, policy="yara") == "direct"

    def test_code_carrier_under_tests_still_direct(self):
        # No regression: code carriers under tests/ already stay loud/direct.
        ctx = gate.classify_file_context("tests/shell.php")
        assert ctx.primary == "code"
        assert not ctx.is_test_fixture
        assert gate.gate_evidence(ctx, policy="yara") == "direct"

    def test_prose_doc_under_tests_still_demotes(self):
        # No regression: a genuine prose .md under tests/ still demotes
        # (intended FP suppression — YARA maps prose-doc -> inferred).
        ctx = gate.classify_file_context("tests/notes.md")
        assert ctx.primary == "prose-doc"
        assert ctx.is_test_fixture
        assert gate.gate_evidence(ctx, policy="yara") == "inferred"
