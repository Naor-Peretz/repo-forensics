"""Self-healing guard for the suppression-bypass CLASS.

repo-forensics has two evidence engines that must agree on code-vs-doc:
  - forensics_core.infer_evidence_class  (governs sast/dataflow/correlation ->
    the report exit code)
  - _context_gate.classify_file_context  (governs yara/skill_threats/
    runtime_dynamism)

The docs/helper.py and readme.php bypasses shipped because these two drifted:
one engine was fixed, the other kept a naive copy of the logic. Both now share
core._is_doc_carrier. These tests fail CI if they EVER diverge again, and if a
finding's severity ever depends on the DIRECTORY a payload sits in.
"""

import os
import pytest
import forensics_core as core
import _context_gate as gate
import aggregate_json as agg


# A payload path matrix spanning every branch: doc ext, code ext, config ext,
# doc basename + code ext (readme.php), docs/ location + each ext type,
# unknown ext, Windows separators, casing, agent-instruction files.
_MATRIX = [
    "readme.md", "notes.rst", "guide.txt", "docs/intro.md", "docs/readme.md",
    "src/main.py", "docs/helper.py", "doc/util.js", "documentation/run.sh",
    "readme.php", "license.bat", "docs/shell.php", "changelog.sh", "app/x.jsp",
    "payload.hta", "macro.vbs", "handler.cgi",
    "config.yaml", "docs/config.json", "settings.toml", "docs/app.ini",
    "README", "LICENSE", "docs/CHANGELOG", "docs/weird", "weird", "x.unknownext",
    "DOCS/Helper.PY", "Docs/Shell.PHP", r"docs\shell.php", r"src\deep\a.py",
    "SKILL.md", "docs/SKILL.md", "CLAUDE.md",
    # Path-normalization edge cases (the matrix was thin here and the torture
    # gauntlet walked straight through it): escaped '..' segments, redundant
    # '.'/empty segments, and the Windows trailing-dot/space filename forms
    # that execute as the stripped name.
    "docs/../installer", "docs/../shell.py", "tests/../shell.php",
    "a/b/../../docs/x.py", "./docs/../x.py", ".//docs/x",
    "docs/./guide.md", "docs//guide.md", "readme/../x.py",
    "evil.py.", "evil.py ", "docs/shell.py ", "guide.md ", "readme.", "readme..",
    "docs/shell .py", "shell.py/..",
]

_SNIPPET = "subprocess.run(cmd, shell=True)"


class TestConstantsAreShared:
    """The two engines must reference the SAME set objects, not copies — the
    strongest anti-drift guarantee: identical by construction."""

    def test_code_exts_is_same_object(self):
        assert gate._CODE_EXTS is core._CODE_EXTS

    def test_config_exts_is_same_object(self):
        assert gate._CONFIG_EXTS is core._CONFIG_EXTS

    def test_gate_carrier_delegates_to_core(self):
        # Gate's carrier must return exactly what core's does for every input.
        for p in _MATRIX:
            norm = p.replace("\\", "/").lower()
            ext = os.path.splitext(norm)[1]
            stem = os.path.splitext(os.path.basename(norm))[0]
            parts = norm.split("/")
            assert gate._is_doc_carrier(ext, stem, parts) == \
                core._is_doc_carrier(ext, stem, parts), p


class TestEngineParity:
    """core._is_doc_file (demotion signal for the exit-code path) and the gate's
    prose-doc primary must agree on every path — a divergence is a live bypass."""

    @pytest.mark.parametrize("path", _MATRIX)
    def test_prose_doc_demotion_agrees(self, path):
        # Agent-instruction files (SKILL.md/CLAUDE.md/AGENTS.md) have their own
        # precedence branch in BOTH engines and are handled upstream in core's
        # infer_evidence_class (step 2), above the doc check — the gate ranks
        # agent-instruction above prose-doc. So the doc-carrier invariant is:
        # gate's prose-doc == core demotes-as-doc AND is-not-an-agent-instruction.
        core_demotes = core._is_doc_file(path) and \
            not core._is_agent_instruction_file(path)
        gate_demotes = (gate.classify_file_context(path).primary == "prose-doc")
        assert core_demotes == gate_demotes, (
            f"{path}: core doc-demote={core_demotes} but "
            f"gate.prose-doc={gate_demotes} — evidence engines diverged"
        )


class TestSeverityIsLocationInvariant:
    """Metamorphic: identical executable bytes must reach the SAME final
    severity and exit code no matter which directory (or obfuscated path) they
    sit in. This is the property the docs/helper.py bypass violated."""

    def _final_exit(self, path):
        ec = core.infer_evidence_class("sast", "dangerous-exec", path, _SNIPPET)
        findings = [{"scanner": "correlation", "severity": "critical",
                     "evidence_class": ec, "file": path, "confidence": 0.99}]
        agg.apply_evidence_caps(findings)
        summary = {"critical": sum(1 for f in findings if f["severity"] == "critical"),
                   "high": 0, "medium": 0}
        return findings[0]["severity"], agg.calculate_report_exit_code(
            summary, [{"parse_error": False, "exit_code": 0}])

    @pytest.mark.parametrize("directory", [
        "src", "docs", "doc", "documentation", "lib/docs", "docs/vendor",
        "a/b/c/docs", "DOCS",
    ])
    def test_same_payload_same_verdict_everywhere(self, directory):
        base_sev, base_exit = self._final_exit("src/helper.py")
        sev, code = self._final_exit(f"{directory}/helper.py")
        assert (sev, code) == (base_sev, base_exit), (
            f"{directory}/helper.py graded {(sev, code)} vs src {(base_sev, base_exit)}"
        )

    def test_executing_payload_is_critical_exit_2(self):
        # Sanity anchor: a real executing payload must NOT be silently cleared.
        sev, code = self._final_exit("docs/helper.py")
        assert sev == "critical" and code == 2


class TestCarrierCorrectness:
    """Parity guarantees the two engines AGREE; these guarantee they agree
    CORRECTLY. Executable/interpreted formats must NEVER demote to prose, even
    the long tail outside _CODE_EXTS — the fail-OPEN default on unknown
    extensions is what let docs/payload.command / readme.awk demote to exit 0.
    """

    # Executable or code-bearing carriers a doc/ folder or doc basename must not
    # launder into "documentation". Includes known-code, web-exec, build/CI, and
    # long-tail interpreted formats NOT in _CODE_EXTS.
    _MUST_NOT_DEMOTE = [
        "docs/helper.py", "docs/shell.php", "docs/app.jsp", "docs/x.hta",
        "docs/deploy.command", "docs/build.gradle", "docs/migrate.sql",
        # P0-8: extensionless files under docs/ fail CLOSED — `docs/install`
        # and friends are routinely executable stagers.
        "docs/install", "docs/bootstrap", "docs/architecture",
        "docs/notebook.ipynb", "docs/setup.tcl", "docs/run.awk", "docs/x.nim",
        "docs/a.coffee", "docs/b.clj", "docs/c.hs", "docs/d.erl", "docs/e.sc",
        "readme.php", "license.bat", "readme.command", "license.awk",
        "changelog.sh", "docs/Makefile", "docs/Dockerfile", "docs/Jenkinsfile",
        "documentation/configure", "docs/config.json", "docs/settings.yaml",
    ]

    @pytest.mark.parametrize("path", _MUST_NOT_DEMOTE)
    def test_executable_never_demoted(self, path):
        assert not core._is_doc_file(path), path
        assert core.infer_evidence_class("sast", "code-execution", path,
                                         "os.system(x)") == "direct", path
        assert gate.classify_file_context(path).primary != "prose-doc", path

    # Genuine documentation that SHOULD still demote (guards against over-
    # correction turning the scanner into a false-positive machine).
    _MUST_DEMOTE = [
        "docs/guide.md", "notes.rst", "docs/intro.txt",
        "CHANGELOG.md", "README.md", "LICENSE.txt",
        # NOTE: an extensionless file under docs/ is deliberately NOT here.
        # P0-8 made that case fail CLOSED (see _MUST_NOT_DEMOTE): only a doc
        # BASENAME (readme/license/...) demotes without an extension.
        # R1: extensionless doc BASENAMES ("README"/"LICENSE") are ALSO NOT here
        # any more — on the content-less path they fail CLOSED (a prose README
        # carries a .md/.txt extension; an extensionless script named `readme`
        # is the attack). Covered by test_forensics_core's R1 regression tests.
    ]

    @pytest.mark.parametrize("path", _MUST_DEMOTE)
    def test_real_docs_still_demote(self, path):
        assert core._is_doc_file(path), path
