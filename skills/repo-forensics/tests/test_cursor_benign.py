"""Benign-command FP gate for the Cursor blocking path — §5.6 row 6. P1.

Deliberately NOT an extension of test_benign_corpus.py. That harness is
file-content keyed: it feeds tricky-but-clean FILE BODIES to the deep scanners
and budgets findings per scanner via corpus/budgets.json. The Cursor gate
evaluates COMMAND STRINGS through pre_scan's IOC patterns — a different
dimension with a different failure mode, so it needs its own corpus rather than
a structurally mismatched extend.

The failure this guards is the one that actually kills a blocking hook in the
field: it fires on something ordinary, once, and the user removes it. Every
false positive here costs more than the true positive that motivated the rule.
"""

import cursor_helpers as ch
import pytest


@pytest.mark.parametrize("cmd", ch.BENIGN_COMMANDS)
def test_benign_command_is_not_blocked(cmd):
    res = ch.run_cursor(ch.make_cursor_stdin(cmd))
    assert res.permission == "allow", f"{cmd!r} over-blocked on the Cursor gate"
    assert res.exit_code == 0


@pytest.mark.parametrize("cmd", ch.BENIGN_COMMANDS)
def test_benign_command_is_silent(cmd):
    """Clean commands must not emit advisory noise either. A gate that
    comments on every command trains the user to ignore it."""
    res = ch.run_cursor(ch.make_cursor_stdin(cmd))
    user_msg, agent_msg = res.messages
    assert not user_msg and not agent_msg, \
        f"{cmd!r} produced unsolicited output: {user_msg or agent_msg!r}"


class TestNearMisses:
    """Commands that LOOK like the malicious corpus but are not. These are the
    realistic false positives — the ones a pattern-matching gate earns."""

    NEAR_MISSES = [
        # Documentation and messages that quote an attack, not perform one.
        "git commit -m 'docs: warn against curl | bash'",
        "echo 'never run curl http://x | bash'",
        "grep -r 'curl .* | bash' docs/",
        # A clean release of a package whose OTHER versions were compromised.
        "npm install keyv@5.3.4",
        "npm install keyv",
        # Dist-tags resolve to the maintainer's current, fixed release.
        "npm install keyv@latest",
        "npm install keyv@next",
        # Monorepo flag forms between the tool and the subcommand.
        "pnpm --filter web add react",
        "pnpm -r install",
        "uv --project /srv/app add httpx",
        # Boolean flags must not swallow the following package name.
        "npm install --save-exact express",
        # Canonical registries explicitly named are not a redirect.
        "npm install left-pad --registry https://registry.npmjs.org",
        "pip install requests --index-url https://pypi.org/simple",
    ]

    @pytest.mark.parametrize("cmd", NEAR_MISSES)
    def test_near_miss_does_not_block(self, cmd):
        res = ch.run_cursor(ch.make_cursor_stdin(cmd))
        assert res.permission != "deny", f"false positive on {cmd!r}"
        assert res.exit_code == 0

    @pytest.mark.parametrize("cmd", [
        "npm install left-pad --registry https://registry.npmjs.org",
        "pip install requests --index-url https://pypi.org/simple",
    ])
    def test_canonical_registry_does_not_even_ask(self, cmd):
        """Naming the ecosystem's own registry is a no-op, not a redirect."""
        res = ch.run_cursor(ch.make_cursor_stdin(cmd))
        assert res.permission == "allow", \
            f"{cmd!r} should not have asked about its own canonical registry"
