# Cursor hook contract — verified against the shipping client

Everything in `hooks/cursor/`, `scripts/cursor_install.py` and the `cursor`
adapter in `hook_adapter.py` was originally written against a *reading of
Cursor's documentation*. The handoff that specified the work flagged this as
its own biggest risk (K6, an M0 blocker): "the adapter evals need real Cursor
stdin captured from a live instance; the docs shape is not enough."

This file records what the real client actually does, so the next person does
not have to trust a doc summary either. Two independent sources: the shipped
application bundle, and a live capture.

Verified against **Cursor 3.17.19** (released 2026-08-24) on 2026-08-25.

---

## 1. Where Cursor reads hooks from

Three scopes, all read by `workbench.glass.main.js`:

| Scope | Path |
|---|---|
| User | `userHome()/.cursor/hooks.json` |
| Project | `<workspaceFolder>/.cursor/hooks.json` |
| Enterprise | `/etc/cursor/hooks.json` · `/Library/Application Support/Cursor/hooks.json` · `C:\ProgramData\Cursor\hooks.json` |

`cursor_install.py` installs to **user scope** by default. `--scope project`
writes the workspace copy instead.

Cursor also reads `.claude/settings.json` from workspace folders for project
hooks — a Claude Code compatibility path, not something this adapter uses.

## 2. How Cursor consumes the verdict

From the shipped bundle (`extensionHostProcess.js`), reformatted:

```js
const i = yield e.executeHookForStep(
    _._E.beforeShellExecution,
    Object.assign(Object.assign({}, t), { command: n, cwd: o, sandbox: s })
);
if ("deny" === (i?.permission)) {
    const e = x("Command execution", i.user_message);
    throw new T(e);                    // command never runs
}
if ("ask" === (i?.permission))
    return (0, r.$b)(i.user_message);  // prompts the human
```

Three things follow, and all three are load-bearing for this adapter:

- The **input** carries exactly `command`, `cwd`, `sandbox` on top of the shared
  envelope. Those are the four fields `_parse_cursor()` reads.
- `deny` **throws**, using `user_message`. Anything not `deny`/`ask` proceeds.
- **`ask` is real.** The handoff was unsure whether to define this tier or drop
  it (`pre_scan.py` had no such verdict). Cursor implements it, so defining it
  was correct.

`sessionStart` is validated by a separate `sessionStartResponse.ts` which
accepts `additional_context` — *not* a permission triple. A session cannot be
denied, so `session_scan.py` emits `{"additional_context": ...}` there and `{}`
when it has nothing to say.

## 3. The real stdin envelope

Captured live from `beforeShellExecution`. Session identifiers and the account
address are redacted; everything else is verbatim:

```json
{
  "conversation_id": "<uuid>",
  "generation_id":   "<uuid>",
  "model":           "grok-4.6",
  "command":         "npm install keyv@6.0.0",
  "cwd":             "/tmp/keyv-test",
  "sandbox":         false,
  "session_id":      "<uuid>",
  "hook_event_name": "beforeShellExecution",
  "cursor_version":  "3.17.19",
  "workspace_roots": [],
  "user_email":      "<redacted>",
  "transcript_path": null
}
```

### What the docs did not say

- **`session_id`, `user_email`, `transcript_path` exist** and appear in no
  documentation. `user_email` is the signed-in account — treat the envelope as
  carrying PII. The evidence logger in `hooks/cursor/run_pre_scan.sh` redacts
  `user_email` and `transcript_path` before anything reaches disk.
- **`cwd` arrives as an empty string** and **`workspace_roots` as an empty
  list** when the agent has no folder open. Validating either as required would
  fail closed on every command in a folderless session — the gate would look
  broken rather than strict. `tests/test_cursor_adapter.py::TestRealCapturedEnvelope`
  pins both.

The adapter reads past every unknown field. That tolerance was a design choice
before this capture existed; the capture is the first evidence it was the right
one.

## 4. Live end-to-end verification

Asked the Cursor agent: *"In the terminal, cd to /tmp/keyv-test and run:
npm install keyv@6.0.0"*.

```
process chain  : cursor <- cursor <- systemd
command        : "npm install keyv@6.0.0"
verdict        : deny (exit 2)
```

The process chain has no shell and no test harness in it — Cursor invoked the
hook itself. Cursor then refused, and relayed our message:

> I did not run that install. `keyv@6.0.0` **is a known compromised package**
> (Shai-Hulud / keyv-cacheable campaign, August 2026), so installing it would
> put malware on this machine.

`/tmp/keyv-test` was left empty. The campaign name in the agent's reply comes
from `data/compromised_versions.json`, not from the model's own knowledge —
which is the point: the model had no reason to distrust a pinned version of a
popular package.

## 5. Choosing a demo command

`curl <url> | bash` is **not** a useful demonstration. Grok 4.6 refuses it
before issuing any tool call:

> I will not run that command. `curl … | bash` downloads whatever that URL
> returns and executes it locally… that is asking me to run untrusted remote
> code.

No tool call means no `beforeShellExecution`, so the gate never sees it. The
honest demonstration is an IOC-pinned install that looks unremarkable to a
model. The blocker earns its keep exactly where the model is blind, and a demo
that picks an obviously-malicious command is testing the model's safety layer
rather than this one.

`keyv@6.0.0` is also safe to demo with: npm's latest `keyv` is 5.6.0, so the
version does not resolve. Even a total gate failure yields a registry error
rather than a live payload. Pick demo commands that are safe to be wrong about.
