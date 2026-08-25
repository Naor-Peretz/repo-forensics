"""Cross-platform invocation of the repo's .sh entrypoints.

Windows cannot exec a shell script as a program -- `subprocess.run(["x.sh"])`
raises OSError [WinError 193] "not a valid Win32 application" -- and there is no
`/bin/bash` to hardcode either ([WinError 2]). Both mistakes were in the suite,
and together they accounted for 33 of the 49 failures the first Windows CI run
reported.

The product genuinely requires bash on Windows (run_forensics.sh and
python-launcher.sh are bash, and python-launcher.sh already carries explicit
Windows handling), so routing through a resolved bash is the honest fix rather
than skipping the tests. GitHub's windows-latest images ship Git for Windows,
which puts bash on PATH.
"""

import os
import shutil

# Git for Windows' default locations, checked only if bash is not already on
# PATH. Ordered most- to least-likely.
_WINDOWS_BASH_CANDIDATES = (
    r"C:\Program Files\Git\bin\bash.exe",
    r"C:\Program Files (x86)\Git\bin\bash.exe",
    r"C:\Program Files\Git\usr\bin\bash.exe",
)


def find_bash():
    """Absolute path to a usable bash, or None."""
    found = shutil.which("bash")
    if found:
        return found
    if os.name == "nt":
        for candidate in _WINDOWS_BASH_CANDIDATES:
            if os.path.isfile(candidate):
                return candidate
    for candidate in ("/bin/bash", "/usr/bin/bash"):
        if os.path.isfile(candidate):
            return candidate
    return None


def sh_argv(script, *args):
    """argv that runs *script* through bash on any platform.

    On POSIX the script's shebang would do, but going through bash there too
    keeps one code path and removes any dependence on the executable bit
    surviving a checkout.
    """
    bash = find_bash()
    if bash is None:
        raise RuntimeError(
            "no bash interpreter found; the repo's .sh entrypoints cannot run. "
            "On Windows install Git for Windows.")
    return [bash, str(script), *[str(a) for a in args]]


def bash_c(script_text):
    """argv for `bash -c <script_text>`, portable."""
    bash = find_bash()
    if bash is None:
        raise RuntimeError("no bash interpreter found")
    return [bash, "-c", script_text]
