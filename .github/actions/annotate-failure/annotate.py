"""Print the tails of log files as GitHub `::error` annotations.

GitHub keeps at most ten error annotations per step and caps a message at
64 KiB, so the tails are split into chunks under that size and the first
nine are published (the tenth slot stays free for the step's own failure).
"""

import glob
import os
import re
import sys

MAX_ANNOTATIONS = 9
MAX_CHUNK = 60_000
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: str) -> str:
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def files_for(pattern: str) -> list[str]:
    pattern = pattern.replace("\\", "/")
    if any(c in pattern for c in "*?["):
        matches = glob.glob(pattern, recursive=True)
    else:
        matches = [pattern] if os.path.exists(pattern) else []
    out: list[str] = []
    for match in matches:
        if os.path.isdir(match):
            found = [
                os.path.join(root, name)
                for root, _, names in os.walk(match)
                for name in names
                if name.endswith((".log", ".txt"))
            ]
            out.extend(sorted(found, key=os.path.getmtime, reverse=True))
        elif os.path.isfile(match):
            out.append(match)
    return out


def tail(path: str, lines: int) -> str:
    with open(path, "rb") as handle:
        data = handle.read()
    text = ANSI.sub("", data.decode("utf-8", errors="replace"))
    return "\n".join(text.splitlines()[-lines:])


FAILURE = re.compile(
    r"panicked at|^\s*error(\[E\d+\])?:|FAILED|FAIL[: ]|^---- .+ ----$|^Error:|fatal:|failed to"
)


def failure_lines(text: str, context: int = 3) -> str:
    """Every line that looks like a failure, anywhere in the log, with the
    lines after it (a panic's message, a test's assertion)."""
    lines = text.splitlines()
    keep: list[int] = []
    for i, line in enumerate(lines):
        if FAILURE.search(line):
            keep.extend(range(i, min(i + 1 + context, len(lines))))
    seen: set[int] = set()
    out = []
    for i in keep:
        if i not in seen:
            seen.add(i)
            out.append(lines[i])
    return "\n".join(out)


def main() -> None:
    # Windows runners print in cp1252, which has no U+FFFD (the replacement
    # character the logs are read with).
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    lines = int(os.environ.get("ANNOTATE_LINES") or "150")
    temp = os.environ.get("RUNNER_TEMP", "")
    patterns = [os.path.join(temp, "step-output.log")] if temp else []
    patterns += [p.strip() for p in os.environ.get("ANNOTATE_PATHS", "").splitlines() if p.strip()]
    seen: set[str] = set()
    files = []
    for pattern in patterns:
        for path in files_for(pattern):
            real = os.path.realpath(path)
            if real not in seen:
                seen.add(real)
                files.append(path)
    if not files:
        print("::notice title=annotate-failure::no log files matched")
        return
    budget = MAX_ANNOTATIONS
    # First: the failure-looking lines of every file, wherever they are (a
    # test's panic can sit far above a long tail).
    collected = []
    for path in files:
        with open(path, "rb") as handle:
            text = ANSI.sub("", handle.read().decode("utf-8", errors="replace"))
        found = failure_lines(text)
        if found:
            collected.append(f"== {os.path.basename(path)}\n{found}")
    if collected:
        summary = "\n".join(collected)
        summary = summary.encode("utf-8")[:MAX_CHUNK].decode("utf-8", errors="ignore")
        print(f"::error title={escape_property('error lines (whole log)')}::{escape_data(summary)}")
        budget -= 1
    for path in files:
        text = tail(path, lines)
        if not text.strip():
            continue
        chunks = []
        while text:
            # Split on a line boundary under the size cap (bytes, as GitHub counts).
            piece = text.encode("utf-8")[:MAX_CHUNK].decode("utf-8", errors="ignore")
            if len(piece) < len(text) and "\n" in piece:
                piece = piece[: piece.rindex("\n") + 1]
            chunks.append(piece)
            text = text[len(piece):]
        for index, chunk in enumerate(chunks, start=1):
            if budget == 0:
                return
            name = os.path.basename(path)
            title = f"{name} (last {lines} lines, part {index}/{len(chunks)})"
            print(f"::error title={escape_property(title)}::{escape_data(chunk)}")
            budget -= 1


if __name__ == "__main__":
    main()
