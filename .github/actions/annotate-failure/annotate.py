"""Print the tails of log files as GitHub `::error` annotations.

GitHub keeps at most ten error annotations per step and stores at most 4096
characters of each message (it drops the rest, end first), so the output is
cut into chunks under that size: the failure-looking lines first, then each
file's tail, cut from its end so the last chunk is the log's real end. Nine
are published; the tenth slot stays free for the step's own failure.
"""

import glob
import os
import re
import sys

MAX_ANNOTATIONS = 9
MAX_CHUNK = 4_000
MAX_SUMMARY_CHUNKS = 3
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


def read(path: str) -> str:
    with open(path, "rb") as handle:
        data = handle.read()
    return ANSI.sub("", data.decode("utf-8", errors="replace"))


DIGITS = re.compile(r"\d+")


def without_progress(lines: list[str]) -> list[str]:
    """Drops a percentage that the next line repeats but for its numbers (a
    progress meter: apt's "Reading database ... 45%")."""
    out = []
    for i, line in enumerate(lines):
        following = lines[i + 1] if i + 1 < len(lines) else None
        if (
            "%" in line
            and following is not None
            and DIGITS.sub("#", line) == DIGITS.sub("#", following)
        ):
            continue
        out.append(line)
    return out


def fit(line: str) -> str:
    """A line cut to the chunk size (bytes, on a character boundary)."""
    return line.encode("utf-8")[: MAX_CHUNK - 1].decode("utf-8", errors="ignore")


def size(line: str) -> int:
    return len(line.encode("utf-8")) + 1


def chunks_from_start(lines: list[str], limit: int) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    used = 0
    for line in map(fit, lines):
        if used + size(line) > MAX_CHUNK:
            chunks.append("\n".join(current))
            if len(chunks) == limit:
                return chunks
            current, used = [], 0
        current.append(line)
        used += size(line)
    if current:
        chunks.append("\n".join(current))
    return chunks[:limit]


def chunks_from_end(lines: list[str], limit: int) -> list[str]:
    """The last `limit` chunks of `lines`, in order: the final one ends with
    the last line."""
    reverse = chunks_from_start([fit(line) for line in reversed(lines)], limit)
    return ["\n".join(reversed(chunk.split("\n"))) for chunk in reversed(reverse)]


FAILURE = re.compile(
    r"panicked at|(?i:\berror)(\[E\d+\])?:|\bERROR\b|FAILED|FAIL[: ]|^---- .+ ----$|fatal:"
    r"|failed to|\bfailed:|No such file or directory|command not found|exit code [1-9]"
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
        summary = chunks_from_start("\n".join(collected).splitlines(), MAX_SUMMARY_CHUNKS)
        for index, chunk in enumerate(summary, start=1):
            title = f"error lines (whole log, part {index}/{len(summary)})"
            print(f"::error title={escape_property(title)}::{escape_data(chunk)}")
            budget -= 1
    # Then each file's tail, the budget shared among the files left.
    tails = [(path, without_progress(read(path).splitlines()[-lines:])) for path in files]
    tails = [(path, text) for path, text in tails if any(line.strip() for line in text)]
    for left, (path, text) in zip(range(len(tails), 0, -1), tails):
        if budget == 0:
            return
        chunks = chunks_from_end(text, max(1, budget // left))
        for index, chunk in enumerate(chunks, start=1):
            name = os.path.basename(path)
            title = f"{name} (last {lines} lines, part {index}/{len(chunks)})"
            print(f"::error title={escape_property(title)}::{escape_data(chunk)}")
            budget -= 1


if __name__ == "__main__":
    main()
