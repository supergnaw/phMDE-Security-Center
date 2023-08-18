import re
from typing import Iterator, Match, Any, AnyStr, Pattern

re_flags = {
    "a": re.ASCII,
    "i": re.IGNORECASE,
    "l": re.LOCALE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
    "u": re.UNICODE,
    "x": re.VERBOSE
}


# SPECIALTY INTERNAL FUNCTIONS

def _parse_regex(pattern: Pattern[AnyStr], pre_flags: int = re.NOFLAG) -> Pattern[Any] | Pattern[str | Any]:
    if not re.fullmatch(r"^\/(.*)\/([\w]*)$", f"{pattern}"):
        return re.compile(pattern, pre_flags)

    pattern, flags = re.fullmatch(r"^\/(.*)\/([\w]*)$", f"{pattern}").groups()
    flags = _parse_flags(flags, pre_flags)

    return re.compile(pattern, flags)


def _parse_flags(flags: str = "", pre_flags: int = re.NOFLAG) -> int:
    parsed_flags = pre_flags
    flags = re.sub(r"[^ailmsux]", "", flags).strip()

    for character_flag in flags:
        parsed_flags |= re_flags.get(character_flag, re.NOFLAG)

    return parsed_flags


# UPDATED RE FUNCTIONS USING COMPILED REGEX

def compile(pattern: Pattern[AnyStr], flags: int = re.NOFLAG) -> re.Pattern:
    return _parse_regex(pattern, flags)


def search(pattern: bytes | Pattern[AnyStr], string: str, flags: int = re.NOFLAG) -> Match[bytes] | None | Match[str]:
    return re.search(_parse_regex(pattern, flags), string)


def match(pattern: bytes | Pattern[AnyStr], string: str, flags: int = re.NOFLAG) -> Match[bytes] | None | Match[str]:
    return re.match(_parse_regex(pattern, flags), string)


def fullmatch(pattern: bytes | Pattern[AnyStr], string: str, flags: int = re.NOFLAG) -> Match[bytes] | None | Match[str]:
    return re.fullmatch(_parse_regex(pattern, flags), string)


def split(pattern: bytes | Pattern[AnyStr], string: str, maxsplit: int = 0, flags: int = re.NOFLAG) -> list[bytes | Any] | list[str | Any]:
    return re.split(_parse_regex(pattern, flags), string, maxsplit, flags)


def findall(pattern: bytes | Pattern[AnyStr], string, flags: int = re.NOFLAG) -> list[Any]:
    return re.findall(_parse_regex(pattern, flags), string)


def finditer(pattern: bytes | Pattern[AnyStr], string, flags: int = re.NOFLAG) -> Iterator[Match[bytes]] | Iterator[Match[str]]:
    return re.finditer(_parse_regex(pattern, flags), string)


def sub(pattern: bytes | Pattern[AnyStr], repl, string, count: int = 0, flags: int = re.NOFLAG) -> bytes | str:
    return re.sub(_parse_regex(pattern, flags), repl, string, count)


def subn(pattern: bytes | Pattern[AnyStr], repl, string, count: int = 0, flags: int = re.NOFLAG) -> tuple[bytes, int] | tuple[str, int]:
    return re.subn(_parse_regex(pattern, flags), repl, string, count)
