"""
profile_loader.py -- Issue #320: loads a target codebase's function-name
sets (by role: arith/reduce/check), name-matching mode, source language,
expected check-site order, and FIPS 204 thresholds from a profile file
under profiles/<name>.json.

Before this module, all of that lived hardcoded in m1b_site_finder.py
(TARGET_PROFILES) and task.py (SITE_ORDER_BY_FUNCTION/KNOWN_SITE_LABELS) --
adding a target meant editing those .py files. Adding a target now means
adding a new profiles/<name>.json file; --target-profile's choices and
cli.py's --std default are both derived from what's on disk, not a
hardcoded list.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

PROFILES_DIR = Path(__file__).resolve().parent / "profiles"

_VALID_LANGUAGES = ("c", "cpp")
_VALID_MATCH_MODES = ("exact", "suffix")


class ProfileError(Exception):
    """A profile file is missing, malformed, or internally inconsistent --
    always raised with an actionable message (Issue #320: "явная ошибка с
    понятным сообщением, без пустого отчёта"), never a silently empty
    report."""


@dataclass(frozen=True)
class SiteLabel:
    label: str
    hi: int


@dataclass(frozen=True)
class TargetProfile:
    name: str
    language: str                          # "c" | "cpp" -- drives cli.py's --std default
    match_mode: str                        # "exact" | "suffix"
    arith: frozenset[str]
    reduce: frozenset[str]
    check: frozenset[str]
    site_labels: dict[str, SiteLabel]
    site_order_default: tuple[str, ...]
    site_order_by_function: dict[str, tuple[str, ...]]

    def site_order_for(self, function_name: str) -> tuple[str, ...]:
        return self.site_order_by_function.get(function_name, self.site_order_default)


def available_profiles() -> list[str]:
    """Profile names with a profiles/<name>.json file on disk -- used for
    cli.py's --target-profile choices, so a new profile file is enough to
    make a new target selectable, no .py edit needed."""
    return sorted(p.stem for p in PROFILES_DIR.glob("*.json"))


def load_profile(name: str) -> TargetProfile:
    path = PROFILES_DIR / f"{name}.json"
    if not path.exists():
        known = ", ".join(available_profiles()) or "(none found)"
        raise ProfileError(
            f"target profile {name!r} not found at {path} -- available profiles: {known}"
        )

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProfileError(f"profile {name!r} ({path}) is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise ProfileError(f"profile {name!r} ({path}) could not be read: {exc}") from exc

    for key in ("language", "match_mode", "functions", "site_labels", "site_order"):
        if key not in raw:
            raise ProfileError(f"profile {name!r} ({path}) is missing required field {key!r}")

    language = raw["language"]
    if language not in _VALID_LANGUAGES:
        raise ProfileError(
            f"profile {name!r}: language must be one of {_VALID_LANGUAGES}, got {language!r}"
        )

    match_mode = raw["match_mode"]
    if match_mode not in _VALID_MATCH_MODES:
        raise ProfileError(
            f"profile {name!r}: match_mode must be one of {_VALID_MATCH_MODES}, got {match_mode!r}"
        )

    functions = raw["functions"]
    roles: dict[str, frozenset[str]] = {}
    for role in ("arith", "reduce", "check"):
        names = functions.get(role)
        if not names:
            raise ProfileError(
                f"profile {name!r}: functions.{role} is missing or empty -- "
                f"every profile needs at least one function name per role"
            )
        roles[role] = frozenset(names)

    site_labels: dict[str, SiteLabel] = {}
    for key, entry in raw["site_labels"].items():
        if "label" not in entry or "hi" not in entry:
            raise ProfileError(
                f"profile {name!r}: site_labels.{key} needs both 'label' and 'hi'"
            )
        try:
            hi = int(entry["hi"])
        except (TypeError, ValueError) as exc:
            raise ProfileError(
                f"profile {name!r}: site_labels.{key}.hi must be an integer, got {entry['hi']!r}"
            ) from exc
        site_labels[key] = SiteLabel(label=str(entry["label"]), hi=hi)

    if not site_labels:
        raise ProfileError(f"profile {name!r}: site_labels must declare at least one site")

    site_order = raw["site_order"]
    default_order = site_order.get("default")
    if not default_order:
        raise ProfileError(f"profile {name!r}: site_order.default is missing or empty")
    for key in default_order:
        if key not in site_labels:
            raise ProfileError(
                f"profile {name!r}: site_order.default references undeclared site {key!r} "
                f"(known sites: {sorted(site_labels)})"
            )

    by_function: dict[str, tuple[str, ...]] = {}
    for func_name, order in site_order.get("by_function", {}).items():
        for key in order:
            if key not in site_labels:
                raise ProfileError(
                    f"profile {name!r}: site_order.by_function[{func_name!r}] references "
                    f"undeclared site {key!r} (known sites: {sorted(site_labels)})"
                )
        by_function[func_name] = tuple(order)

    return TargetProfile(
        name=name,
        language=language,
        match_mode=match_mode,
        arith=roles["arith"],
        reduce=roles["reduce"],
        check=roles["check"],
        site_labels=site_labels,
        site_order_default=tuple(default_order),
        site_order_by_function=by_function,
    )
