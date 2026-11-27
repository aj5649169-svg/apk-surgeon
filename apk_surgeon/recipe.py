"""Declarative YAML patch recipes.

A recipe can add tracker package prefixes, exact concrete smali method
signatures, manifest components to disable and extra sinkhole domains.  It can
never add a protected shared domain; see :mod:`apk_surgeon.sinkhole`.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import sinkhole

DESCRIPTOR = re.compile(r"L[^;:()\s]+;")
SIGNATURE = re.compile(r"(?:L[^;:()\s]+;->)?[^:()\s<>]+\((?:\[*(?:[ZBCSIFJD]|L[^;()\s]+;))*\)(?:\[*(?:[ZBCSIFJD]|L[^;()\s]+;)|V)")
PACKAGE = re.compile(r"^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*$")
COMPONENT = re.compile(r"^[A-Za-z_.][\w.]*$")
ALLOWED = {"version", "package_prefixes", "methods", "disable_components", "sinkhole_domains", "notes"}
TOP_LEVEL_ERROR = "Recipe must be a mapping with any of: " + ", ".join(sorted(ALLOWED))


@dataclass
class Recipe:
    """Validated recipe contents."""

    path: Path | None = None
    package_prefixes: list = field(default_factory=list)
    methods: dict = field(default_factory=dict)
    disable_components: list = field(default_factory=list)
    sinkhole_domains: list = field(default_factory=list)
    custom_sinkhole_domains: list = field(default_factory=list)
    allow_custom_domains: bool = False

    def signatures(self):
        return {signature for values in self.methods.values() for signature in values}


def _fail(source, message):
    raise ValueError(f"Recipe {source}: {message}")


def _strings(source, value, key):
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        _fail(source, f"{key} must be a list of strings")
    return [item.strip() for item in value if item.strip()]


def loads(text, *, source="<inline>", allow_custom_domains=False):
    """Parse and validate recipe YAML text."""
    try:
        import yaml
    except ImportError as error:  # pragma: no cover - dependency is declared
        raise ValueError("YAML recipes need PyYAML. Install apk-surgeon with its declared dependencies.") from error
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ValueError(f"Recipe {source}: invalid YAML{where}: {getattr(error, 'problem', error)}") from error
    if raw is None:
        _fail(source, "file is empty")
    if not isinstance(raw, dict):
        _fail(source, TOP_LEVEL_ERROR)
    unknown = sorted(set(raw) - ALLOWED)
    if unknown:
        _fail(source, "unknown field(s): " + ", ".join(unknown) + ". " + TOP_LEVEL_ERROR)
    recipe = Recipe(path=Path(source) if source != "<inline>" else None)
    version = raw.get("version")
    if version is not None and version != 1:
        _fail(source, f"unsupported version {version!r} (expected 1)")
    for prefix in _strings(source, raw.get("package_prefixes"), "package_prefixes"):
        if not PACKAGE.match(prefix):
            _fail(source, f"package_prefixes entry {prefix!r} is not a dotted Java package")
        recipe.package_prefixes.append(prefix)
    for entry in raw.get("methods") or []:
        if isinstance(entry, str):
            if not DESCRIPTOR.search(entry) or not SIGNATURE.search(entry):
                _fail(source, f"methods entry {entry!r} must be a full 'Lpkg/Class;->name(args)Ret' signature")
            descriptor = DESCRIPTOR.search(entry).group(0)
            signature = entry.split("->", 1)[1] if "->" in entry else entry
            recipe.methods.setdefault(descriptor, set()).add(signature)
            continue
        if not isinstance(entry, dict) or set(entry) != {"class", "method"}:
            _fail(source, "methods entries must be strings or {class, method} mappings")
        descriptor, signature = str(entry["class"]), str(entry["method"])
        if not DESCRIPTOR.fullmatch(descriptor):
            _fail(source, f"methods class {descriptor!r} must be a smali descriptor like Lcom/example/Track;")
        if not SIGNATURE.fullmatch(signature):
            _fail(source, f"methods signature {signature!r} is not a concrete Dalvik signature")
        recipe.methods.setdefault(descriptor, set()).add(signature)
    for component in _strings(source, raw.get("disable_components"), "disable_components"):
        if not COMPONENT.match(component):
            _fail(source, f"disable_components entry {component!r} is not a class name")
        recipe.disable_components.append(component)
    domains = _strings(source, raw.get("sinkhole_domains"), "sinkhole_domains")
    recipe.sinkhole_domains = sinkhole.validate_recipe_domains(domains, allow_custom=allow_custom_domains)
    recipe.custom_sinkhole_domains = sinkhole.custom_domains(recipe.sinkhole_domains)
    recipe.allow_custom_domains = bool(allow_custom_domains)
    return recipe


def load(path, *, allow_custom_domains=False):
    """Load and validate a recipe file."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"Recipe {path}: cannot read file ({error})") from error
    return loads(text, source=path, allow_custom_domains=allow_custom_domains)
