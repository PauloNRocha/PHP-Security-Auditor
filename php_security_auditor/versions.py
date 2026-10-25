"""Avaliação fail closed por pacote de fornecedor."""
from __future__ import annotations

import json
import re
from importlib.resources import files
from urllib.parse import urlsplit

from .system import System

PHP_PACKAGE = re.compile(r"^(?:php\d+\.\d+(?:-[a-z0-9+.-]+)?|libapache2-mod-php\d+\.\d+)$")
BRANCH = re.compile(r"(?:^php|^libapache2-mod-php)(\d+\.\d+)")
POLICY_VERSION = re.compile(r"^\s*(?:\*\*\*\s+)?(\S+)\s+-?\d+(?:\s+\(phased (?:100|[1-9]?\d)%\))?\s*$")
POLICY_VERSION_CANDIDATE = re.compile(r"^\s*(?:\*\*\*\s+)?(\S+)\s+-?\d+(?:\s+.*)?$")
POLICY_SOURCE = re.compile(r"^\s+-?\d+\s+(.+?(?:Packages|/var/lib/dpkg/status))\s*$")


def database() -> dict:
    return json.loads(files("php_security_auditor").joinpath("data/advisories.json").read_text())


def _policy_sources(output: str, version: str | None = None) -> dict[str, list[dict[str, str]]]:
    """Relaciona cada índice APT com seus metadados; versão filtra policy PACOTE."""
    sources: dict[str, list[dict[str, str]]] = {}
    active = version is None
    current: dict[str, str] | None = None
    invalid_requested = False
    for line in output.splitlines():
        if version is not None:
            selected = POLICY_VERSION.fullmatch(line)
            if selected:
                active = selected.group(1) == version
                current = None
                continue
            candidate = POLICY_VERSION_CANDIDATE.fullmatch(line)
            if candidate:
                invalid_requested |= candidate.group(1) == version
                active = False
                current = None
                continue
            if re.match(r"^\s*(?:\*\*\*\s+)?" + re.escape(version) + r"\s+", line):
                invalid_requested = True
                active = False
                current = None
                continue
        if not active:
            continue
        source = POLICY_SOURCE.match(line)
        if source:
            descriptor = source.group(1)
            if descriptor == "/var/lib/dpkg/status":
                current = None
                continue
            current = {}
            sources.setdefault(descriptor, []).append(current)
        elif current is not None and line.strip().startswith("release "):
            if "release" in current:
                current["invalid"] = "1"
            current["release"] = line.strip()[len("release "):]
        elif current is not None and line.strip().startswith("origin "):
            if "host" in current:
                current["invalid"] = "1"
            current["host"] = line.strip()[len("origin "):]
    return {} if invalid_requested else sources


def _official_source(descriptor: str, metadata: dict[str, str], distro: str,
                     require_host: bool) -> bool:
    if "invalid" in metadata:
        return False
    url = descriptor.split(maxsplit=1)[0]
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    host = parsed.hostname or ""
    if parsed.scheme not in ("http", "https") or parsed.username or parsed.password or port is not None:
        return False
    if distro == "debian":
        known_host = host in ("deb.debian.org", "security.debian.org")
        known_path = parsed.path.startswith("/debian/") or parsed.path == "/debian" or (
            parsed.path.startswith("/debian-security/") or parsed.path == "/debian-security")
        expected = "Debian"
    elif distro == "ubuntu":
        known_host = host in ("archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com") or bool(
            re.fullmatch(r"[a-z]{2}\.archive\.ubuntu\.com", host))
        known_path = parsed.path.startswith("/ubuntu/") or parsed.path == "/ubuntu"
        expected = "Ubuntu"
    else:
        return False
    fields = {}
    for part in metadata.get("release", "").split(","):
        if "=" not in part:
            return False
        key, value = part.split("=", 1)
        if not key or key in fields:
            return False
        fields[key] = value
    metadata_host = metadata.get("host")
    host_matches = metadata_host == host if require_host else metadata_host in (None, host)
    return bool(known_host and known_path and fields.get("o") == expected and host_matches)


def package_origin(system: System, name: str, version: str, distro: str) -> str:
    result = system.run(["apt-cache", "policy", name], 8)
    if result.returncode != 0:
        return "não comprovada"
    selected = _policy_sources(result.stdout, version)
    if not selected:
        return "não comprovada"
    # policy PACOTE geralmente omite release; policy sem argumentos contém esse campo.
    global_result = system.run(["apt-cache", "policy"], 8)
    repositories = _policy_sources(global_result.stdout) if global_result.returncode == 0 else {}
    for descriptor, entries in selected.items():
        known = repositories.get(descriptor)
        # Saídas antigas ou sintéticas podem trazer release junto à versão.
        metadata = known if known is not None else entries
        if not metadata or not all(_official_source(descriptor, item, distro, known is not None)
                                   for item in metadata):
            return "não comprovada"
    return "oficial " + distro


def compare(system: System, installed: str, fixed: str) -> bool | None:
    result = system.run(["dpkg", "--compare-versions", installed, "ge", fixed], 5)
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None


def evaluate(packages: list[dict], distro: dict, system: System, db: dict | None = None) -> list[dict]:
    db = db or database()
    rules = db["vendors"].get(distro["id"], {}).get(distro["version"], {})
    output = []
    for package in packages:
        item = dict(package)
        name = item["name"]
        match = BRANCH.match(name)
        item.update({"status": "INDETERMINADO", "fixed": None,
                     "source": None, "advisory_updated": db["updated"]})
        if not match:
            output.append(item)
            continue
        source_name = "php" + match.group(1)
        if item.get("source_package") and item["source_package"] != source_name:
            item["status"] = "NÃO APLICÁVEL"
            item["reason"] = "Pacote de extensão de outra origem de código; não representa a versão do PHP principal."
            output.append(item)
            continue
        if not item.get("source_package"):
            item["reason"] = "Pacote fonte não identificado; versão do runtime não comprovada."
            output.append(item)
            continue
        rule = rules.get(source_name)
        item["branch"] = match.group(1)
        if not rule:
            item["reason"] = "Sem regra validada para este ramo e distribuição."
        elif item.get("origin") != "oficial " + distro["id"]:
            item["reason"] = "Origem do pacote não comprovada como oficial."
        else:
            item["fixed"] = rule["fixed"]
            item["source"] = rule["source"]
            result = compare(system, item["version"], rule["fixed"])
            item["status"] = "CORRIGIDO" if result is True else "VULNERÁVEL" if result is False else "INDETERMINADO"
            if result is None:
                item["reason"] = "Comparação dpkg indisponível."
        output.append(item)
    return output
