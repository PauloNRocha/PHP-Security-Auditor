"""Inventário local sem executar interpretadores PHP encontrados."""
from __future__ import annotations

import json
import os
import re
from glob import iglob
from itertools import islice
from pathlib import Path

from .system import System, os_release
from .versions import PHP_PACKAGE, package_origin

WEB_NAMES = ("apache", "httpd", "nginx", "php-fpm", "php-cgi", "frankenphp", "lshttpd", "lsphp", "litespeed")
PHP_NAMES = re.compile(r"^(?:php(?:[0-9.]+)?|php-fpm(?:[0-9.]+)?|php-cgi(?:[0-9.]+)?|frankenphp|lsphp(?:[0-9.]+)?)$")
FPM_SERVICE = re.compile(r"php(?:\d+\.\d+)?-fpm")
BIN_GLOBS = ("/usr/bin/php*", "/usr/sbin/php-fpm*", "/usr/local/bin/php*",
             "/usr/local/sbin/php*", "/opt/*/bin/php*", "/usr/local/lsws/lsphp*/bin/lsphp")
PF_KTHREAD = 0x00200000


def _kernel_thread(path: Path, status: str) -> bool:
    """Confirma thread do kernel sem depender do nome, que pode ser imitado."""
    marker = re.search(r"^Kthread:[ \t]*([01])[ \t]*$", status, re.M)
    if marker:
        return marker.group(1) == "1"
    # Kernels mais antigos não apresentam Kthread em status; flags é o campo 9 de stat.
    try:
        with (path / "stat").open(encoding="utf-8", errors="replace") as source:
            raw = source.read(4096)
        closing = raw.rfind(")")
        fields = raw[closing + 1:].split() if closing >= 0 else []
        return len(fields) > 6 and bool(int(fields[6]) & PF_KTHREAD)
    except (OSError, ValueError):
        return False


def packages(system: System, distro: dict) -> tuple[list[dict], str]:
    result = system.run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Status}\t${source:Package}\n"], 15)
    if result.returncode != 0:
        return [], "incompleta: dpkg-query indisponível ou falhou"
    entries = []
    for line in result.stdout.splitlines()[:30000]:
        parts = line.split("\t")
        if len(parts) != 4 or parts[2] != "install ok installed":
            continue
        name = parts[0].split(":", 1)[0]
        if PHP_PACKAGE.fullmatch(name):
            entries.append({"name": name, "version": parts[1], "source_package": parts[3],
                            "origin": package_origin(system, name, parts[1], distro["id"])})
    return entries, "completa" if len(result.stdout) < 2_000_000 else "incompleta: saída truncada"


def binaries() -> list[dict]:
    found = {}
    for pattern in BIN_GLOBS:
        for name in islice(iglob(pattern), 100):
            path = Path(name)
            if PHP_NAMES.match(path.name) or path.name.startswith("php-fpm"):
                try:
                    found[str(path)] = {"path": str(path), "target": str(path.resolve(strict=True)),
                                        "symlink": path.is_symlink()}
                except (OSError, RuntimeError):
                    found[str(path)] = {"path": str(path), "target": "indeterminado"}
    return list(found.values())[:300]


def processes() -> tuple[list[dict], str]:
    output = []
    denied = 0
    proc = Path("/proc")
    try:
        pids = [p for p in proc.iterdir() if p.name.isdigit()][:10000]
    except OSError:
        return [], "incompleta: /proc indisponível"
    for path in pids:
        try:
            comm = (path / "comm").read_text(errors="replace").strip()
            status = (path / "status").read_text(errors="replace")[:16384]
            ppid = re.search(r"^PPid:\s*(\d+)", status, re.M)
            uid = re.search(r"^Uid:\s*(\d+)", status, re.M)
            state_match = re.search(r"^State:[ \t]*([A-Z])(?:[ \t]|$)", status, re.M)
            state = state_match.group(1) if state_match else "indeterminado"
            try:
                exe = os.readlink(path / "exe")
            except OSError:
                exe = "indisponível"
                zombie = state in ("Z", "X")
                if not (_kernel_thread(path, status) or zombie):
                    if not path.exists():
                        continue  # O processo terminou entre a listagem e a leitura.
                    denied += 1
            output.append({"pid": int(path.name), "ppid": int(ppid.group(1)) if ppid else None,
                           "uid": int(uid.group(1)) if uid else None, "name": comm[:80],
                           "exe": exe[:512], "state": state})
        except FileNotFoundError:
            continue  # Processo encerrado durante a coleta.
        except OSError:
            denied += 1
    return output, "incompleta: acesso limitado ao /proc" if denied else "completa"


def services(system: System) -> tuple[list[str], str]:
    result = system.run(["systemctl", "list-units", "--type=service", "--state=running",
                         "--no-legend", "--plain"], 8)
    if result.returncode != 0:
        return [], "incompleta: systemd indisponível"
    names = []
    for line in result.stdout.splitlines()[:3000]:
        name = line.split(maxsplit=1)[0] if line.split() else ""
        if any(token in name.lower() for token in WEB_NAMES) or FPM_SERVICE.search(name.lower()):
            names.append(name)
    return names, "completa"


def containers(system: System) -> tuple[list[dict], dict]:
    found = []
    coverage = {}
    for engine in ("docker", "podman"):
        result = system.run([engine, "ps", "--format", "{{json .}}"], 8)
        if result.returncode != 0:
            coverage[engine] = "incompleta: ferramenta ou acesso ao socket indisponível"
            continue
        coverage[engine] = "metadados de contêineres em execução; interior não inspecionado"
        for line in result.stdout.splitlines()[:200]:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            image = str(row.get("Image", ""))[:256]
            command = str(row.get("Command", ""))[:256]
            if "php" in (image + command).lower() or "frankenphp" in image.lower() or "litespeed" in image.lower():
                found.append({"engine": engine, "id": str(row.get("ID", ""))[:80],
                              "image": image, "status": "INDETERMINADO",
                              "note": "Versão interna e uso HTTP não comprovados."})
    result = system.run(["lxc-ls", "--active", "-1"], 8)
    coverage["lxc"] = ("metadados de contêineres em execução; interior não inspecionado" if result.returncode == 0
                       else "incompleta: ferramenta ou acesso LXC indisponível")
    if result.returncode == 0:
        for name in result.stdout.splitlines()[:200]:
            found.append({"engine": "lxc", "id": name[:80], "status": "INDETERMINADO",
                          "note": "Presença de PHP no interior não comprovada."})
    return found, coverage


def discover(system: System) -> dict:
    distro = os_release(system)
    pkgs, pkg_coverage = packages(system, distro)
    procs, proc_coverage = processes()
    running, svc_coverage = services(system)
    ctrs, ctr_coverage = containers(system)
    bins = binaries()
    php_procs = [p for p in procs if PHP_NAMES.match(p["name"])]
    has_host_php = bool(pkgs or bins or php_procs)
    web_running = any(any(n in s.lower() for n in ("apache", "httpd", "nginx", "lighttpd", "litespeed", "lshttpd")) for s in running)
    fpm_running = any(FPM_SERVICE.search(s.lower()) for s in running) or any("php-fpm" in p["name"].lower() for p in procs)
    apache_running = any("apache" in s or "httpd" in s for s in running)
    mod_php = any(p["name"].startswith("libapache2-mod-php") for p in pkgs)
    exposure = "HTTP provável" if ((fpm_running and web_running) or (mod_php and apache_running)) else "HTTP indeterminada"
    if has_host_php and not web_running and not any("php-cgi" in p["name"] or "frankenphp" in p["name"] or "lsphp" in p["name"] for p in procs):
        exposure = "sem serviço web PHP identificado; uso CLI possível"
    return {"os": distro, "packages": pkgs, "binaries": bins, "processes": procs,
            "services": running, "containers": ctrs, "host_php": has_host_php,
            "exposure": exposure,
            "coverage": {"pacotes": pkg_coverage, "processos": proc_coverage,
                         "serviços": svc_coverage, "contêineres": ctr_coverage,
                         "binários": "caminhos usuais e instalações em /opt; não exaustivo"},
            "methods": ["dpkg-query", "caminhos de binários", "/proc", "systemctl",
                        "docker ps", "podman ps", "lxc-ls --active"]}
