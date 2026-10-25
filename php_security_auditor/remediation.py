"""Planejamento e atualização APT estritamente limitada."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .backup import BackupSession, _write_exclusive, validate_manifest
from .discovery import FPM_SERVICE, PHP_NAMES, discover
from .system import System
from .versions import compare, database, evaluate, package_origin

OFFICIAL = {"debian": {"12", "13"}, "ubuntu": {"22.04", "24.04", "26.04"}}
# Liberação depende de ensaios ponta a ponta nas distribuições suportadas.
REMEDIATION_VALIDATED = False
PACKAGE_NAME = re.compile(r"^(?:php\d+\.\d+(?:-[a-z0-9+.-]+)?|libapache2-mod-php\d+\.\d+)$")
INST_LINE = re.compile(r"^Inst ([a-zA-Z0-9+.-]+(?::[a-zA-Z0-9-]+)?) (?:\[[^]]+\] )?\((\S+) ")


def _candidate(system: System, name: str) -> tuple[str | None, str | None]:
    result = system.run(["apt-cache", "policy", name], 8)
    if result.returncode != 0:
        return None, "FALHA_CONSULTA_APT"
    candidates = re.findall(r"^\s*Candidate:\s*(\S+)\s*$", result.stdout, re.M)
    if len(candidates) != 1:
        return None, "RESPOSTA_APT_INVALIDA"
    if candidates[0] == "(none)":
        return None, "CANDIDATO_AUSENTE"
    return candidates[0], None


def _simulation(system: System, specs: list[str]) -> tuple[list[str], int]:
    result = system.run(["apt-get", "-s", "--no-remove", "--only-upgrade", "install", *specs], 60)
    changes = [line for line in result.stdout.splitlines() if line.startswith(("Inst ", "Conf ", "Remv "))]
    return changes, result.returncode


def _coverage_limitations(coverage: dict) -> list[str]:
    notes = []
    for source, value in coverage.items():
        entries = value.items() if isinstance(value, dict) else ((source, value),)
        for label, detail in entries:
            if "incompleta" in str(detail):
                notes.append(f"Cobertura {label}: {detail}")
    return notes


def _unmatched_runtime(system: System, inventory: dict, assessed: list[dict]) -> bool:
    """Só associa um executável observado a um pacote avaliado com posse comprovada."""
    official = "oficial " + inventory["os"]["id"]
    known_packages = {p["name"] for p in assessed
                      if p["status"] in ("CORRIGIDO", "VULNERÁVEL") and p.get("origin") == official}
    binaries = inventory.get("binaries", [])
    php_processes = [p for p in inventory.get("processes", [])
                     if PHP_NAMES.match(p.get("name", "")) and p.get("state") not in ("Z", "X")]
    php_services = [service for service in inventory.get("services", [])
                    if FPM_SERVICE.search(service.lower()) or any(
                        name in service.lower() for name in ("frankenphp", "lsphp", "php-cgi"))]
    if not known_packages:
        return bool(binaries or php_processes or php_services)
    if any(service.lower().startswith(("frankenphp", "lsphp")) for service in php_services):
        return True
    process_branches = {match.group(1) for p in php_processes
                        if (match := re.match(r"^php-fpm(\d+\.\d+)$", p["name"]))}
    for service in php_services:
        service_name = service.lower()
        cgi = re.fullmatch(r"(php-cgi(?:\d+\.\d+)?)\.service", service_name)
        if cgi:
            process_names = {p["name"] for p in php_processes}
            if cgi.group(1) == "php-cgi":
                matched = any(re.fullmatch(r"php-cgi(?:\d+\.\d+)?", name) for name in process_names)
            else:
                matched = cgi.group(1) in process_names
            if not matched:
                return True
            continue
        match = re.fullmatch(r"php(\d+\.\d+)-fpm\.service", service_name)
        if not match or match.group(1) not in process_branches:
            return True

    targets = [b.get("target") for b in binaries] + [p.get("exe") for p in php_processes]
    if any(not isinstance(target, str) for target in targets):
        return True
    unique = set(targets)
    if len(unique) > 64:
        return True
    if any(not path.startswith("/") or len(path) > 1024 or os.path.normpath(path) != path or
           any(char in path for char in "*?[\\") or any(ord(char) < 32 or ord(char) == 127 for char in path)
           for path in unique):
        return True
    if not unique:
        return False
    response = system.run(["dpkg-query", "--search", "--", *sorted(unique)], 8)
    if response.returncode != 0:
        return True
    owned = set()
    for line in response.stdout.splitlines():
        owners, separator, path = line.partition(": ")
        if not separator or path not in unique or path in owned or ", " in owners:
            return True
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?", owners):
            return True
        package = owners.split(":", 1)[0]
        if package not in known_packages:
            return True
        owned.add(path)
    return owned != unique


def plan(system: System, inventory: dict, assessed: list[dict]) -> dict:
    distro = inventory["os"]
    coverage = inventory.get("coverage", {})
    limitations = _coverage_limitations(coverage) + [
        "Busca de binários limitada aos caminhos conhecidos; instalações alternativas podem não ser detectadas.",
        "Interior de contêineres não inspecionado; metadados não comprovam a versão interna.",
        "Propriedade registrada pelo dpkg associa executáveis a pacotes, mas não comprova integridade dos bytes em disco.",
    ]

    def result(status: str, code: str, reason: str, *, issues: list[dict] | None = None,
               specs: list[str] | None = None, changes: list[str] | None = None) -> dict:
        eligible = status == "PLANO_DISPONIVEL"
        problems = issues or []
        return {"cves": database()["cves"], "os": distro,
                "status": status, "reason_code": code, "reason": reason,
                "issues": problems, "coverage": coverage, "limitations": limitations,
                "packages": specs if eligible else [], "simulation": changes or [],
                "errors": [item["message"] for item in problems], "approved_possible": eligible,
                "services": inventory.get("services", []) if eligible else [],
                "applications": "Aplicações PHP atendidas pelos serviços listados; mapeamento exige confirmação local." if eligible else None,
                "backups": "Configurações PHP e logs pertinentes, dentro dos limites documentados; manifesto SHA-256." if eligible else None,
                "checks": ["versão dpkg", "serviços", "portas de escuta", "módulos CLI", "processos com executável removido"] if eligible else [],
                "risks": ["APT pode executar scripts dos pacotes e reiniciar serviços.",
                          "APT usa DEBIAN_FRONTEND=noninteractive; perguntas adicionais podem receber respostas padrão.",
                          "Módulos CLI e simulação não comprovam funcionamento do SAPI web nem de cada aplicação."] if eligible else [],
                "recovery": "Configurações preservadas podem ser comparadas; downgrade do PHP é proibido." if eligible else None}

    if distro.get("id") not in OFFICIAL or distro.get("version") not in OFFICIAL[distro["id"]]:
        message = "Distribuição sem planejamento de atualização validado."
        return result("BLOQUEADO", "DISTRIBUICAO_NAO_SUPORTADA", message,
                      issues=[{"code": "DISTRIBUICAO_NAO_SUPORTADA", "message": message}])

    essential = [source for source in ("pacotes", "processos")
                 if source not in coverage or "incompleta" in str(coverage[source])]
    if essential:
        message = "Cobertura essencial insuficiente: " + ", ".join(essential) + "."
        return result("INCONCLUSIVO", "COBERTURA_ESSENCIAL_INCOMPLETA", message,
                      issues=[{"code": "COBERTURA_ESSENCIAL_INCOMPLETA", "message": message}])

    uncertain = [p for p in assessed if p["status"] == "INDETERMINADO"]
    if uncertain or any(p["status"] not in ("CORRIGIDO", "VULNERÁVEL", "NÃO APLICÁVEL", "INDETERMINADO") for p in assessed):
        command_failed = any(p.get("reason") == "Comparação dpkg indisponível." for p in uncertain)
        status = "ERRO" if command_failed else "INCONCLUSIVO"
        code = "FALHA_COMPARACAO_DPKG" if command_failed else "VERSAO_INDETERMINADA"
        message = "Comparação de versões dpkg falhou." if command_failed else "Há versão ou origem de runtime PHP indeterminada."
        return result(status, code, message, issues=[{"code": code, "message": message}])

    if _unmatched_runtime(system, inventory, assessed):
        message = "Binário ou processo PHP sem versão e origem de pacote comprovadas."
        return result("INCONCLUSIVO", "RUNTIME_NAO_AVALIADO", message,
                      issues=[{"code": "RUNTIME_NAO_AVALIADO", "message": message}])
    if inventory.get("containers"):
        message = "Contêiner identificado; versão interna do PHP não inspecionada."
        return result("INCONCLUSIVO", "CONTEINER_NAO_INSPECIONADO", message,
                      issues=[{"code": "CONTEINER_NAO_INSPECIONADO", "message": message}])
    if inventory.get("packages") and not assessed:
        message = "Pacotes PHP descobertos sem avaliação de versão."
        return result("INCONCLUSIVO", "PACOTES_NAO_AVALIADOS", message,
                      issues=[{"code": "PACOTES_NAO_AVALIADOS", "message": message}])

    vulnerable = [p for p in assessed if p["status"] == "VULNERÁVEL"]
    if not vulnerable:
        if any(p["status"] == "CORRIGIDO" for p in assessed):
            return result("SEM_ACAO", "PACOTES_CORRIGIDOS",
                          "Pacotes PHP avaliáveis atingem a correção conhecida; nenhuma atualização aplicável foi proposta.")
        return result("SEM_ACAO", "PHP_NAO_IDENTIFICADO",
                      "Nenhum runtime PHP foi identificado pelos métodos executados; nenhuma ação foi proposta.")

    issues = []
    specs = []
    for package in vulnerable:
        name = package["name"]
        if not PACKAGE_NAME.fullmatch(name):
            issues.append({"code": "NOME_PACOTE_INVALIDO", "message": f"Nome de pacote PHP inválido: {name}."})
            continue
        if package.get("origin") != "oficial " + distro["id"]:
            issues.append({"code": "ORIGEM_NAO_COMPROVADA", "message": f"Origem do pacote não comprovada: {name}."})
            continue
        if not package.get("fixed"):
            issues.append({"code": "CORRECAO_DESCONHECIDA", "message": f"Versão corrigida não comprovada: {name}."})
            continue
        candidate, failure = _candidate(system, name)
        if failure:
            messages = {"FALHA_CONSULTA_APT": "Falha ao consultar o candidato APT",
                        "RESPOSTA_APT_INVALIDA": "Resposta APT sem candidato único",
                        "CANDIDATO_AUSENTE": "Nenhum candidato APT disponível"}
            issues.append({"code": failure, "message": f"{messages[failure]}: {name}."})
            continue
        if package_origin(system, name, candidate, distro["id"]) != "oficial " + distro["id"]:
            issues.append({"code": "CANDIDATO_NAO_COMPROVADO", "message": f"Origem oficial do candidato não comprovada: {name}."})
            continue
        comparison = compare(system, candidate, package["fixed"])
        if comparison is not True:
            code = "FALHA_COMPARACAO_DPKG" if comparison is None else "CANDIDATO_ABAIXO_CORRECAO"
            issues.append({"code": code, "message": f"Candidato não comprovado como corrigido: {name}."})
            continue
        specs.append(f"{name}={candidate}")
    if issues:
        operational = {"FALHA_CONSULTA_APT", "RESPOSTA_APT_INVALIDA", "FALHA_COMPARACAO_DPKG"}
        first = next((item for item in issues if item["code"] in operational), issues[0])
        return result("ERRO" if first["code"] in operational else "BLOQUEADO",
                      first["code"], first["message"], issues=issues)

    changes, simulation_code = _simulation(system, specs)
    if simulation_code != 0:
        message = f"Simulação APT falhou (código {simulation_code}); nenhuma atualização aprovada."
        return result("ERRO", "FALHA_SIMULACAO_APT", message,
                      issues=[{"code": "FALHA_SIMULACAO_APT", "message": message}], changes=changes)
    if any(line.startswith("Remv ") for line in changes):
        message = "A simulação APT propõe remoção de pacotes."
        return result("BLOQUEADO", "REMOCAO_NA_SIMULACAO", message,
                      issues=[{"code": "REMOCAO_NA_SIMULACAO", "message": message}], changes=changes)
    for line in changes:
        if not line.startswith("Inst "):
            continue
        match = INST_LINE.match(line)
        if not match or package_origin(system, match.group(1), match.group(2), distro["id"]) != "oficial " + distro["id"]:
            message = "Dependência ou pacote da simulação sem origem oficial comprovada."
            return result("BLOQUEADO", "DEPENDENCIA_NAO_COMPROVADA", message,
                          issues=[{"code": "DEPENDENCIA_NAO_COMPROVADA", "message": message}], changes=changes)
    installed = {match.group(1): match.group(2) for line in changes
                 if line.startswith("Inst ") and (match := INST_LINE.match(line))}
    if any(installed.get(name) != version for name, version in
           (spec.split("=", 1) for spec in specs)):
        message = "APT não confirmou todos os pacotes e versões solicitados na simulação."
        return result("BLOQUEADO", "SIMULACAO_INCOMPLETA", message,
                      issues=[{"code": "SIMULACAO_INCOMPLETA", "message": message}], changes=changes)
    return result("PLANO_DISPONIVEL", "ATUALIZACAO_ELEGIVEL",
                  "Atualização simulada e elegível para revisão; isto não autoriza remediação.",
                  specs=specs, changes=changes)


def _modules(system: System, assessed: list[dict]) -> dict[str, list[str] | str]:
    result = {}
    for package in assessed:
        if not re.fullmatch(r"php\d+\.\d+-cli", package["name"]):
            continue
        if not package.get("origin", "").startswith("oficial "):
            continue
        branch = package["branch"]
        response = system.run(["runuser", "-u", "nobody", "--", f"/usr/bin/php{branch}", "-m"], 10)
        result[branch] = sorted(response.stdout.splitlines()) if response.returncode == 0 else "falha no carregamento"
    return result


def _ports(system: System) -> list[str]:
    response = system.run(["ss", "-ltnH"], 8)
    return [line.split()[3] for line in response.stdout.splitlines()[:500] if len(line.split()) >= 4] if response.returncode == 0 else []


def _configs() -> list[Path]:
    root = Path("/etc/php")
    try:
        return [p for p in root.glob("*/*/*.ini") if p.is_file() and not p.is_symlink()]
    except OSError as exc:
        raise RuntimeError("Falha ao listar configurações PHP antes da atualização.") from exc


def validate_after(before: dict, after: dict, assessed: list[dict], stale: list[dict]) -> list[str]:
    failures = []
    runtimes = [p for p in assessed if p["status"] != "NÃO APLICÁVEL"]
    if not runtimes:
        failures.append("Nenhum runtime PHP foi comprovado após a atualização.")
    if any(p["status"] == "VULNERÁVEL" for p in runtimes):
        failures.append("Runtime PHP vulnerável permanece instalado.")
    if any(p["status"] not in ("CORRIGIDO", "VULNERÁVEL") for p in runtimes):
        failures.append("Há runtime PHP com correção indeterminada.")
    if any(value == "falha no carregamento" for value in before["modules"].values()) or any(value == "falha no carregamento" for value in after["modules"].values()):
        failures.append("Validação de módulos PHP incompleta.")
    if stale:
        failures.append("Processos com executável removido permanecem ativos.")
    if set(before["services"]) - set(after["services"]):
        failures.append("Serviço anteriormente ativo não aparece como ativo.")
    if set(before["ports"]) - set(after["ports"]):
        failures.append("Porta anteriormente em escuta desapareceu.")
    for branch, modules in before["modules"].items():
        if modules != "falha no carregamento" and (after["modules"].get(branch) == "falha no carregamento" or
                                                  not set(modules).issubset(set(after["modules"].get(branch, [])))):
            failures.append(f"Módulos do PHP {branch} falharam ou desapareceram.")
    return failures


def remediate(system: System, approved: dict, backup_root: Path | None = None, *, investigation_reviewed: bool = False) -> dict:
    if not REMEDIATION_VALIDATED:
        raise RuntimeError("Remediação indisponível até ensaios ponta a ponta representativos e liberação explícita.")
    if not investigation_reviewed:
        raise RuntimeError("A investigação precisa ser apresentada antes de iniciar a atualização.")
    if os.geteuid() != 0:
        raise PermissionError("Remediação requer root ou sudo.")
    fresh = discover(system)
    assessed = evaluate(fresh["packages"], fresh["os"], system)
    current = plan(system, fresh, assessed)
    if not current["approved_possible"] or current["packages"] != approved["packages"] or current["simulation"] != approved["simulation"]:
        raise RuntimeError("O estado ou a simulação mudou; gere e aprove novo plano.")
    log_paths = [Path(p) for p in approved.get("logs_inspected", [])]
    metadata = approved.get("log_metadata", {})
    if any(str(path) not in metadata for path in log_paths):
        raise RuntimeError("Metadados dos logs examinados ausentes; nova coleta é necessária.")
    sources = _configs() + log_paths
    if len(sources) > 100:
        raise RuntimeError("Mais de 100 configurações e logs exigem preservação; transação bloqueada.")
    expected = sum(p.stat().st_size for p in sources)
    session = BackupSession(backup_root, expected)
    operations = ["reavaliação", "simulação APT", "preservação antes da atualização"]
    for source in sources:
        category = "evidencias" if source in log_paths else "configuracoes"
        session.preserve(source, category, expected=metadata[str(source)] if category == "evidencias" else None)
    manifest = session.finalize(fresh["os"], operations)
    failures = validate_manifest(session.path)
    if failures:
        raise RuntimeError("Backup inválido: " + "; ".join(failures))
    before = {"modules": _modules(system, assessed), "ports": _ports(system), "services": fresh["services"]}
    _write_exclusive(session.path / "transacao/antes.json", json.dumps(before, ensure_ascii=False, indent=2).encode())
    command = ["apt-get", "--no-remove", "--only-upgrade", "install", *current["packages"]]
    result = system.run(command, 900)
    transaction = {"command": command, "returncode": result.returncode,
                   "stdout_tail": result.stdout[-10000:], "stderr_tail": result.stderr[-10000:]}
    # Saída APT pode conter dados locais; arquivo restrito, nunca incluído em relatório resumido.
    _write_exclusive(session.path / "transacao/apt.json", json.dumps(transaction, ensure_ascii=False, indent=2).encode())
    if result.returncode != 0:
        return {"status": "FALHA NA ATUALIZAÇÃO", "backup": str(session.path), "manifest": str(manifest),
                "validation": "Não executada após falha; revisar transação manualmente."}
    after_inventory = discover(system)
    after_assessed = evaluate(after_inventory["packages"], after_inventory["os"], system)
    after = {"modules": _modules(system, after_assessed), "ports": _ports(system),
             "services": after_inventory["services"],
             "packages": [{"name": p["name"], "version": p["version"], "status": p["status"]} for p in after_assessed]}
    stale = [p for p in after_inventory["processes"] if p["exe"].endswith(" (deleted)")]
    failures = validate_after(before, after, after_assessed, stale)
    _write_exclusive(session.path / "transacao/depois.json", json.dumps(after, ensure_ascii=False, indent=2).encode())
    status = "VALIDAÇÃO INCOMPLETA" if failures else "PACOTES ATUALIZADOS; VALIDAÇÃO WEB PENDENTE"
    failures.append("Versão efetiva em cada worker e teste funcional HTTP dependem de validação local da aplicação.")
    return {"status": status,
            "backup": str(session.path), "manifest": str(manifest), "validation": failures,
            "before": before, "after": after}
