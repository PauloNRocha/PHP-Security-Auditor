"""Relatórios com dados mínimos e arquivos restritos."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from . import VERSION
from .backup import _secure_mkdirs
from .discovery import PHP_NAMES


def build(inventory: dict, assessed: list[dict], investigation: dict | None,
          changes: dict | None = None) -> dict:
    unknown_runtime = bool((inventory["host_php"] and not any(p["status"] != "NÃO APLICÁVEL" for p in assessed)) or inventory["containers"] or
                           any("incompleta" in value for value in inventory["coverage"].values()) or
                           any(str(b.get(key, "")).startswith(("/usr/local/", "/opt/"))
                               for b in inventory["binaries"] for key in ("path", "target")) or
                           any(PHP_NAMES.match(p.get("name", "")) and
                               str(p.get("exe", "")).startswith(("/usr/local/", "/opt/"))
                               for p in inventory["processes"]))
    statuses = {p["status"] for p in assessed}
    if "VULNERÁVEL" in statuses:
        status = "VULNERÁVEL"
    elif "INDETERMINADO" in statuses or unknown_runtime or (not inventory["host_php"] and any("incompleta" in v for v in inventory["coverage"].values())):
        status = "INDETERMINADO"
    elif "CORRIGIDO" in statuses:
        status = "CORRIGIDO"
    else:
        status = "NÃO APLICÁVEL"
    limitations = [f"{key}: {value}" for key, value in inventory["coverage"].items() if "incompleta" in value]
    if any(p.get("origin", "").startswith("oficial ") for p in assessed):
        limitations.append("APT confirma disponibilidade da versão em arquivo oficial, não a proveniência nem a integridade dos bytes instalados.")
    if investigation:
        limitations.extend(investigation["limitations"])
    if not inventory["host_php"]:
        limitations.append("PHP não identificado no hospedeiro pelos métodos executados; interior de contêineres não inspecionado.")
    selected_pids = {p["pid"] for p in inventory["processes"] if any(token in p["name"].lower() for token in
                     ("php", "apache", "httpd", "nginx", "lsphp", "litespeed", "frankenphp"))}
    related_processes = [p for p in inventory["processes"] if p["pid"] in selected_pids or p.get("ppid") in selected_pids][:1000]
    return {"tool_version": VERSION, "collected_at": datetime.now(timezone.utc).isoformat(),
            "hostname": os.uname().nodename, "os": inventory["os"], "coverage": inventory["coverage"],
            "methods": inventory["methods"], "php_identified_host": inventory["host_php"],
            "vulnerability_status": status,
            "investigation_status": investigation["status"] if investigation else "NÃO EXECUTADA",
            "exposure": inventory["exposure"], "packages": assessed,
            "binaries": inventory["binaries"], "services": inventory["services"],
            "processes": related_processes,
            "containers": inventory["containers"],
            "findings": investigation["findings"] if investigation else [],
            "logs_inspected": investigation["logs_inspected"] if investigation else [],
            "log_coverage": investigation.get("log_coverage", {}) if investigation else {},
            "limitations": limitations,
            "recommendations": (["Atualizar pacotes vulneráveis de origem comprovada após preservar evidências e aprovar plano."] if status == "VULNERÁVEL" else
                               ["Investigar cobertura e origem dos runtimes indeterminados."] if status == "INDETERMINADO" else
                               ["Manter atualizações e monitoramento; verificar workers e aplicações após mudanças."]) +
                               (investigation.get("recommendations", []) if investigation else []),
            "backups": [changes["backup"]] if changes and changes.get("backup") else [],
            "changes": changes or {}, "tests": changes.get("validation", []) if changes else [],
            "final_result": changes.get("status") if changes else status}


def _safe_iso(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.isoformat() if parsed.tzinfo else None


def sanitized(report: dict) -> dict:
    """Lista positiva de dados permitidos em relatórios para compartilhamento."""
    allowed_vulnerability = {"CORRIGIDO", "VULNERÁVEL", "INDETERMINADO", "NÃO APLICÁVEL"}
    allowed_investigation = {"SEM INDÍCIOS IDENTIFICADOS", "EVENTOS SUSPEITOS", "FORTES INDÍCIOS DE COMPROMETIMENTO",
                             "COMPROMETIMENTO CONFIRMADO", "INVESTIGAÇÃO INCONCLUSIVA", "NÃO EXECUTADA"}
    allowed_exposure = {"HTTP provável", "HTTP indeterminada", "sem serviço web PHP identificado; uso CLI possível"}
    status = report.get("vulnerability_status")
    investigation = report.get("investigation_status")
    exposure = report.get("exposure")
    os_info = report.get("os", {})
    os_id = os_info.get("id") if os_info.get("id") in ("debian", "ubuntu") else "não comprovado"
    version = os_info.get("version", "")
    os_version = version if isinstance(version, str) and re.fullmatch(r"[0-9.]{1,12}", version) else "não comprovada"
    coverage = report.get("log_coverage", {})
    package_counts = {key: sum(p.get("status") == key for p in report.get("packages", [])) for key in sorted(allowed_vulnerability)}
    finding_counts = {key: sum(f.get("severity") == key for f in report.get("findings", [])) for key in ("ALTA", "MÉDIA", "BAIXA")}
    unknown_time = coverage.get("unknown_time_findings", 0)
    return {"tool_version": VERSION, "collected_at": _safe_iso(report.get("collected_at")),
            "os": {"id": os_id, "version": os_version}, "php_identified_host": bool(report.get("php_identified_host")),
            "vulnerability_status": status if status in allowed_vulnerability else "INDETERMINADO",
            "investigation_status": investigation if investigation in allowed_investigation else "INVESTIGAÇÃO INCONCLUSIVA",
            "exposure": exposure if exposure in allowed_exposure else "HTTP indeterminada",
            "package_status_counts": package_counts, "finding_severity_counts": finding_counts,
            "log_coverage": {"requested_since": _safe_iso(coverage.get("requested_since")),
                             "requested_until": _safe_iso(coverage.get("requested_until")),
                             "observed_first": _safe_iso(coverage.get("observed_first")),
                             "observed_last": _safe_iso(coverage.get("observed_last")),
                             "files_analyzed_count": len(coverage.get("files_analyzed", [])),
                             "files_skipped_count": len(coverage.get("files_skipped", [])),
                             "files_partial_count": len(coverage.get("files_partial", [])),
                             "unknown_time_findings": unknown_time if isinstance(unknown_time, int) and unknown_time >= 0 else 0},
            "limitations_count": len(report.get("limitations", [])),
            "notice": "Resumo sanitizado; consulte o relatório técnico privado para achados, arquivos e limitações. Ausência de indicadores não exclui comprometimento."}


def render(report: dict, fmt: str, detailed: bool = False) -> str:
    if not detailed:
        data = sanitized(report)
        if fmt == "json":
            return json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        heading = "# Relatório resumido do PHP Security Auditor" if fmt == "md" else "RELATÓRIO RESUMIDO DO PHP SECURITY AUDITOR"
        lines = [heading, "", f"Coleta: {data['collected_at']}", f"Sistema: {data['os']['id']} {data['os']['version']}",
                 f"PHP no hospedeiro: {'sim' if data['php_identified_host'] else 'não identificado'}",
                 f"Vulnerabilidade: {data['vulnerability_status']}", f"Investigação: {data['investigation_status']}",
                 f"Exposição: {data['exposure']}",
                 "Pacotes por status: " + ", ".join(f"{key}={value}" for key, value in data["package_status_counts"].items()),
                 "Achados por gravidade: " + ", ".join(f"{key}={value}" for key, value in data["finding_severity_counts"].items()),
                 f"Período solicitado: {data['log_coverage']['requested_since'] or 'não investigado'} a {data['log_coverage']['requested_until'] or 'não investigado'}",
                 f"Datas observadas nos logs: {data['log_coverage']['observed_first'] or 'indisponível'} a {data['log_coverage']['observed_last'] or 'indisponível'}",
                 f"Logs analisados: {data['log_coverage']['files_analyzed_count']}; ignorados: {data['log_coverage']['files_skipped_count']}",
                 f"Logs parciais: {data['log_coverage']['files_partial_count']}",
                 f"Achados sem data: {data['log_coverage']['unknown_time_findings']}; limitações: {data['limitations_count']}",
                 data["notice"]]
        return "\n".join(lines) + "\n"
    if fmt == "json":
        return json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    heading = "# Relatório do PHP Security Auditor\n\n" if fmt == "md" else "RELATÓRIO DO PHP SECURITY AUDITOR\n\n"
    lines = [heading, f"Hospedeiro: {report['hostname']}", f"Sistema: {report['os'].get('name', '')}",
             f"Coleta: {report['collected_at']}", f"Versão da ferramenta: {report['tool_version']}",
             f"PHP no hospedeiro: {'sim' if report['php_identified_host'] else 'não identificado'}",
             f"Vulnerabilidade: {report['vulnerability_status']}",
             f"Investigação: {report['investigation_status']}", f"Exposição: {report['exposure']}", ""]
    lines.append("Pacotes PHP:")
    for p in report["packages"]:
        lines.append(f"- {p['name']} {p['version']}: {p['status']} | arquivo APT da versão: {p['origin']} | correção: {p.get('fixed') or 'não comprovada'} | fonte: {p.get('source') or 'não comprovada'} | base: {p.get('advisory_updated') or 'indisponível'}")
    lines.append("Serviços relacionados: " + (", ".join(report["services"]) or "nenhum identificado"))
    lines.append("Contêineres relacionados: " + str(len(report["containers"])))
    if detailed:
        lines.append("Processos relacionados (PID, PPID, UID, nome, executável):")
        for process in report["processes"]:
            lines.append(f"- {process['pid']}, {process.get('ppid')}, {process.get('uid')}, {process['name']}, {process['exe']}")
    lines.append("Achados:")
    for finding in report["findings"]:
        lines.append(f"- {finding['id']} {finding['title']} | {finding['severity']} | confiança {finding['confidence']} | {finding['time']}")
        if detailed:
            if finding.get("context"):
                lines.append(f"  Contexto: {finding['context']}")
            lines.append(f"  Origem: {finding['origin']}; evidência: {finding['evidence']}")
            lines.append(f"  Explicação legítima: {finding['legitimate']}")
            lines.append(f"  Próximo passo: {finding['recommendation']}")
    lines.append("Cobertura:")
    for key, value in report["coverage"].items():
        lines.append(f"- {key}: {value}")
    if report.get("log_coverage"):
        scan = report["log_coverage"]
        lines.append(f"Período solicitado: {scan.get('requested_since')} a {scan.get('requested_until')}")
        lines.append(f"Datas observadas: {scan.get('observed_first') or 'indisponível'} a {scan.get('observed_last') or 'indisponível'}")
        lines.append("Arquivos analisados: " + (", ".join(scan.get("files_analyzed", [])) or "nenhum"))
        for skipped in scan.get("files_skipped", []):
            lines.append(f"Arquivo ignorado: {skipped['path']} ({skipped['reason']})")
        for partial in scan.get("files_partial", []):
            lines.append(f"Arquivo parcialmente analisado: {partial['path']} ({partial['reason']})")
        lines.append(f"Bytes lidos: {scan.get('bytes_read', 0)}; achados sem data: {scan.get('unknown_time_findings', 0)}")
        lines.append(scan.get("note", ""))
    lines.append("Limitações:")
    for item in report["limitations"]:
        lines.append(f"- {item}")
    lines.append("Recomendações:")
    for item in report["recommendations"]:
        lines.append(f"- {item}")
    lines.append("Backups: " + (", ".join(report["backups"]) or "nenhum"))
    lines.append("Resultado final: " + report["final_result"])
    lines.append("A ferramenta não substitui investigação forense profissional. Ausência de indicadores não prova ausência de comprometimento.")
    escaped = [heading] + ["".join(c if ord(c) >= 32 and ord(c) not in range(127, 160) else f"\\x{ord(c):02x}" for c in line)
                           for line in lines[1:]]
    if fmt == "md":
        # Valores do host são dados não confiáveis; impeça links, imagens e HTML ativos.
        def markdown_literal(line: str) -> str:
            prefix = "- " if line.startswith("- ") else ""
            value = line[len(prefix):]
            return prefix + "".join(("&amp;" if char == "&" else "&lt;" if char == "<" else
                                     "&gt;" if char == ">" else "\\" + char if char in r"\\`*_{}[]()#+-.!|~" else char)
                                    for char in value)
        escaped = [heading] + [markdown_literal(line) for line in escaped[1:]]
        return "\n".join(escaped).replace("Pacotes PHP:\n", "## Pacotes PHP\n\n").replace("Achados:\n", "## Achados\n\n") + "\n"
    return "\n".join(escaped) + "\n"


def save(report: dict, directory: Path, detailed: bool = False) -> list[str]:
    _secure_mkdirs(directory)
    output = []
    for fmt, suffix in (("txt", "txt"), ("json", "json"), ("md", "md")):
        target = directory / f"relatorio-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{suffix}"
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(render(report, fmt, detailed))
        output.append(str(target))
    return output
