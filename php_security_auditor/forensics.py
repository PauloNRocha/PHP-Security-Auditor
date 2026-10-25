"""Triagem passiva e limitada; nenhuma heurística confirma invasão."""
from __future__ import annotations

import gzip
import hashlib
import os
import re
import stat
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

LOG_DIRS = ("/var/log/apache2", "/var/log/nginx", "/var/log/php", "/var/log/php-fpm",
            "/var/log/lighttpd", "/usr/local/lsws/logs")
LOG_NAMES = re.compile(r"(?:access|error|php|fpm|httpd|lsws|litespeed).*(?:\.log)?(?:\.\d+)?(?:\.gz)?$", re.I)
HOST_CONTEXT = "Suspeita geral do hospedeiro; vínculo com PHP não comprovado."
WEB_CONTEXT = "Suspeita em serviço web; vínculo com PHP não comprovado."
PHP_CONTEXT = "Suspeita correlacionada com processo de serviço PHP; relação com estas CVEs não comprovada."
CVE_CONTEXT = "Sinal compatível com técnica investigada; exploração das CVEs não comprovada."
LOG_CONTEXT = "Anomalia de log; relação com PHP e com as CVEs não comprovada."
SIGNALS = (
    (re.compile(r"PHP_SESSION_UPLOAD_PROGRESS", re.I), "Referência a progresso de upload", "MÉDIA", "MÉDIA",
     "Pode ser uso legítimo de upload; correlacione com erros e processos.", CVE_CONTEXT),
    (re.compile(r"(?:Allowed memory size.*exhausted|out of memory|OOM|memory allocation failed)", re.I),
     "Erro de memória", "MÉDIA", "MÉDIA", "Aplicações legítimas também esgotam memória.", LOG_CONTEXT),
    (re.compile(r"(?:segmentation fault|segfault|child.*exited on signal|worker.*crash)", re.I),
     "Falha de worker", "MÉDIA", "MÉDIA", "Falhas podem ter outras causas.", LOG_CONTEXT),
    (re.compile(r"(?:multipart/form-data|upload)" , re.I), "Atividade de upload registrada", "BAIXA", "BAIXA",
     "Uploads normais são comuns; este evento sozinho não indica ataque.", LOG_CONTEXT),
)
APACHE_STAMP = re.compile(r"\[(\d{2}/[A-Za-z]{3}/20\d{2}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]")
PHP_STAMP = re.compile(r"^\[(\d{2}-[A-Za-z]{3}-20\d{2} \d{2}:\d{2}:\d{2})(?: (UTC|GMT))?\]")
ISO_STAMP = re.compile(r"^\[?(20\d{2}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
ENGLISH_MONTHS = {name: f"{index:02d}" for index, name in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
MAX_LOG_FILES = 100
MAX_LOG_SIZE = 20 * 1024 * 1024


def _stamp(line: str) -> datetime | None:
    """Interpreta formatos comuns; data sem fuso usa o fuso local do host."""
    prefix = line[:180]
    try:
        if match := APACHE_STAMP.search(prefix):
            value = match.group(1)
            parsed = datetime.strptime(value[:3] + ENGLISH_MONTHS[value[3:6].lower()] + value[6:],
                                       "%d/%m/%Y:%H:%M:%S %z")
        elif match := PHP_STAMP.match(prefix):
            value = match.group(1)
            parsed = datetime.strptime(value[:3] + ENGLISH_MONTHS[value[3:6].lower()] + value[6:],
                                       "%d-%m-%Y %H:%M:%S")
            if match.group(2):
                parsed = parsed.replace(tzinfo=timezone.utc)
        elif match := ISO_STAMP.match(prefix):
            value = match.group(1).replace("/", "-").replace(",", ".").replace("Z", "+00:00")
            parsed = datetime.fromisoformat(value)
        else:
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, KeyError):
        return None


def _discover_logs() -> tuple[list[Path], list[str]]:
    result = []
    limits = []
    for directory in LOG_DIRS:
        root = Path(directory)
        try:
            for path in root.iterdir():
                if LOG_NAMES.match(path.name) and (path.name.endswith(".log") or ".log." in path.name or
                                                   path.name.startswith(("access", "error", "php", "fpm"))):
                    result.append(path)
                    if len(result) > 200:
                        limits.append("Descoberta de logs interrompida após 200 candidatos; pode haver outros arquivos.")
                        return sorted(result, key=lambda p: str(p)), limits
        except FileNotFoundError:
            continue
        except OSError as exc:
            limits.append(f"{root}: diretório de logs indisponível ({type(exc).__name__})")
    return sorted(result, key=lambda p: str(p)), limits


def _candidate_logs() -> list[Path]:
    return _discover_logs()[0]


def scan_logs(since: datetime, paths: list[Path] | None = None,
              max_total_bytes: int = 40 * 1024 * 1024) -> tuple[list[dict], list[str], list[str]]:
    findings, limits, inspected, _ = _scan_logs_with_coverage(since, paths, max_total_bytes)
    return findings, limits, inspected


def _scan_logs_with_coverage(since: datetime, paths: list[Path] | None,
                             max_total_bytes: int) -> tuple[list[dict], list[str], list[str], dict]:
    findings, limits, inspected = [], [], []
    if paths is None:
        candidates, discovery_limits = _discover_logs()
        limits.extend(discovery_limits)
    else:
        candidates = paths
    skipped: list[dict] = []
    partial: list[dict] = []
    if len(candidates) > MAX_LOG_FILES:
        limits.append(f"Somente {MAX_LOG_FILES} de pelo menos {len(candidates)} logs candidatos foram selecionados.")
        skipped.extend({"path": str(path), "reason": "limite de arquivos"} for path in candidates[MAX_LOG_FILES:])
    remaining = max_total_bytes
    observed_first = observed_last = None
    unknown_time = 0
    file_metadata: dict[str, dict[str, int]] = {}
    selected = candidates[:MAX_LOG_FILES]
    for index, path in enumerate(selected):
        read_bytes_for_file = 0
        long_line_reported = False
        try:
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_LOG_SIZE:
                reason = "não é arquivo regular ou excede 20 MiB"
                limits.append(f"{path}: {reason}")
                skipped.append({"path": str(path), "reason": reason})
                continue
            if remaining <= 0:
                limits.append("limite total de leitura atingido")
                skipped.extend({"path": str(item), "reason": "limite total de leitura"} for item in selected[index:])
                break
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as source:
                opened = os.fstat(source.fileno())
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    limits.append(f"{path}: arquivo mudou durante a abertura")
                    skipped.append({"path": str(path), "reason": "arquivo mudou durante a abertura"})
                    continue
                with (gzip.GzipFile(fileobj=source) if path.suffix == ".gz" else source) as handle:
                    inspected.append(str(path))
                    for line_number in range(1, 100001):
                        if remaining <= 0:
                            limits.append(f"{path}: orçamento de leitura atingido; fim do arquivo não comprovado")
                            partial.append({"path": str(path), "reason": "fim do arquivo não comprovado"})
                            break
                        raw = handle.readline(min(8193, remaining))
                        if not raw:
                            break
                        read_bytes_for_file += len(raw)
                        remaining -= len(raw)
                        if len(raw) == 8193 and not raw.endswith(b"\n"):
                            if not long_line_reported:
                                reason = "linhas acima de 8192 bytes omitidas; conteúdo e hash não analisados"
                                limits.append(f"{path}: {reason}")
                                partial.append({"path": str(path), "reason": reason})
                                long_line_reported = True
                            # Descarte limitado até o próximo separador; nenhum fragmento vira achado.
                            while remaining > 0:
                                chunk = handle.readline(min(8193, remaining))
                                if not chunk:
                                    break
                                read_bytes_for_file += len(chunk)
                                remaining -= len(chunk)
                                if chunk.endswith(b"\n"):
                                    break
                            if remaining == 0:
                                limits.append(f"{path}: orçamento de leitura atingido; fim do arquivo não comprovado")
                                break
                            continue
                        if remaining == 0 and not raw.endswith(b"\n"):
                            limits.append(f"{path}: linha incompleta no limite de leitura")
                            partial.append({"path": str(path), "reason": "linha incompleta no limite de leitura"})
                            break
                        line = raw[:8192].decode("utf-8", "replace")
                        stamp = _stamp(line)
                        if stamp:
                            observed_first = min(observed_first, stamp) if observed_first else stamp
                            observed_last = max(observed_last, stamp) if observed_last else stamp
                        if stamp and stamp < since:
                            continue
                        for pattern, title, severity, confidence, explanation, context in SIGNALS:
                            if pattern.search(line):
                                if stamp is None:
                                    unknown_time += 1
                                findings.append({"id": f"LOG-{len(findings)+1:04d}", "time": stamp.isoformat() if stamp else "desconhecido",
                                                 "temporal_status": "DENTRO_DO_PERÍODO" if stamp else "TEMPO_DESCONHECIDO",
                                                 "origin": str(path), "line": line_number,
                                                 "evidence": "SHA-256 da linha: " + hashlib.sha256(raw).hexdigest(),
                                                 "title": title, "severity": severity, "confidence": confidence,
                                                 "context": context,
                                                 "legitimate": explanation,
                                                 "recommendation": "Correlacione com requisições, erros, processos e mudanças no mesmo período."})
                                break
                        if len(findings) >= 500:
                            limits.append("limite de 500 achados atingido")
                            partial.append({"path": str(path), "reason": "limite de achados"})
                            break
                    else:
                        limits.append(f"{path}: limite de 100000 linhas atingido")
                        partial.append({"path": str(path), "reason": "limite de linhas"})
                    end_state = os.fstat(source.fileno())
                    if (end_state.st_dev, end_state.st_ino, end_state.st_size, end_state.st_mtime_ns) != (
                            opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
                        limits.append(f"{path}: arquivo mudou durante a análise")
                        partial.append({"path": str(path), "reason": "arquivo mudou durante a análise"})
                    else:
                        file_metadata[str(path)] = {"dev": opened.st_dev, "ino": opened.st_ino,
                                                    "size": opened.st_size, "mtime_ns": opened.st_mtime_ns}
        except (OSError, EOFError, zlib.error) as exc:
            reason = "zlib.error" if isinstance(exc, zlib.error) else type(exc).__name__
            limits.append(f"{path}: leitura indisponível ({reason})")
            if read_bytes_for_file:
                partial.append({"path": str(path), "reason": reason})
            else:
                skipped.append({"path": str(path), "reason": reason})
                if str(path) in inspected:
                    inspected.remove(str(path))
        if len(findings) >= 500 or remaining <= 0:
            skipped.extend({"path": str(item), "reason": "limite anterior interrompeu a coleta"} for item in selected[index + 1:])
            break
    if unknown_time:
        limits.append(f"{unknown_time} achado(s) de log sem data reconhecida; período não comprovado.")
    coverage = {"requested_since": since.isoformat(), "observed_first": observed_first.isoformat() if observed_first else None,
                "observed_last": observed_last.isoformat() if observed_last else None,
                "files_analyzed": inspected, "files_skipped": skipped, "files_partial": partial,
                "file_metadata": file_metadata,
                "bytes_read": max_total_bytes - max(remaining, 0),
                "unknown_time_findings": unknown_time,
                "essential_complete": False,
                "note": "Datas observadas não comprovam cobertura contínua do período; validação manual da cobertura é necessária antes de qualquer remediação. Logs HTTP podem omitir corpos de requisição."}
    return findings, limits, inspected, coverage


def _php_service_name(name: str) -> bool:
    name = name.lower()
    return name.startswith(("php-fpm", "php-cgi", "lsphp", "frankenphp")) or bool(
        re.fullmatch(r"php[0-9.]+-(?:fpm|cgi)", name))


def _php_service_ancestor(process: dict, by_pid: dict[int, dict]) -> bool:
    """Reconhece apenas a linhagem observada de serviços PHP explícitos."""
    current = process
    for _ in range(16):
        if _php_service_name(current.get("name", "")):
            return True
        parent = by_pid.get(current.get("ppid"))
        if parent is None or parent is current:
            return False
        current = parent
    return False


def inspect_processes(processes: list[dict]) -> list[dict]:
    findings = []
    by_pid = {p["pid"]: p for p in processes}
    for process in processes:
        exe = process.get("exe", "")
        parent = by_pid.get(process.get("ppid"))
        php_context = PHP_CONTEXT if _php_service_ancestor(process, by_pid) else None
        if exe.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")) or exe.endswith(" (deleted)"):
            findings.append({"id": f"PROC-{len(findings)+1:04d}", "time": "observação atual",
                             "origin": "/proc", "evidence": f"PID {process['pid']}; executável {exe}; pai {process.get('ppid')}",
                             "title": "Executável em diretório temporário ou removido", "severity": "ALTA",
                             "context": php_context or HOST_CONTEXT,
                             "confidence": "MÉDIA", "legitimate": "Atualização de pacote ou execução temporária autorizada.",
                             "recommendation": "Identifique o processo e preserve evidências antes de agir."})
        if parent and (parent["name"].lower().startswith(("apache", "httpd", "nginx")) or
                       _php_service_name(parent["name"])) and process["name"] in ("sh", "bash", "dash"):
            findings.append({"id": f"PROC-{len(findings)+1:04d}", "time": "observação atual",
                             "origin": "/proc", "evidence": f"PID {process['pid']}; pai {parent['pid']}",
                             "title": "Shell filho de serviço web", "severity": "ALTA", "confidence": "MÉDIA",
                             "context": php_context or WEB_CONTEXT,
                             "legitimate": "Aplicação pode executar tarefas administrativas previstas.",
                             "recommendation": "Confirme a origem da execução e as conexões associadas."})
    return findings


def inspect_persistence(since: datetime, max_files: int = 200) -> tuple[list[dict], list[str]]:
    findings, limits = [], []
    roots = ("/etc/cron.d", "/etc/systemd/system", "/etc/rc.local", "/tmp", "/var/tmp", "/dev/shm")
    count = 0
    for root_name in roots:
        root = Path(root_name)
        try:
            children = [root] if root.is_file() else list(root.iterdir())[:max_files]
        except OSError:
            limits.append(f"{root}: sem acesso")
            continue
        for path in children:
            count += 1
            if count > max_files:
                limits.append("limite de arquivos de persistência atingido")
                return findings, limits
            try:
                info = path.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                continue
            if datetime.fromtimestamp(info.st_mtime, timezone.utc) < since:
                continue
            suspicious = str(path).startswith(("/tmp/", "/var/tmp/", "/dev/shm/")) and bool(info.st_mode & 0o111)
            if suspicious:
                findings.append({"id": f"FILE-{len(findings)+1:04d}", "time": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),
                                 "origin": str(path), "evidence": f"modo={oct(info.st_mode & 0o777)} tamanho={info.st_size}",
                                 "title": "Executável recente em diretório temporário", "severity": "MÉDIA",
                                 "context": HOST_CONTEXT,
                                 "confidence": "BAIXA", "legitimate": "Instaladores e tarefas autorizadas podem criar esse arquivo.",
                                 "recommendation": "Verifique propriedade, processo de origem e contexto da alteração."})
    return findings, limits


def investigate(inventory: dict, days: int = 30, log_paths: list[Path] | None = None) -> dict:
    until = datetime.now(timezone.utc)
    since = until - timedelta(days=days)
    logs, log_limits, inspected, log_coverage = _scan_logs_with_coverage(since, log_paths, 40 * 1024 * 1024)
    log_coverage["requested_until"] = until.isoformat()
    proc = inspect_processes(inventory["processes"])
    persistence, persistence_limits = inspect_persistence(since) if log_paths is None else ([], ["persistência não examinada no teste isolado"])
    findings = logs + proc + persistence
    limitations = log_limits + persistence_limits
    if not inspected:
        limitations.append("Nenhum log legível examinado; investigação histórica inconclusiva.")
    status = "EVENTOS SUSPEITOS" if any(f["severity"] in ("MÉDIA", "ALTA") for f in findings) else "SEM INDÍCIOS IDENTIFICADOS"
    if not inspected or log_limits:
        status = "INVESTIGAÇÃO INCONCLUSIVA" if not findings else status
    return {"status": status, "findings": findings, "logs_inspected": inspected, "log_coverage": log_coverage,
            "recommendations": ["Para PHP web exposto ao PHP2Shell, considere ampliar a investigação até 01/08/2026, se houver registros; a janela atual não prova ausência de atividade anterior."],
            "limitations": limitations + ["Ausência de indicadores não exclui comprometimento anterior; logs HTTP geralmente não incluem corpos de requisições."]}
