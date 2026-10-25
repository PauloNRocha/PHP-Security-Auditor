"""Interface de terminal em português brasileiro."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import VERSION
from .backup import BackupSession, validate_manifest
from . import remediation as remediation_module
from .discovery import PHP_NAMES, discover
from .forensics import investigate
from .remediation import plan, remediate
from .report import build, render, save
from .system import System
from .versions import evaluate


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="php-security-auditor", description="Auditoria passiva e planejamento de correção de PHP; remediação bloqueada nesta versão")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("operation", nargs="?", default="audit", choices=("audit", "plan", "remediate", "verify", "report", "rollback-config"))
    p.add_argument("--days", type=int, default=30, help="Período da investigação em dias (1 a 365)")
    p.add_argument("--output", type=Path, help="Diretório restrito para relatórios TXT, JSON e Markdown")
    p.add_argument("--backup-dir", type=Path, help="Raiz explícita para backups")
    p.add_argument("--preserve", action="store_true", help="Preservar logs examinados em uma sessão de backup")
    p.add_argument("--detailed", action="store_true", help="Relatório técnico detalhado")
    p.add_argument("--non-interactive", action="store_true", help="Nunca solicitar autorização nem alterar pacotes")
    p.add_argument("--session", type=Path, help="Sessão de backup para rollback-config")
    return p


def remediation_blockers(investigation: dict | None) -> list[str]:
    if investigation is None:
        return ["Investigação inicial não foi executada."]
    blocked = []
    if investigation["status"] in ("FORTES INDÍCIOS DE COMPROMETIMENTO", "COMPROMETIMENTO CONFIRMADO") or any(
            finding.get("severity") == "ALTA" for finding in investigation["findings"]):
        blocked.append("Achados graves exigem preservação e resposta a incidente antes de atualizar.")
    if investigation["status"] == "INVESTIGAÇÃO INCONCLUSIVA" or not investigation.get("log_coverage", {}).get("essential_complete"):
        blocked.append("Coleta essencial de logs insuficiente ou período solicitado sem cobertura comprovada.")
    return blocked


def _runtime_needs_investigation(inventory: dict, assessed: list[dict]) -> bool:
    if any(p["status"] in ("VULNERÁVEL", "INDETERMINADO") for p in assessed):
        return True
    binaries = inventory["binaries"]
    running_php = any(PHP_NAMES.match(p.get("name", "")) for p in inventory["processes"])
    assessed_runtime = any(p["status"] != "NÃO APLICÁVEL" for p in assessed)
    manual_binary = any(str(b.get(key, "")).startswith(("/usr/local/", "/opt/"))
                        for b in binaries for key in ("path", "target"))
    manual_process = any(PHP_NAMES.match(p.get("name", "")) and
                         str(p.get("exe", "")).startswith(("/usr/local/", "/opt/"))
                         for p in inventory["processes"])
    return bool(manual_binary or manual_process or ((binaries or running_php) and not assessed_runtime))


def _plan_failure(code: str, message: str, inventory: dict | None = None) -> dict:
    """Mantém uma resposta JSON previsível se a avaliação operacional falhar."""
    inventory = inventory or {}
    return {"cves": [], "os": inventory.get("os", {}), "status": "ERRO",
            "reason_code": code, "reason": message,
            "issues": [{"code": code, "message": message}],
            "coverage": inventory.get("coverage", {}),
            "limitations": ["Avaliação interrompida; nenhuma conclusão sobre PHP ou atualização foi comprovada."],
            "packages": [], "simulation": [], "errors": [message], "approved_possible": False,
            "services": [], "applications": None, "backups": None, "checks": [], "risks": [], "recovery": None}


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = parser().parse_args(argv)
    if not 1 <= args.days <= 365:
        parser().error("--days deve estar entre 1 e 365")
    if args.operation == "rollback-config":
        if args.session is None:
            parser().error("rollback-config requer --session")
        try:
            failures = validate_manifest(args.session)
        except (OSError, ValueError, KeyError) as exc:
            print(f"Sessão inválida: {exc}", file=sys.stderr)
            return 2
        if failures:
            print("Integridade do backup falhou: " + "; ".join(failures), file=sys.stderr)
            return 2
        print("Backup íntegro. Esta versão não modifica configurações; não há restauração automática a executar. Compare as cópias em configuracoes/ antes de qualquer restauração manual. Não faça downgrade do PHP.")
        return 0
    system = System()
    try:
        inventory = discover(system)
        assessed = evaluate(inventory["packages"], inventory["os"], system)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError):
        if args.operation != "plan":
            raise
        print(json.dumps(_plan_failure("FALHA_DESCOBERTA_OU_AVALIACAO",
                                       "Falha operacional ao descobrir ou avaliar PHP."), ensure_ascii=False, indent=2))
        return 2
    potentially_vulnerable = _runtime_needs_investigation(inventory, assessed)
    investigation = investigate(inventory, args.days) if inventory["host_php"] and potentially_vulnerable and args.operation in ("audit", "report", "remediate") else None
    changes = None
    if args.preserve and investigation:
        try:
            paths = [Path(item) for item in investigation["logs_inspected"]]
            metadata = investigation["log_coverage"].get("file_metadata", {})
            if any(str(path) not in metadata for path in paths):
                raise ValueError("Nem todos os logs examinados têm identidade estável; revise a coleta antes de preservar.")
            session = BackupSession(args.backup_dir, sum(p.stat().st_size for p in paths if p.exists() and not p.is_symlink()))
            for path in paths:
                session.preserve(path, expected=metadata[str(path)])
            session.finalize(inventory["os"], ["preservação solicitada pelo operador"])
            failures = validate_manifest(session.path)
            if failures:
                raise RuntimeError("; ".join(failures))
            changes = {"status": "EVIDÊNCIAS PRESERVADAS", "backup": str(session.path), "validation": ["SHA-256 validado"]}
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"Falha na preservação: {exc}", file=sys.stderr)
            return 2
    if args.operation in ("plan", "remediate"):
        if args.operation == "remediate":
            interactive = not args.non_interactive and sys.stdin.isatty()
            print("REVISÃO PRÉVIA PRIVADA — avalie vulnerabilidade, investigação, achados, limites e evidências."
                  if interactive else "RESUMO PRÉVIO — modo não interativo, atualização bloqueada.", flush=True)
            print(render(build(inventory, assessed, investigation, changes), "txt", detailed=interactive), flush=True)
            if interactive:
                print("Evidências: " + ("preservadas na sessão informada acima" if changes and changes.get("backup") else
                                       "preservação pendente; use audit --preserve antes de qualquer mudança"), flush=True)
            else:
                print("Remediação exige revisão em terminal interativo e não está liberada nesta versão.", file=sys.stderr)
                return 2
        try:
            proposed = plan(system, inventory, assessed)
        except (OSError, ValueError, RuntimeError, KeyError, TypeError):
            if args.operation != "plan":
                raise
            print(json.dumps(_plan_failure("FALHA_PLANEJAMENTO",
                                           "Falha operacional durante o planejamento.", inventory),
                             ensure_ascii=False, indent=2))
            return 2
        print(json.dumps(proposed, ensure_ascii=False, indent=2), flush=True)
        if args.operation == "plan":
            return 0 if proposed.get("status") in ("PLANO_DISPONIVEL", "SEM_ACAO") else 2
        if not proposed["approved_possible"]:
            print("Plano bloqueado; nenhuma alteração executada.", file=sys.stderr)
            return 2
        blockers = remediation_blockers(investigation)
        if blockers:
            print("ATUALIZAÇÃO BLOQUEADA: " + " ".join(blockers), file=sys.stderr)
            return 2
        if not remediation_module.REMEDIATION_VALIDATED:
            print("Remediação indisponível até ensaios ponta a ponta em VMs representativas e liberação explícita.", file=sys.stderr)
            return 2
        print("ATENÇÃO: APT pode reiniciar serviços. Confirme janela, aplicações afetadas e preservação de evidências.")
        expected = "ATUALIZAR " + ",".join(proposed["packages"]) + " APÓS ANALISAR " + investigation["status"]
        try:
            confirmation = input(f"Digite exatamente '{expected}' para autorizar: ").strip()
        except EOFError:
            confirmation = ""
        if confirmation != expected:
            print("Operação cancelada.")
            return 2
        if investigation:
            proposed["logs_inspected"] = investigation["logs_inspected"]
            proposed["log_metadata"] = investigation["log_coverage"].get("file_metadata", {})
        try:
            changes = remediate(system, proposed, args.backup_dir, investigation_reviewed=True)
        except (OSError, ValueError, RuntimeError, PermissionError) as exc:
            print(f"Remediação interrompida: {exc}", file=sys.stderr)
            return 2
    if args.operation == "verify":
        stale = [p for p in inventory["processes"] if p["exe"].endswith(" (deleted)")]
        changes = {"status": "VALIDAÇÃO INCOMPLETA" if stale or not any(p["status"] == "CORRIGIDO" for p in assessed) or any(p["status"] not in ("CORRIGIDO", "NÃO APLICÁVEL") for p in assessed) else "PACOTES CORRIGIDOS; TESTE FUNCIONAL PENDENTE",
                   "validation": [f"processos com executável removido: {len(stale)}", "Verificar aplicação HTTP manualmente."]}
    report = build(inventory, assessed, investigation, changes)
    print(render(report, "txt", args.detailed))
    if args.output:
        try:
            for path in save(report, args.output, args.detailed):
                print(f"Relatório salvo: {path}")
        except (OSError, ValueError) as exc:
            print(f"Falha ao salvar relatório: {exc}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
