"""Resultado limitado às verificações automatizadas, sem teste HTTP."""
from __future__ import annotations

from .coverage import container_enumeration_incomplete
from .remediation import runtime_association
from .system import System

STATUSES = {"SATISFATORIO_NO_ESCOPO_AUTOMATIZADO", "INCONCLUSIVO", "INSATISFATORIO", "ERRO"}
REASONS = {"COBERTURA_ESSENCIAL_INCOMPLETA", "PACOTES_NAO_COMPROVADOS", "EXECUTAVEL_REMOVIDO",
           "RUNTIME_NAO_AVALIADO", "CONTEINER_NAO_INSPECIONADO", "AVALIACAO_INDETERMINADA",
           "FALHA_ASSOCIACAO_RUNTIME", "COBERTURA_CONTEINER_INCOMPLETA"}


def verify_checks(system: System, inventory: dict, assessed: list[dict], status: str,
                  runtime_state: str | None = None) -> dict:
    reasons = []
    coverage = inventory.get("coverage", {})
    if any(coverage.get(source) != "completa" for source in ("pacotes", "processos", "serviços")):
        reasons.append("COBERTURA_ESSENCIAL_INCOMPLETA")
    if not any(p["status"] == "CORRIGIDO" for p in assessed) or any(
            p["status"] not in ("CORRIGIDO", "NÃO APLICÁVEL") for p in assessed):
        reasons.append("PACOTES_NAO_COMPROVADOS")
    stale = sum(str(p.get("exe", "")).endswith(" (deleted)") for p in inventory["processes"])
    if stale:
        reasons.append("EXECUTAVEL_REMOVIDO")
    if inventory.get("containers"):
        reasons.append("CONTEINER_NAO_INSPECIONADO")
    if container_enumeration_incomplete(coverage):
        reasons.append("COBERTURA_CONTEINER_INCOMPLETA")
    if status == "INDETERMINADO":
        reasons.append("AVALIACAO_INDETERMINADA")
    # Usa a mesma comprovação de propriedade exigida pelo planejamento. Não executa PHP.
    association = runtime_state if runtime_state is not None else runtime_association(system, inventory, assessed)
    if association == "ERRO":
        reasons.append("FALHA_ASSOCIACAO_RUNTIME")
    elif association != "COMPROVADO":
        reasons.append("RUNTIME_NAO_AVALIADO")
    result = ("ERRO" if "FALHA_ASSOCIACAO_RUNTIME" in reasons else
              "INSATISFATORIO" if stale or any(p["status"] == "VULNERÁVEL" for p in assessed) else
              "INCONCLUSIVO" if reasons else "SATISFATORIO_NO_ESCOPO_AUTOMATIZADO")
    return {"status": "VALIDAÇÃO INCOMPLETA" if reasons else "PACOTES CORRIGIDOS; TESTE FUNCIONAL PENDENTE",
            "validation": [f"processos com executável removido: {stale}",
                           "Escopo: pacotes e runtimes observados; integridade dos bytes não comprovada.",
                           "Teste funcional HTTP não executado; verificar aplicação manualmente.",
                           "Mecanismos opcionais indisponíveis não foram inspecionados."],
            "verification": {"status": result, "reason_codes": reasons,
                             "http_test_performed": False}}


def sanitized_verification(value: dict) -> dict:
    status = value.get("status")
    return {"status": status if isinstance(status, str) and status in STATUSES else "INCONCLUSIVO",
            "reason_codes": [reason for reason in value.get("reason_codes", [])
                             if isinstance(reason, str) and reason in REASONS],
            "http_test_performed": False}
