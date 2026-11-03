"""Apresentação de cobertura sem promover falha opcional a vulnerabilidade."""
from __future__ import annotations


def coverage_limitations(coverage: dict) -> list[str]:
    notes = []

    def visit(values: dict, prefix: str = "") -> None:
        for source, detail in values.items():
            label = f"{prefix}/{source}" if prefix else source
            if isinstance(detail, dict):
                visit(detail, label)
            elif isinstance(detail, str) and ("incompleta" in detail or
                                              label.startswith("contêineres/")):
                notes.append(f"Cobertura {label}: {detail}")

    visit(coverage)
    return notes


def container_summary(coverage: dict) -> dict[str, str]:
    """Lista positiva: não copia texto ou identificadores do hospedeiro."""
    engines = coverage.get("contêineres", {})
    engines = engines if isinstance(engines, dict) else {}
    result = {}
    for engine in ("docker", "podman", "lxc"):
        detail = engines.get(engine)
        if not isinstance(detail, str):
            code = "NAO_INFORMADO"
        elif "ferramenta ausente" in detail:
            code = "FERRAMENTA_AUSENTE"
        elif "acesso à ferramenta negado" in detail:
            code = "ACESSO_NEGADO"
        elif "consulta falhou" in detail:
            code = "CONSULTA_FALHOU"
        elif "incompleta" in detail:
            code = "COBERTURA_INCOMPLETA"
        elif detail.startswith("nenhum contêiner relacionado"):
            code = "SEM_RELACIONADOS_INTERIOR_NAO_INSPECIONADO"
        elif detail.startswith("contêiner relacionado identificado"):
            code = "RELACIONADOS_INTERIOR_NAO_INSPECIONADO"
        else:
            code = "INDETERMINADO"
        result[engine] = code
    return result
