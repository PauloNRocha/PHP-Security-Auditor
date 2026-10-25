"""Inspeção local, sem extração, de um arquivo de distribuição de fontes."""
from __future__ import annotations

import argparse
import tarfile
from pathlib import PurePosixPath

FORBIDDEN_PARTS = {"__pycache__", ".agents", ".codex", ".aws", ".private", "backup", "backups",
                   "relatorios-locais", "evidencias-locais", "resultados-auditoria", "logs"}
REQUIRED = {"pyproject.toml", "LICENSE", "README.md", "SECURITY.md", "CHANGELOG.md",
            "php_security_auditor/data/advisories.json", "tests/test_auditor.py",
            "tests/test_regressions.py", "tests/test_remote_audit_fixes.py",
            "tests/test_plan_results.py", "tools/check_sdist.py"}


def inspect(archive: str) -> list[str]:
    problems = []
    present = set()
    try:
        with tarfile.open(archive, "r:gz") as source:
            for member in source:
                path = PurePosixPath(member.name)
                if len(path.parts) == 1 and member.isdir():
                    continue
                if path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
                    problems.append("Entrada com caminho inválido")
                    continue
                relative = PurePosixPath(*path.parts[1:])
                name = relative.name.lower()
                if not member.isfile() and not member.isdir():
                    problems.append(f"Entrada não regular: {relative}")
                if any(part.lower() in FORBIDDEN_PARTS for part in relative.parts) or name.endswith((".pyc", ".pyo", ".pyd")):
                    problems.append(f"Artefato privado ou gerado: {relative}")
                if name == ".env" or name.startswith(".env.") or name.endswith((".log", ".bak", ".tmp")):
                    problems.append(f"Arquivo operacional: {relative}")
                if member.isfile():
                    present.add(relative.as_posix())
    except (OSError, tarfile.TarError) as exc:
        return [f"Arquivo de distribuição ilegível: {type(exc).__name__}"]
    for required in sorted(REQUIRED - present):
        problems.append(f"Arquivo obrigatório ausente: {required}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="Confere conteúdo de um sdist sem extrair arquivos")
    parser.add_argument("archive", help="Caminho local para o .tar.gz")
    args = parser.parse_args()
    problems = inspect(args.archive)
    for problem in problems:
        print(problem)
    if problems:
        return 2
    print("Manifesto de distribuição aprovado para revisão manual; publicação continua sujeita a autorização.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
