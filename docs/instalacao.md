# Guia de instalação

Este guia instala a ferramenta em um Linux Debian/Ubuntu para auditoria local. A instalação do programa não atualiza PHP nem modifica serviços.

1. Instale Python 3 e `python3-venv` pelo procedimento normal da distribuição. `dpkg` e APT devem estar disponíveis para avaliar e planejar pacotes.
2. Obtenha o código de uma fonte confiável e confira sua integridade conforme o processo da sua organização. Entre no diretório que contém `pyproject.toml`.
3. Crie ambiente isolado e instale sem resolver dependências externas:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/php-security-auditor --help
```

Se `pip` ou `setuptools` não estiverem instalados no ambiente, execute diretamente `python3 -m php_security_auditor.cli --help` a partir do diretório do projeto. Esse caminho usa somente a biblioteca padrão. Execute auditoria sem root primeiro para conhecer a cobertura. Para ler logs restritos ou preservar arquivos administrativos, use `sudo` conforme a política local; o backup padrão então será em `/root/backup/php-security-auditor/`.

Confira o resultado de `--help` e use inicialmente `audit` ou `plan` em laboratório. `remediate` aparece na interface, mas sua execução está bloqueada até ensaios representativos e decisão explícita de liberação.

## Créditos

Projeto PHP Security Auditor; referências de fornecedor em [pesquisa](pesquisa.md).
