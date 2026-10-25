# PHP Security Auditor

[![Python >= 3.10](https://img.shields.io/badge/Python-%3E%3D%203.10-3776AB)](pyproject.toml)
[![Licença MIT](https://img.shields.io/badge/Licen%C3%A7a-MIT-3B7A57)](LICENSE)
[![Plataforma Linux](https://img.shields.io/badge/Plataforma-Linux-555555)](docs/compatibilidade.md)
[![Testes automatizados](https://github.com/PauloNRocha/PHP-Security-Auditor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/PauloNRocha/PHP-Security-Auditor/actions/workflows/ci.yml)

Ferramenta de terminal para administradores Linux identificarem instalações PHP, avaliarem as vulnerabilidades CVE-2026-109618 e CVE-2026-109619 e planejarem atualizações de pacotes oficiais Debian/Ubuntu.

O PHP Security Auditor reúne inventário, avaliação de versões, investigação local limitada e relatórios. Ajuda a distinguir pacotes corrigidos, instalações potencialmente vulneráveis e situações que exigem verificação manual. O funcionamento básico usa uma base de avisos distribuída com o código e dispensa acesso à Internet.

## Funcionalidades

- Descoberta de pacotes, binários, processos e serviços PHP, incluindo CLI, PHP-FPM, Apache mod_php e instalações alternativas identificáveis.
- Comparação de versões de pacotes com regras de correção dos fornecedores, considerando revisões e backports.
- Consulta de metadados locais de Docker, Podman e LXC.
- Triagem de logs conhecidos, processos e locais selecionados de persistência, com limites de leitura e indicação de cobertura.
- Relatórios TXT, JSON e Markdown, com resumo sanitizado e modo técnico detalhado.
- Preservação opcional de logs examinados, com manifesto e verificação SHA-256.
- Planejamento APT com candidatos, dependências, simulação, riscos e motivos estruturados para bloqueios.

## Segurança e limites operacionais

**A remediação operacional está bloqueada na versão 0.1.0.** O comando `remediate` aparece na interface, mas recusa atualizações mesmo após confirmação humana.

A auditoria padrão é passiva: não atualiza pacotes nem altera configurações, serviços ou firewall. Escrita de relatórios e preservação de evidências são opcionais. A ferramenta não executa provas de conceito nem binários PHP desconhecidos para consultar versões.

Comece sem privilégios administrativos e confira a cobertura informada. Acesso restrito a logs ou processos pode tornar o resultado inconclusivo. Relatórios detalhados e backups podem conter dados sensíveis; mantenha-os fora de árvores Git e diretórios públicos.

A ferramenta não substitui investigação forense profissional. Ausência de indícios não comprova ausência de comprometimento.

## Compatibilidade

Requer Linux e Python 3.10 ou superior. A avaliação e o planejamento de pacotes dependem de `dpkg` e APT; a coleta de serviços utiliza systemd.

| Distribuição | Ramo PHP contemplado nas regras de pacotes oficiais | Evidência de validação |
|---|---|---|
| Debian 12 | 8.2 | Testes isolados com respostas simuladas |
| Debian 13 Trixie | 8.4 | Testes isolados e validação operacional limitada |
| Ubuntu 22.04 LTS | 8.1 | Testes isolados com respostas simuladas |
| Ubuntu 24.04 LTS | 8.3 | Testes isolados com respostas simuladas |
| Ubuntu 26.04 LTS | 8.5 | Testes isolados com respostas simuladas |

A validação operacional abrange somente ambiente isolado com Debian 13 Trixie: sem PHP, uso exclusivamente CLI, Apache com PHP-FPM e execução sem privilégios. A integração HTTP foi confirmada manualmente no cenário Apache/FPM. Não foram validadas atualizações reais de pacotes vulneráveis.

Em distribuições não contempladas, o inventário pode fornecer informações parciais, mas o planejamento de atualização é bloqueado. Instalações manuais e de terceiros permanecem indeterminadas quando sua versão ou origem não pode ser comprovada. Consulte a [matriz de compatibilidade](docs/compatibilidade.md) e os [cenários de validação](docs/testes.md#validação-operacional-em-debian-13).

## Instalação

Após obter o código de uma fonte confiável, entre no diretório que contém `pyproject.toml`. Para instalar o comando em ambiente virtual, com `pip` e um backend `setuptools` compatível com os metadados do projeto disponíveis nesse ambiente:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/php-security-auditor --help
```

Também é possível executar diretamente a partir do código-fonte, usando apenas a biblioteca padrão:

```bash
python3 -m php_security_auditor.cli --help
python3 -m php_security_auditor.cli --version
```

O [guia de instalação](docs/instalacao.md) detalha os requisitos e a execução com os privilégios necessários.

## Exemplos de utilização

A partir da raiz do código-fonte:

```bash
# Auditoria passiva; também é a operação padrão sem argumentos.
python3 -m php_security_auditor.cli audit

# Triagem dos últimos 30 dias, quando aplicável, com relatório técnico privado.
python3 -m php_security_auditor.cli audit --days 30 --detailed

# Planejamento em JSON; nenhuma instalação é executada.
python3 -m php_security_auditor.cli plan

# Gravação de relatórios fora do repositório.
python3 -m php_security_auditor.cli report --output "$HOME/relatorios-php"
```

Após a instalação, `php-security-auditor` aceita as mesmas operações e opções. Consulte o [guia de utilização](docs/utilizacao.md) para preservação de evidências, período investigado e automação.

## Interpretação dos resultados

O status de vulnerabilidade é separado do status da investigação:

| Status de vulnerabilidade | Interpretação |
|---|---|
| `CORRIGIDO` | Os pacotes avaliáveis atingem o limiar conhecido de correção, dentro da cobertura disponível. |
| `VULNERÁVEL` | Há pacote oficial abaixo do limiar de correção aplicável. |
| `INDETERMINADO` | Versão, origem ou cobertura não permitem uma conclusão confiável. |
| `NÃO APLICÁVEL` | Nenhum PHP foi identificado pelos métodos executados; também pode classificar individualmente uma extensão cuja versão não representa o runtime. |

Achados suspeitos precisam de análise humana e correlação. A versão do PHP CLI não comprova a versão usada pelo serviço web, e um pacote corrigido não demonstra que todos os workers foram substituídos.

Para `plan`, o código de saída é `0` nos estados `PLANO_DISPONIVEL` e `SEM_ACAO`, e `2` nos estados `INCONCLUSIVO`, `BLOQUEADO` e `ERRO`. Um plano elegível não autoriza remediação. Veja o [contrato dos estados e códigos](docs/utilizacao.md#correção-assistida).

## Limitações conhecidas

- `verify` pode retornar código `0` com validação interna incompleta e não executa teste HTTP funcional. Seu código de saída não deve aprovar uma atualização ou confirmar segurança isoladamente.
- O relatório de auditoria não contabiliza corretamente todas as limitações aninhadas de contêineres. Examine a cobertura detalhada e as limitações estruturadas de `plan`; o interior dos contêineres não é inspecionado.
- A descoberta de instalações e a triagem de evidências não são exaustivas. Logs grandes, dados indisponíveis e limites de leitura podem deixar lacunas.
- Metadados APT e propriedade de arquivos por pacote não comprovam a integridade dos bytes instalados.

Os limites de processamento, as ressalvas de cobertura e os requisitos de validação estão em [limitações conhecidas](docs/limitacoes.md).

## Documentação

| Assunto | Guia |
|---|---|
| Instalação e operação | [Instalação](docs/instalacao.md), [utilização](docs/utilizacao.md) e [compatibilidade](docs/compatibilidade.md) |
| Vulnerabilidades e investigação | [Pesquisa técnica](docs/pesquisa.md) e [metodologia](docs/metodologia.md) |
| Projeto e segurança | [Arquitetura](docs/arquitetura.md), [modelo de ameaças](docs/modelo_ameacas.md) e [propriedades de segurança](docs/revisao_seguranca.md) |
| Evidências e recuperação | [Backups](docs/backups.md) e [recuperação](docs/recuperacao.md) |
| Validação e limites | [Testes](docs/testes.md) e [limitações](docs/limitacoes.md) |
| Manutenção e distribuição | [Changelog](CHANGELOG.md), [governança](docs/governanca_publicacao.md) e [auditoria de publicação](docs/auditoria_publicacao.md) |

## Contribuição e divulgação responsável de vulnerabilidades

Consulte [CONTRIBUTING.md](CONTRIBUTING.md) para propor alterações com testes isolados e dados sintéticos. Problemas funcionais podem ser descritos em [issues](https://github.com/PauloNRocha/PHP-Security-Auditor/issues), com versões, passos de reprodução e saídas revisadas para remover dados sensíveis.

Para vulnerabilidades de segurança, siga [SECURITY.md](SECURITY.md). O canal privado deve estar habilitado e verificado antes da divulgação pública do projeto. Não publique detalhes sensíveis de exploração, credenciais ou evidências reais em issues.

## Licença

Distribuído sob a licença [MIT](LICENSE).

## Créditos

Projeto PHP Security Auditor. Fontes técnicas: equipe de segurança do PHP, Debian, Ubuntu, Datadog Security Labs e AWS Threat Intelligence, referenciadas em [pesquisa](docs/pesquisa.md).
