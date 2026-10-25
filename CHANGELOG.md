# Changelog

Funcionalidades e alterações do PHP Security Auditor por versão, seguindo os princípios do [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).

## [0.1.0] — Versão inicial

### Funcionalidades iniciais

- Inventário local de pacotes, binários, processos e serviços PHP, com identificação de instalações alternativas e consulta de metadados de contêineres.
- Avaliação de CVE-2026-109618 e CVE-2026-109619 com base offline, comparação de versões de pacotes e regras de correção de fornecedores Debian/Ubuntu.
- Investigação passiva limitada de logs conhecidos, processos e locais selecionados de persistência, com indicação de cobertura e confiança dos achados.
- Relatórios TXT, JSON e Markdown, com resumo sanitizado e modo técnico detalhado.
- Preservação opcional de logs examinados, com manifesto e verificação SHA-256.
- Planejamento APT com candidatos, dependências, simulação e resultados estruturados: `PLANO_DISPONIVEL`, `SEM_ACAO`, `INCONCLUSIVO`, `BLOQUEADO` e `ERRO`.

### Proteções de segurança

- Auditoria padrão não destrutiva e remediação operacional bloqueada.
- Versões ou origens sem comprovação permanecem indeterminadas; nomes de runtimes não bastam para associá-los a pacotes oficiais.
- Comandos externos sem shell, com timeout e limite de saída; logs e evidências não são executados como código.
- Leitura limitada de evidências, proteção contra links simbólicos e destinos de gravação inadequados, permissões restritivas e recusa de sobrescrita dos backups.
- Seleção explícita de campos nos relatórios resumidos e tratamento de conteúdo não confiável na saída de terminal e Markdown.

### Compatibilidade e validação

- Requer Linux e Python 3.10 ou superior. Avaliação e planejamento de pacotes utilizam `dpkg` e APT.
- Regras para Debian 12/13 e Ubuntu 22.04, 24.04 e 26.04 LTS; detalhes e ramos PHP estão na [matriz de compatibilidade](docs/compatibilidade.md).
- Validação operacional limitada em ambiente isolado com Debian 13 Trixie: sem PHP, PHP CLI, Apache com PHP-FPM e execução sem privilégios. Integração HTTP confirmada manualmente no cenário Apache/FPM.
- Testes automatizados isolados com dados sintéticos e integração contínua em Python 3.10 e 3.12. Não há validação operacional em outras distribuições nem de atualização real de pacotes vulneráveis.

### Limitações conhecidas

- `remediate` não executa atualizações. `rollback-config` valida backups e orienta recuperação manual, sem restauração automática.
- `verify` pode retornar código `0` com validação interna incompleta e não executa teste HTTP funcional automático; o código isolado não aprova atualização nem confirma segurança.
- O relatório de auditoria não contabiliza corretamente todas as limitações aninhadas de Docker, Podman e LXC. `plan` apresenta essas limitações de forma estruturada; o interior dos contêineres não é inspecionado.
- Inventário e investigação têm cobertura limitada. Não há comprovação automática da integridade dos bytes instalados, da versão efetiva em todos os workers web ou de ausência de comprometimento.

Consulte os [cenários de validação](docs/testes.md) e as [limitações técnicas](docs/limitacoes.md).
