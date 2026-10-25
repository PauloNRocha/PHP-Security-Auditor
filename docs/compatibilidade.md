# Matriz de compatibilidade

| Plataforma | Avaliação de pacote oficial | Plano/atualização | Validação executada neste projeto |
|---|---|---|---|
| Debian 12, php8.2 | Regra DLA-4848-1 | Plano disponível; execução bloqueada | Testes unitários com respostas simuladas |
| Debian 13 Trixie, php8.4 | Regra DSA-6574-1 | Planejamento avaliado em laboratório; execução bloqueada | Testes unitários e ambiente isolado: sem PHP, CLI, Apache/FPM e execução sem privilégios |
| Ubuntu 22.04 LTS, php8.1 | Regra USN-8948-1 | Plano disponível; execução bloqueada | Testes unitários com respostas simuladas |
| Ubuntu 24.04 LTS, php8.3 | Regra USN-8948-1 | Plano disponível; execução bloqueada | Testes unitários com respostas simuladas |
| Ubuntu 26.04 LTS, php8.5 | Regra USN-8948-1 | Plano disponível; execução bloqueada | Testes unitários com respostas simuladas |
| Outros ramos, fontes manuais e terceiros | Indeterminado | Bloqueado | Não validado |
| Docker/Podman/LXC | Somente metadados locais | Bloqueado | Testes isolados de descoberta |

Os [cenários operacionais registrados](testes.md#validação-operacional-em-debian-13) limitam-se a auditoria e planejamento em Debian 13 Trixie, com PHP `8.4.27-1~deb13u1` quando instalado. No cenário Apache/FPM, a integração HTTP foi confirmada manualmente. A execução sem privilégios preservou a classificação inconclusiva quando `/proc` não pôde ser lido integralmente.

Não há validação operacional em Debian 12 ou Ubuntu LTS. Nenhuma distribuição recebeu ensaio ponta a ponta de atualização real de pacotes vulneráveis, reinício causado pela atualização e validação posterior. `remediate` permanece bloqueado no código até esses ensaios e decisão explícita de liberação. `plan` simula transações elegíveis sem instalar pacotes; não simula instalação nos estados `SEM_ACAO`.

## Créditos

Projeto PHP Security Auditor.
