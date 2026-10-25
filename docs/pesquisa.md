# Pesquisa técnica: CVE-2026-109618 e CVE-2026-109619

Este documento fundamenta a detecção local no Debian 12/13 e Ubuntu LTS. Ele não contém instruções de exploração. As fontes foram consultadas em 22/10/2026; o banco offline da ferramenta registra essa data e deve ser revisado quando os fornecedores publicarem novas correções.

## Escopo e mecanismos

As duas falhas são do núcleo do PHP, alcançáveis durante o processamento de requisições web sem autenticação, e receberam CVSS v4.0 9,2. A CVE-2026-109618 decorre de saída antecipada por falta de memória durante inicialização parcial de dados da requisição, seguida por limpeza que usa estado inválido. A CVE-2026-109619 envolve estado global referente à memória de uma requisição já liberada, reutilizado por um worker antes da inicialização normal. PHP-FPM, Apache mod_php, php-cgi, FrankenPHP e LiteSpeed podem atender requisições afetadas. A demonstração pública do primeiro mecanismo inclui mod_php antes de executar código da aplicação. Uma instalação somente CLI não tem a mesma exposição HTTP, mas ainda precisa de inventário e análise de origem.

Fontes primárias: [aviso PHP](https://www.php.net/archive/2026.php#2026-10-21-5), [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

## Versões corrigidas

| Origem | Ramo/sistema | Primeira versão corrigida | Referência |
|---|---|---|---|
| PHP upstream | 8.2 | 8.2.35 | Avisos PHP/GHSA |
| PHP upstream | 8.3 | 8.3.36 | Avisos PHP/GHSA |
| PHP upstream | 8.4 | 8.4.27 | Avisos PHP/GHSA |
| PHP upstream | 8.5 | 8.5.12 | Avisos PHP/GHSA |
| Debian 12 | php8.2 | 8.2.35-1~deb12u1 | [DLA-4848-1](https://lists.debian.org/debian-lts-announce/2026/10/msg00042.html) |
| Debian 13 | php8.4 | 8.4.27-1~deb13u1 | [DSA-6574-1](https://lists.debian.org/debian-security-announce/2026/msg00489.html) |
| Ubuntu 22.04 LTS | php8.1 | 8.1.2-1ubuntu2.28 | [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) |
| Ubuntu 24.04 LTS | php8.3 | 8.3.6-0ubuntu0.24.04.13 | USN-8948-1 |
| Ubuntu 26.04 LTS | php8.5 | 8.5.4-0ubuntu1.5 | USN-8948-1 |

O Ubuntu aplicou backports: comparar apenas o número upstream produziria falsos positivos. O PHP forneceu patches de código-fonte para 7.4, 8.0 e 8.1, sem nova versão oficial desses ramos. Instalações manuais ou de repositórios terceiros permanecem indeterminadas sem prova própria do fornecedor. A avaliação de pacotes usa `dpkg --compare-versions`, que considera época, revisão e sufixos de distribuição. A [página da CVE-2026-109618 no Debian Tracker](https://security-tracker.debian.org/tracker/CVE-2026-109618) ainda mostrava Debian 12 vulnerável no momento da consulta; o [DLA-4848-1](https://lists.debian.org/debian-lts-announce/2026/10/msg00042.html) e a [página da CVE-2026-109619](https://security-tracker.debian.org/tracker/CVE-2026-109619) já registravam a correção. Essa divergência exige atenção ao atualizar a base.

## Investigação e limites

A [AWS Threat Intelligence](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/) observou tentativa em 17/10/2026 e recomenda investigar desde essa data. A [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/) aponta formulários anômalos, erros de memória e shells inesperados como sinais de investigação. Endereços IP publicados pela AWS podem ser infraestrutura compartilhada: ocorrência isolada não confirma ataque.

Logs HTTP comuns não guardam corpo de requisição, contagem de partes multipart nem, necessariamente, tamanho da requisição. Ausência desses indicadores não exclui exploração. Erros 4xx/5xx isolados, falhas de worker ou arquivos recentes isolados também não provam comprometimento. Exploração bem-sucedida pode não derrubar o worker. Um diagnóstico forte depende de correlação temporal e da proveniência dos eventos. A ferramenta nunca usa essas heurísticas para emitir “comprometimento confirmado” automaticamente.

## Riscos operacionais da correção

Atualizações de pacotes podem executar scripts de manutenção e reiniciar PHP-FPM ou Apache; processos antigos podem continuar usando bibliotecas substituídas. Extensões de terceiros e aplicações podem depender do ramo/ABI do PHP. O plano deve mostrar a simulação do APT, dependências, serviço e testes de aplicação. Mitigações temporárias descritas pelo PHP reduzem apenas caminhos específicos; podem quebrar uploads e não substituem atualização. A ferramenta não modifica configurações de mitigação automaticamente.

## Créditos

Projeto PHP Security Auditor. Referências oficiais e pesquisas técnicas estão vinculadas nas seções acima.
