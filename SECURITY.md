# Política de segurança

## Escopo

Esta política abrange a série `0.1` do PHP Security Auditor, destinado a inventário, auditoria local, investigação limitada e planejamento APT. A remediação operacional está bloqueada, inclusive após confirmação humana, até ensaios representativos e aprovação específica. A [matriz de compatibilidade](docs/compatibilidade.md) distingue regras implementadas, testes isolados e validação operacional.

São relevantes relatos de execução inesperada de comandos, vazamento de dados, atualização não autorizada, corrupção de evidências, falhas de controle de acesso ou conclusões indevidas sobre versões e cobertura. Limitações documentadas não excluem automaticamente um problema de segurança.

## Como relatar uma vulnerabilidade

O PHP Security Auditor recebe relatos de segurança pelo **GitHub Private Vulnerability Reporting**, habilitado neste repositório público. Para comunicar uma vulnerabilidade, acesse [Security → Advisories](https://github.com/PauloNRocha/PHP-Security-Auditor/security/advisories) e selecione **Report a vulnerability**. O formulário permite compartilhar o relato de forma privada com os responsáveis pelo projeto.

**Não divulgue detalhes de vulnerabilidades, provas de conceito ou evidências sensíveis em Issues, Pull Requests ou discussões públicas.** Se o formulário de relato privado não estiver acessível, informe apenas a indisponibilidade do canal por meio de uma Issue, sem incluir detalhes técnicos do problema.

A habilitação do recurso está confirmada nas configurações do repositório. O recebimento das notificações e o fluxo completo de resposta ainda não foram verificados de ponta a ponta; não há prazo de resposta garantido.

## Conteúdo do relato e divulgação responsável

Descreva a versão da ferramenta, o componente afetado, o impacto, as condições de reprodução em ambiente isolado e uma forma segura de validação. Use dados sintéticos; não envie credenciais, dados pessoais, logs reais ou evidências de terceiros sem necessidade e autorização.

A equipe avaliará o achado, coordenará a correção e combinará a divulgação responsável com o relator. Não execute provas de conceito contra sistemas de terceiros nem exponha detalhes sensíveis antes dessa coordenação.

## Propriedades de segurança esperadas

Logs, nomes de arquivo, metadados de pacotes, caminhos e argumentos são dados não confiáveis. A auditoria padrão deve ser não destrutiva. Alterações exigem plano, autorização, backup verificável e validação posterior; evidências não podem ser executadas como código.

Pacotes sem origem ou versão comprovada devem permanecer **INDETERMINADOS**. Relatórios e backups precisam de proteção contra acesso indevido, links simbólicos e sobrescrita.

## Limitações relevantes

Testes automatizados e revisões estáticas não demonstram segurança em produção. A inspeção de contêineres, a correlação forense e a validação de todos os workers web são limitadas.

`verify` retorna `0` apenas para um resultado satisfatório no escopo automatizado observado e `2` para insuficiência, resultado insatisfatório ou falha operacional. Não executa testes HTTP funcionais nem comprova integridade dos executáveis. Limitações aninhadas de Docker, Podman e LXC são apresentadas nos relatórios; indisponibilidade opcional não comprova vulnerabilidade, ausência de contêineres ou inspeção de seu interior. Consulte as [limitações conhecidas](docs/limitacoes.md) antes de interpretar os resultados.
