# Política de segurança

## Escopo

Esta política abrange o PHP Security Auditor `0.1.0`, destinado a inventário, auditoria local, investigação limitada e planejamento APT. A remediação operacional está bloqueada, inclusive após confirmação humana, até ensaios representativos e aprovação específica. A [matriz de compatibilidade](docs/compatibilidade.md) distingue regras implementadas, testes isolados e validação operacional.

São relevantes relatos de execução inesperada de comandos, vazamento de dados, atualização não autorizada, corrupção de evidências, falhas de controle de acesso ou conclusões indevidas sobre versões e cobertura. Limitações documentadas não excluem automaticamente um problema de segurança.

## Como relatar uma vulnerabilidade

**O canal privado de relatos ainda não está habilitado nem verificado.** Não envie detalhes sensíveis em issues públicas. Até que haja um canal aprovado e indicado nesta política, solicite ao responsável pelo projeto um meio privado adequado antes de compartilhar o conteúdo do relato. Não há endereço de contato ou prazo de resposta definido.

O recurso [GitHub Private Vulnerability Reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository) permite relatos privados em repositórios públicos. Sua habilitação e verificação são requisitos anteriores à divulgação pública do projeto. Após autorização para a mudança de visibilidade e assim que a configuração estiver disponível, o responsável deve:

1. Habilitar o recurso.
2. Verificar o formulário de relato privado e o recebimento das notificações.
3. Atualizar esta política com o canal efetivamente disponível antes da divulgação.

Quando esse canal estiver habilitado e verificado, os relatos poderão ser enviados pelo formulário **Report a vulnerability** na área de avisos de segurança do repositório.

## Conteúdo do relato e divulgação responsável

Descreva a versão da ferramenta, o componente afetado, o impacto, as condições de reprodução em ambiente isolado e uma forma segura de validação. Use dados sintéticos; não envie credenciais, dados pessoais, logs reais ou evidências de terceiros sem necessidade e autorização.

A equipe avaliará o achado, coordenará a correção e combinará a divulgação responsável com o relator. Não execute provas de conceito contra sistemas de terceiros nem exponha detalhes sensíveis antes dessa coordenação.

## Propriedades de segurança esperadas

Logs, nomes de arquivo, metadados de pacotes, caminhos e argumentos são dados não confiáveis. A auditoria padrão deve ser não destrutiva. Alterações exigem plano, autorização, backup verificável e validação posterior; evidências não podem ser executadas como código.

Pacotes sem origem ou versão comprovada devem permanecer **INDETERMINADOS**. Relatórios e backups precisam de proteção contra acesso indevido, links simbólicos e sobrescrita.

## Limitações relevantes

Testes automatizados e revisões estáticas não demonstram segurança em produção. A inspeção de contêineres, a correlação forense e a validação de todos os workers web são limitadas.

Em particular, `verify` pode retornar código `0` com validação interna incompleta e não executa testes HTTP funcionais. O relatório de auditoria não contabiliza corretamente todas as limitações aninhadas de Docker, Podman e LXC; `plan` apresenta essas limitações de forma estruturada. Consulte as [limitações conhecidas](docs/limitacoes.md) antes de interpretar os resultados.
