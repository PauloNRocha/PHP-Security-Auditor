# Arquitetura técnica

O projeto usa Python 3 e apenas a biblioteca padrão. Python permite JSON, limites de leitura, comparação de estados e tratamento de arquivos mais seguros e legíveis que um script Bash grande. Comandos externos são chamados como listas de argumentos, com timeout e sem shell. `dpkg`, APT e `systemctl` permanecem integrações explícitas. A base de correções está em JSON versionado; somente regras identificadas por fornecedor, distribuição e ramo são usadas para declarar um pacote corrigido.

Fluxo: descoberta do hospedeiro e contêineres → inventário → avaliação por fonte → investigação limitada se houver PHP potencialmente vulnerável → apresentação dos achados e limites → plano simulado. A atualização tem bloqueio de liberação até ensaios operacionais. O caminho preparado para liberação futura ainda exige triagem sem achado grave, coleta essencial, confirmação humana, backup e validação. A execução sem argumentos termina após a auditoria passiva. Escrita de relatórios é opcional.

Limites: a inspeção de contêiner é por metadados locais e não entra neles; versões e conteúdo interno podem permanecer indeterminados. Não se executam binários PHP desconhecidos para descobrir versões. A versão do CLI nunca prova a versão efetiva do servidor. O plano de atualização considera apenas pacotes oficiais conhecidos do Debian/Ubuntu; a execução de atualizações está bloqueada na versão `0.1.0`. Nenhuma alteração em firewall, contas, serviços ou configuração de segurança é automática.

Os módulos `system`, `discovery`, `versions`, `forensics`, `backup`, `remediation`, `report` e `cli` isolam responsabilidades. A camada `System` é injetável nos testes. Saídas externas, paths, logs e metadados são tratados como dados não confiáveis. Leitura de evidências tem limites de bytes/arquivos, recusa links simbólicos e mantém apenas metadados e indicadores mínimos nos relatórios.

## Créditos

Projeto PHP Security Auditor.
