# Modelo de ameaças da ferramenta

Ativos: integridade dos pacotes e serviços, disponibilidade de aplicações, logs e evidências, backups e relatórios com dados sensíveis. O operador pode executar o programa como root. Um invasor que já controla uma aplicação PHP pode influenciar logs, nomes de arquivos, processos, diretórios temporários e parte dos metadados lidos; um usuário local pode tentar trocar links simbólicos ou esgotar recursos. Um repositório de pacotes não oficial pode fornecer versões enganosas.

Fronteiras: dados locais não confiáveis → interpretador Python; parâmetros CLI → caminhos de saída; metadados APT → plano; confirmação humana → transação APT; arquivos de origem → backup. O programa não interpreta conteúdo de logs como código e não usa `shell=True` ou `eval`. Cada subprocesso tem timeout, ambiente controlado e limite de saída. Arquivos de evidência têm limites de tamanho; links simbólicos são rejeitados; sessão de backup usa nome exclusivo e diretórios restritos.

Riscos residuais: o próprio sistema comprometido pode mentir sobre pacotes, processos e logs. APT e scripts de manutenção possuem privilégios e podem alterar serviços; a ferramenta não garante rollback de pacotes. A associação entre PHP-FPM e um virtual host específico nem sempre é demonstrável. Arquivos podem mudar durante a coleta; nesse caso a cópia é recusada. A leitura de logs não produz imagem forense completa. Um adversário com root já pode alterar evidências e backups locais. Para incidente sério, preserve o sistema conforme procedimento profissional independente.

Revisão crítica deve focar especialmente em injeção por argumentos/ambiente, caminhos e links, corrida durante a cópia, expansão de gzip, excesso de saída de subprocessos, vazamento em relatórios e suposições indevidas sobre origem de pacotes. Inspeção automatizada é revisão estática; não substitui validação em ambiente representativo.

## Créditos

Projeto PHP Security Auditor.
