# Recuperação

Esta versão não altera arquivos de configuração. `rollback-config --session CAMINHO` valida SHA-256 das cópias e mostra que não existe alteração de configuração feita pela ferramenta para desfazer. `CAMINHO` é um **EXEMPLO**: use o caminho real informado após a preservação.

Se o APT falhar ou o serviço não voltar, mantenha a sessão de backup e leia `transacao/apt.json`, `transacao/antes.json` e `transacao/depois.json` quando presentes. Compare configurações preservadas com as atuais, confira `systemctl status` do serviço afetado, `journalctl` e política de pacotes. Qualquer restauração manual de configuração deve seguir o processo de mudança local, com cópia do estado atual e validação do serviço. A ferramenta não faz downgrade automático, pois isso poderia reintroduzir as CVEs. Evidências suspeitas não devem ser restauradas em produção sem análise. Se houver sinais fortes de invasão, acione resposta a incidentes antes de alterar mais o sistema.

## Créditos

Projeto PHP Security Auditor.
